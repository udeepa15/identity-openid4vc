/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * In-memory cache for VP (Verifiable Presentation) requests.
 * Provides fast access to active VP requests during the authorization flow.
 * Entries are automatically expired based on configurable TTL.
 */
public class VPRequestCache {

    private static volatile VPRequestCache instance;

    private final Map<String, VPRequestCacheEntry> cacheByRequestId;
    private final Map<String, String> transactionToRequestIdMap;
    private final ScheduledExecutorService cleanupExecutor;
    private final long expiryTimeMillis;
    private final int maxEntries;

    /**
     * Cache entry wrapper with timestamp for TTL tracking.
     */
    private static class VPRequestCacheEntry {
        private final VPRequest vpRequest;
        private final long createdAt;
        private final long expiresAt;

        VPRequestCacheEntry(VPRequest vpRequest, long expiryTimeMillis) {
            this.vpRequest = vpRequest;
            this.createdAt = System.currentTimeMillis();
            this.expiresAt = this.createdAt + expiryTimeMillis;
        }

        VPRequest getVPRequest() {
            return vpRequest;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        long getExpiresAt() {
            return expiresAt;
        }
    }

    /**
     * Private constructor for singleton pattern.
     */
    private VPRequestCache() {
        this(OpenID4VPConstants.Defaults.CACHE_ENTRY_EXPIRY_SECONDS * 1000L,
                OpenID4VPConstants.Defaults.MAX_CACHE_ENTRIES);
    }

    /**
     * Constructor with custom configuration.
     *
     * @param expiryTimeMillis Time in milliseconds after which entries expire
     * @param maxEntries       Maximum number of entries in the cache
     */
    private VPRequestCache(long expiryTimeMillis, int maxEntries) {
        this.cacheByRequestId = new ConcurrentHashMap<>();
        this.transactionToRequestIdMap = new ConcurrentHashMap<>();
        this.expiryTimeMillis = expiryTimeMillis;
        this.maxEntries = maxEntries;

        // Schedule periodic cleanup every minute
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r);
            thread.setDaemon(true);
            thread.setName("VPRequestCache-Cleanup");
            return thread;
        });
        this.cleanupExecutor.scheduleAtFixedRate(this::cleanup, 1, 1, TimeUnit.MINUTES);

    }

    /**
     * Get the singleton instance of VPRequestCache.
     *
     * @return VPRequestCache instance
     */
    @SuppressFBWarnings("MS_EXPOSE_REP")
    public static VPRequestCache getInstance() {
        if (instance == null) {
            synchronized (VPRequestCache.class) {
                if (instance == null) {
                    instance = new VPRequestCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add a VP request to the cache.
     *
     * @param vpRequest The VP request to cache
     */
    public void put(VPRequest vpRequest) {
        if (vpRequest == null || vpRequest.getRequestId() == null) {
            return;
        }

        // Check cache size limit
        if (cacheByRequestId.size() >= maxEntries) {

            cleanup();

            // If still at limit after cleanup, evict oldest entries
            if (cacheByRequestId.size() >= maxEntries) {
                evictOldestEntries(maxEntries / 10); // Evict 10% of entries
            }
        }

        VPRequestCacheEntry entry = new VPRequestCacheEntry(vpRequest, expiryTimeMillis);
        cacheByRequestId.put(vpRequest.getRequestId(), entry);

        if (vpRequest.getTransactionId() != null) {
            transactionToRequestIdMap.put(vpRequest.getTransactionId(), vpRequest.getRequestId());
        }

    }

    /**
     * Get a VP request by its request ID.
     *
     * @param requestId The request ID
     * @return The VP request or null if not found or expired
     */
    public VPRequest getByRequestId(String requestId) {
        if (requestId == null) {
            return null;
        }

        VPRequestCacheEntry entry = cacheByRequestId.get(requestId);
        if (entry == null) {
            return null;
        }

        if (entry.isExpired()) {
            remove(requestId);

            return null;
        }

        return entry.getVPRequest();
    }

    /**
     * Get a VP request by its transaction ID.
     *
     * @param transactionId The transaction ID
     * @return The VP request or null if not found or expired
     */
    public VPRequest getByTransactionId(String transactionId) {
        if (transactionId == null) {
            return null;
        }

        String requestId = transactionToRequestIdMap.get(transactionId);
        if (requestId == null) {
            return null;
        }

        return getByRequestId(requestId);
    }

    /**
     * Remove a VP request from the cache.
     *
     * @param requestId The request ID to remove
     */
    public void remove(String requestId) {
        if (requestId == null) {
            return;
        }

        VPRequestCacheEntry entry = cacheByRequestId.remove(requestId);
        if (entry != null && entry.getVPRequest().getTransactionId() != null) {
            transactionToRequestIdMap.remove(entry.getVPRequest().getTransactionId());
        }

    }

    /**
     * Remove a VP request by its transaction ID.
     *
     * @param transactionId The transaction ID
     */
    public void removeByTransactionId(String transactionId) {
        if (transactionId == null) {
            return;
        }

        String requestId = transactionToRequestIdMap.remove(transactionId);
        if (requestId != null) {
            cacheByRequestId.remove(requestId);

        }
    }

    /**
     * Check if a VP request exists in the cache.
     *
     * @param requestId The request ID
     * @return true if the request exists and is not expired
     */
    public boolean contains(String requestId) {
        return getByRequestId(requestId) != null;
    }

    /**
     * Get the current size of the cache.
     *
     * @return Number of entries in the cache
     */
    public int size() {
        return cacheByRequestId.size();
    }

    /**
     * Clear all entries from the cache.
     */
    public void clear() {
        cacheByRequestId.clear();
        transactionToRequestIdMap.clear();

    }

    /**
     * Cleanup expired entries from the cache.
     */
    private void cleanup() {

        Iterator<Map.Entry<String, VPRequestCacheEntry>> iterator = cacheByRequestId.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, VPRequestCacheEntry> entry = iterator.next();
            if (entry.getValue().isExpired()) {
                String transactionId = entry.getValue().getVPRequest().getTransactionId();
                if (transactionId != null) {
                    transactionToRequestIdMap.remove(transactionId);
                }
                iterator.remove();

            }
        }

    }

    /**
     * Evict the oldest entries from the cache.
     *
     * @param count Number of entries to evict
     */
    private void evictOldestEntries(int count) {
        List<Map.Entry<String, VPRequestCacheEntry>> entries = new ArrayList<>(cacheByRequestId.entrySet());

        // Sort by creation time (oldest first)
        entries.sort((e1, e2) -> Long.compare(
                e1.getValue().getExpiresAt(),
                e2.getValue().getExpiresAt()));

        int evicted = 0;
        for (Map.Entry<String, VPRequestCacheEntry> entry : entries) {
            if (evicted >= count) {
                break;
            }
            remove(entry.getKey());
            evicted++;
        }

    }

    /**
     * Shutdown the cache and cleanup executor.
     * Should be called during application shutdown.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        clear();
    }
}
