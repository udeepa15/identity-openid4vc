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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe singleton cache for storing VP tokens and submission data
 * temporarily.
 * Implements TTL-based expiration mechanism.
 */
public class WalletDataCache {

    private static final WalletDataCache INSTANCE = new WalletDataCache();
    private static final long DEFAULT_TTL_MINUTES = 5;
    private static final long CLEANUP_INTERVAL_MINUTES = 1;

    private static volatile WalletDataCache walletDataCache;

    private final Map<String, CacheEntry> tokenCache;
    private final Map<String, ContextCacheEntry> contextCache;
    private final Map<String, SubmissionCacheEntry> submissionCache;
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Private constructor for singleton pattern.
     */
    private WalletDataCache() {
        this.tokenCache = new ConcurrentHashMap<>();
        this.contextCache = new ConcurrentHashMap<>();
        this.submissionCache = new ConcurrentHashMap<>();
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "WalletDataCache-Cleanup");
            thread.setDaemon(true);
            return thread;
        });
        startCleanupTask();
    }

    /**
     * Get singleton instance.
     *
     * @return WalletDataCache instance
     */
    @SuppressFBWarnings("MS_EXPOSE_REP")
    public static synchronized WalletDataCache getInstance() {

        if (walletDataCache == null) {
            walletDataCache = new WalletDataCache();
        }
        return walletDataCache;
    }

    /**
     * Store VP token with state as key.
     *
     * @param state   State parameter
     * @param vpToken VP token to store
     */
    public void storeToken(String state, String vpToken) {
        if (state == null || state.trim().isEmpty()) {
            return;
        }
        if (vpToken == null || vpToken.trim().isEmpty()) {
            return;
        }

        long expiryTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES);
        tokenCache.put(state, new CacheEntry(vpToken, expiryTime));

    }

    /**
     * Check if token exists for given state (without removing).
     *
     * @param state State parameter
     * @return true if token exists and not expired, false otherwise
     */
    public boolean hasToken(String state) {
        if (state == null || state.trim().isEmpty()) {

            return false;
        }

        CacheEntry entry = tokenCache.get(state);
        if (entry == null) {

            return false;
        }

        if (entry.isExpired()) {
            tokenCache.remove(state);

            return false;
        }

        return true;
    }

    /**
     * Retrieve and remove VP token (single-use).
     *
     * @param state State parameter
     * @return VP token or null if not found/expired
     */
    public String retrieveToken(String state) {
        if (state == null || state.trim().isEmpty()) {
            return null;
        }

        CacheEntry entry = tokenCache.remove(state);
        if (entry == null) {

            return null;
        }

        if (entry.isExpired()) {
            return null;
        }

        return entry.getToken();
    }

    /**
     * Store VP submission with request ID as key.
     *
     * @param requestId  Request ID (state parameter)
     * @param submission VP submission to store
     */
    public void storeSubmission(String requestId, VPSubmission submission) {
        if (requestId == null || requestId.trim().isEmpty()) {
            return;
        }
        if (submission == null) {
            return;
        }

        long expiryTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES);
        submissionCache.put(requestId, new SubmissionCacheEntry(submission, expiryTime));

    }

    /**
     * Retrieve VP submission (without removing).
     *
     * @param requestId Request ID (state parameter)
     * @return VP submission or null if not found/expired
     */
    public VPSubmission getSubmission(String requestId) {
        if (requestId == null || requestId.trim().isEmpty()) {
            return null;
        }

        SubmissionCacheEntry entry = submissionCache.get(requestId);
        if (entry == null) {

            return null;
        }

        if (entry.isExpired()) {
            submissionCache.remove(requestId);
            return null;
        }

        return entry.getSubmission();
    }

    /**
     * Retrieve and remove VP submission (single-use).
     *
     * @param requestId Request ID (state parameter)
     * @return VP submission or null if not found/expired
     */
    public VPSubmission retrieveSubmission(String requestId) {
        if (requestId == null || requestId.trim().isEmpty()) {
            return null;
        }

        SubmissionCacheEntry entry = submissionCache.remove(requestId);
        if (entry == null) {

            return null;
        }

        if (entry.isExpired()) {
            return null;
        }

        return entry.getSubmission();
    }

    /**
     * Check if submission exists for given request ID (without removing).
     *
     * @param requestId Request ID (state parameter)
     * @return true if submission exists and not expired, false otherwise
     */
    public boolean hasSubmission(String requestId) {
        if (requestId == null || requestId.trim().isEmpty()) {
            return false;
        }

        SubmissionCacheEntry entry = submissionCache.get(requestId);
        if (entry == null) {
            return false;
        }

        if (entry.isExpired()) {
            submissionCache.remove(requestId);
            return false;
        }

        return true;
    }

    /**
     * Store authentication context with sessionDataKey as key.
     *
     * @param sessionDataKey Session data key
     * @param context        Authentication context to store
     */
    public void storeContext(String sessionDataKey, AuthenticationContext context) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            return;
        }
        if (context == null) {
            return;
        }

        long expiryTime = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES);
        contextCache.put(sessionDataKey, new ContextCacheEntry(context, expiryTime));

    }

    /**
     * Retrieve authentication context (without removing).
     *
     * @param sessionDataKey Session data key
     * @return Authentication context or null if not found/expired
     */
    public AuthenticationContext getContext(String sessionDataKey) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            return null;
        }

        ContextCacheEntry entry = contextCache.get(sessionDataKey);
        if (entry == null) {

            return null;
        }

        if (entry.isExpired()) {
            contextCache.remove(sessionDataKey);
            return null;
        }

        return entry.getContext();
    }

    /**
     * Clear authentication context.
     *
     * @param sessionDataKey Session data key
     */
    public void clearContext(String sessionDataKey) {
        if (sessionDataKey == null || sessionDataKey.trim().isEmpty()) {
            return;
        }

        contextCache.remove(sessionDataKey);

    }

    /**
     * Start periodic cleanup task to remove expired entries.
     */
    private void startCleanupTask() {
        cleanupScheduler.scheduleAtFixedRate(this::cleanupCaches,
                CLEANUP_INTERVAL_MINUTES, CLEANUP_INTERVAL_MINUTES, TimeUnit.MINUTES);
    }

    /**
     * Cleanup expired entries from caches.
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    private void cleanupCaches() {
        try {
            // Clean up token cache
            for (Map.Entry<String, CacheEntry> entry : tokenCache.entrySet()) {
                if (entry.getValue().isExpired()) {
                    tokenCache.remove(entry.getKey());
                }
            }

            // Clean up context cache
            for (Map.Entry<String, ContextCacheEntry> entry : contextCache.entrySet()) {
                if (entry.getValue().isExpired()) {
                    contextCache.remove(entry.getKey());
                }
            }

            // Clean up submission cache
            for (Map.Entry<String, SubmissionCacheEntry> entry : submissionCache.entrySet()) {
                if (entry.getValue().isExpired()) {
                    submissionCache.remove(entry.getKey());
                }
            }

        } catch (Exception e) {
            // Ignore exceptions during cleanup to ensure scheduler continues
        }
    }

    /**
     * Get current cache size (for testing/monitoring).
     *
     * @return Number of entries in cache
     */
    public int size() {
        return tokenCache.size();
    }

    /**
     * Get current context cache size (for testing/monitoring).
     *
     * @return Number of context entries in cache
     */
    public int contextSize() {
        return contextCache.size();
    }

    /**
     * Get current submission cache size (for testing/monitoring).
     *
     * @return Number of submission entries in cache
     */
    public int submissionSize() {
        return submissionCache.size();
    }

    /**
     * Clear all entries (for testing).
     */
    public void clear() {
        tokenCache.clear();
        contextCache.clear();
        submissionCache.clear();

    }

    /**
     * Internal class to store cache entry with expiry time.
     */
    private static class CacheEntry {
        private final String token;
        private final long expiryTime;

        CacheEntry(String token, long expiryTime) {
            this.token = token;
            this.expiryTime = expiryTime;
        }

        String getToken() {
            return token;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    /**
     * Internal class to store context cache entry with expiry time.
     */
    private static class ContextCacheEntry {
        private final AuthenticationContext context;
        private final long expiryTime;

        ContextCacheEntry(AuthenticationContext context, long expiryTime) {
            this.context = context;
            this.expiryTime = expiryTime;
        }

        AuthenticationContext getContext() {
            return context;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    /**
     * Internal class to store submission cache entry with expiry time.
     */
    private static class SubmissionCacheEntry {
        private final VPSubmission submission;
        private final long expiryTime;

        SubmissionCacheEntry(VPSubmission submission, long expiryTime) {
            this.submission = submission;
            this.expiryTime = expiryTime;
        }

        VPSubmission getSubmission() {
            return submission;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }
}
