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

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe singleton cache for storing VP submissions and other temporary
 * request-scoped data.
 * Implements TTL-based expiration mechanism.
 */
public final class VPSubmissionCache {

    private static final long DEFAULT_TTL_MINUTES = 5;
    private static final long CLEANUP_INTERVAL_MINUTES = 1;

    private final Map<String, SubmissionCacheEntry> submissionCache;
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Private constructor for singleton pattern.
     */
    private VPSubmissionCache() {
        this.submissionCache = new ConcurrentHashMap<>();
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "VPSubmissionCache-Cleanup");
            thread.setDaemon(true);
            return thread;
        });
        startCleanupTask();
    }

    /**
     * Get singleton instance.
     *
     * @return VPSubmissionCache instance.
     */
    public static synchronized VPSubmissionCache getInstance() {
        return Holder.INSTANCE;
    }

    /**
     * Lazy-loaded singleton holder.
     */
    private static final class Holder {

        private static final VPSubmissionCache INSTANCE = new VPSubmissionCache();

        private Holder() {
        }
    }

    /**
     * Store VP submission with request ID as key.
     *
     * @param requestId Request ID.
     * @param submission VP submission to store.
     */
    public void storeSubmission(final String requestId, final VPSubmission submission) {
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
     * Retrieve VP submission.
     *
     * @param requestId Request ID.
     * @return VP submission or null if not found/expired.
     */
    public VPSubmission getSubmission(final String requestId) {
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
     * Check if submission exists for given request ID.
     *
     * @param requestId Request ID.
     * @return true if submission exists and not expired, false otherwise.
     */
    public boolean hasSubmission(final String requestId) {
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
     * Start periodic cleanup task to remove expired entries.
     */
    private void startCleanupTask() {
        cleanupScheduler.scheduleAtFixedRate(this::cleanupCaches,
                CLEANUP_INTERVAL_MINUTES, CLEANUP_INTERVAL_MINUTES, TimeUnit.MINUTES);
    }

    /**
     * Cleanup expired entries from caches.
     */
    private void cleanupCaches() {
        try {
            submissionCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
        } catch (RuntimeException e) {
            // Ignore runtime exceptions during cleanup to ensure scheduler continues.
        }
    }

    /**
     * Get current submission cache size.
     *
     * @return Number of submission entries in cache.
     */
    public int submissionSize() {
        return submissionCache.size();
    }

    /**
     * Internal class to store submission cache entry with expiry time.
     */
    private static class SubmissionCacheEntry {
        private final VPSubmission submission;
        private final long expiryTime;

        SubmissionCacheEntry(final VPSubmission submission, final long expiryTime) {
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
