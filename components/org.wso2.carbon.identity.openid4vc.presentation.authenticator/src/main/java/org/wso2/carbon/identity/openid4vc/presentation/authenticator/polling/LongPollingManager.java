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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Manager for long polling operations.
 * Handles the coordination between status polling requests and VP submissions.
 */
public class LongPollingManager {

    private static volatile LongPollingManager instance;

    /**
     * Default polling timeout in milliseconds (5 seconds).
     */
    private static final long DEFAULT_POLLING_TIMEOUT_MS = 5000L;

    /**
     * Minimum polling timeout in milliseconds (5 seconds).
     */
    private static final long MIN_POLLING_TIMEOUT_MS = 5000L;

    /**
     * Maximum polling timeout in milliseconds (120 seconds).
     */
    private static final long MAX_POLLING_TIMEOUT_MS = 120000L;

    private final VPStatusListenerCache statusListenerCache;
    private final WalletDataCache walletDataCache;
    private final VPRequestDAO vpRequestDAO;

    /**
     * Private constructor for singleton.
     */
    private LongPollingManager() {

        this.statusListenerCache = VPStatusListenerCache.getInstance();
        this.walletDataCache = WalletDataCache.getInstance();
        this.vpRequestDAO = new VPRequestDAOImpl();

    }

    /**
     * Get singleton instance.
     *
     * @return LongPollingManager instance
     */
    public static LongPollingManager getInstance() {

        if (instance == null) {
            synchronized (LongPollingManager.class) {
                if (instance == null) {
                    instance = new LongPollingManager();
                }
            }
        }
        return instance;
    }

    /**
     * Wait for status change with long polling.
     * This method blocks until:
     * 1. The status changes (VP submitted or error)
     * 2. The timeout expires
     * 3. The request expires
     *
     * @param requestId Request ID to poll for
     * @param timeoutMs Timeout in milliseconds
     * @param tenantId  Tenant ID
     * @return PollingResult with the current status
     */
    public PollingResult waitForStatusChange(final String requestId,
            final long timeoutMs,
            final int tenantId) {

        long actualTimeout = normalizeTimeout(timeoutMs);
        String listenerId = generateListenerId();

        // First check current status immediately
        PollingResult immediateResult = checkCurrentStatus(requestId, tenantId);
        if (immediateResult.isComplete()) {

            return immediateResult;
        }

        // Set up long polling with latch
        final CountDownLatch latch = new CountDownLatch(1);
        final PollingResultHolder resultHolder = new PollingResultHolder();

        // Register listener
        VPStatusListenerCache.StatusCallback callback = new VPStatusListenerCache.StatusCallback() {

            @Override
            public void onStatusChange(String status) {

                resultHolder.setResult(createPollingResult(status, requestId, tenantId));
                latch.countDown();
            }

            @Override
            public void onTimeout() {

                resultHolder.setResult(PollingResult.timeout(requestId));
                latch.countDown();
            }
        };

        statusListenerCache.registerListener(requestId, listenerId, actualTimeout, callback);

        try {
            // Wait for status change or timeout
            boolean completed = latch.await(actualTimeout, TimeUnit.MILLISECONDS);

            if (!completed) {
                // Timeout occurred

                return PollingResult.timeout(requestId);
            }

            // Return the result set by the callback
            PollingResult result = resultHolder.getResult();
            return result != null ? result : PollingResult.timeout(requestId);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return PollingResult.error(requestId, "Polling interrupted");
        } finally {
            // Clean up listener
            statusListenerCache.removeListener(requestId, listenerId);
        }
    }

    /**
     * Check current status without waiting.
     *
     * @param requestId Request ID to check
     * @param tenantId  Tenant ID
     * @return PollingResult with current status
     */
    public PollingResult checkCurrentStatus(final String requestId, final int tenantId) {

        // Check if VP token is available in cache
        if (walletDataCache.hasToken(requestId)) {
            return PollingResult.submitted(requestId,
                    VPRequestStatus.VP_SUBMITTED.name());
        }

        // Check if submission is available in cache
        if (walletDataCache.hasSubmission(requestId)) {
            return PollingResult.submitted(requestId,
                    VPRequestStatus.VP_SUBMITTED.name());
        }

        // Check database for request status
        try {
            VPRequest vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);

            if (vpRequest == null) {
                return PollingResult.notFound(requestId);
            }

            VPRequestStatus status = vpRequest.getStatus();

            switch (status) {
                case VP_SUBMITTED:
                case COMPLETED:
                    return PollingResult.submitted(requestId, status.name());

                case EXPIRED:
                    return PollingResult.expired(requestId);

                case ACTIVE:
                default:
                    // Check if request has actually expired
                    if (isRequestExpired(vpRequest)) {
                        return PollingResult.expired(requestId);
                    }
                    return PollingResult.waiting(requestId);
            }
        } catch (VPException e) {
            return PollingResult.error(requestId, e.getMessage());
        }
    }

    /**
     * Notify that a VP has been submitted for a request.
     * This will trigger all waiting long poll requests to complete.
     *
     * @param requestId Request ID
     * @param status    New status
     */
    public void notifySubmission(final String requestId, final String status) {

        statusListenerCache.notifyListeners(requestId, status);
    }

    /**
     * Create polling result based on status.
     */
    private PollingResult createPollingResult(final String status,
            final String requestId,
            final int tenantId) {

        if (status == null) {
            return PollingResult.waiting(requestId);
        }

        if (status.startsWith(VPRequestStatus.VP_SUBMITTED.name())) {
            if (status.contains("ERROR")) {
                return PollingResult.submittedWithError(requestId, status);
            }
            return PollingResult.submitted(requestId, status);
        }

        if (status.equals(VPRequestStatus.EXPIRED.name())) {
            return PollingResult.expired(requestId);
        }

        if (status.equals(VPRequestStatus.COMPLETED.name())) {
            return PollingResult.submitted(requestId, status);
        }

        return PollingResult.waiting(requestId);
    }

    /**
     * Check if request has expired.
     */
    private boolean isRequestExpired(final VPRequest vpRequest) {

        return vpRequest.getExpiresAt() > 0
                && System.currentTimeMillis() > vpRequest.getExpiresAt();
    }

    /**
     * Normalize timeout to valid range.
     */
    private long normalizeTimeout(final long timeoutMs) {

        if (timeoutMs <= 0) {
            return DEFAULT_POLLING_TIMEOUT_MS;
        }
        if (timeoutMs < MIN_POLLING_TIMEOUT_MS) {
            return MIN_POLLING_TIMEOUT_MS;
        }
        if (timeoutMs > MAX_POLLING_TIMEOUT_MS) {
            return MAX_POLLING_TIMEOUT_MS;
        }
        return timeoutMs;
    }

    /**
     * Generate unique listener ID.
     */
    private String generateListenerId() {

        return "poll_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * Holder class for passing result from callback.
     */
    private static class PollingResultHolder {

        private volatile PollingResult result;

        void setResult(final PollingResult result) {

            this.result = result;
        }

        PollingResult getResult() {

            return result;
        }
    }

    /**
     * Get default polling timeout.
     *
     * @return Default timeout in milliseconds
     */
    public long getDefaultPollingTimeoutMs() {

        return DEFAULT_POLLING_TIMEOUT_MS;
    }

    /**
     * Get statistics about active listeners.
     *
     * @return Number of active listeners
     */
    public int getActiveListenerCount() {

        return statusListenerCache.getTotalListenerCount();
    }
}
