/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.status;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Service for managing status change notifications.
 * Coordinates between VP submissions and polling clients.
 */
public class StatusNotificationService {

    private static volatile StatusNotificationService instance;

    private final List<StatusChangeListener> statusChangeListeners;

    /**
     * Private constructor for singleton.
     */
    private StatusNotificationService() {

        this.statusChangeListeners = new CopyOnWriteArrayList<>();

    }

    /**
     * Get singleton instance.
     *
     * @return StatusNotificationService instance
     */
    public static StatusNotificationService getInstance() {

        if (instance == null) {
            synchronized (StatusNotificationService.class) {
                if (instance == null) {
                    instance = new StatusNotificationService();
                }
            }
        }
        return instance;
    }

    /**
     * Notify that a VP has been submitted for a request.
     *
     * @param requestId  Request ID
     * @param submission The VP submission
     */
    public void notifyVPSubmitted(final String requestId, final VPSubmission submission) {

        if (requestId == null || submission == null) {
            return;
        }

        // Notify registered status change listeners
        notifyStatusChangeListeners(requestId, VPRequestStatus.VP_SUBMITTED, submission);
    }

    /**
     * Notify that a VP submission has an error.
     *
     * @param requestId        Request ID
     * @param error            Error code
     * @param errorDescription Error description
     */
    public void notifySubmissionError(final String requestId,
            final String error,
            final String errorDescription) {

        if (requestId == null) {
            return;
        }

        // Create minimal submission for listeners
        VPSubmission errorSubmission = new VPSubmission.Builder()
                .requestId(requestId)
                .error(error)
                .errorDescription(errorDescription)
                .build();

        // Notify registered status change listeners
        notifyStatusChangeListeners(requestId, VPRequestStatus.VP_SUBMITTED, errorSubmission);
    }

    /**
     * Notify that a request has expired.
     *
     * @param requestId Request ID
     */
    public void notifyRequestExpired(final String requestId) {

        if (requestId == null) {
            return;
        }

        // Notify registered status change listeners
        notifyStatusChangeListeners(requestId, VPRequestStatus.EXPIRED, null);
    }

    /**
     * Notify that verification is complete.
     *
     * @param requestId  Request ID
     * @param submission The VP submission with verification results
     */
    public void notifyVerificationComplete(final String requestId,
            final VPSubmission submission) {

        if (requestId == null) {
            return;
        }

        // Notify registered status change listeners
        notifyStatusChangeListeners(requestId, VPRequestStatus.COMPLETED, submission);
    }

    /**
     * Register a status change listener.
     *
     * @param listener Listener to register
     */
    public void registerStatusChangeListener(final StatusChangeListener listener) {

        if (listener != null && !statusChangeListeners.contains(listener)) {
            statusChangeListeners.add(listener);

        }
    }

    /**
     * Unregister a status change listener.
     *
     * @param listener Listener to unregister
     */
    public void unregisterStatusChangeListener(final StatusChangeListener listener) {

        if (listener != null) {
            statusChangeListeners.remove(listener);

        }
    }

    /**
     * Notify all registered status change listeners.
     */
    private void notifyStatusChangeListeners(final String requestId,
            final VPRequestStatus newStatus,
            final VPSubmission submission) {

        for (StatusChangeListener listener : statusChangeListeners) {
            try {
                listener.onStatusChange(requestId, newStatus, submission);
            } catch (RuntimeException e) {
                // Ignore runtime exceptions from listener to avoid disrupting notification flow
            }
        }
    }

    /**
     * Get count of registered status change listeners.
     *
     * @return Number of listeners
     */
    public int getStatusChangeListenerCount() {

        return statusChangeListeners.size();
    }

    /**
     * Interface for status change listeners.
     */
    public interface StatusChangeListener {

        /**
         * Called when a VP request status changes.
         *
         * @param requestId  Request ID
         * @param newStatus  New status
         * @param submission VP submission (may be null for some status changes)
         */
        void onStatusChange(String requestId, VPRequestStatus newStatus, VPSubmission submission);
    }
}
