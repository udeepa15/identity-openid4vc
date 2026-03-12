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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.status;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Manager for VP request status transitions.
 * Enforces valid state transitions and provides utilities for status
 * management.
 *
 * Valid transitions:
 * - ACTIVE → VP_SUBMITTED (when wallet submits VP)
 * - ACTIVE → EXPIRED (when request times out)
 * - VP_SUBMITTED → COMPLETED (when verification completes)
 * - VP_SUBMITTED → EXPIRED (if not processed in time)
 */
public class StatusTransitionManager {

    /**
     * Map of valid transitions for each status.
     */
    private static final Map<VPRequestStatus, Set<VPRequestStatus>> VALID_TRANSITIONS;

    static {
        VALID_TRANSITIONS = new EnumMap<>(VPRequestStatus.class);

        // From ACTIVE: Can go to VP_SUBMITTED or EXPIRED
        VALID_TRANSITIONS.put(VPRequestStatus.ACTIVE,
                EnumSet.of(VPRequestStatus.VP_SUBMITTED, VPRequestStatus.EXPIRED));

        // From VP_SUBMITTED: Can go to COMPLETED or EXPIRED
        VALID_TRANSITIONS.put(VPRequestStatus.VP_SUBMITTED,
                EnumSet.of(VPRequestStatus.COMPLETED, VPRequestStatus.EXPIRED));

        // COMPLETED and EXPIRED are terminal states
        VALID_TRANSITIONS.put(VPRequestStatus.COMPLETED, EnumSet.noneOf(VPRequestStatus.class));
        VALID_TRANSITIONS.put(VPRequestStatus.EXPIRED, EnumSet.noneOf(VPRequestStatus.class));
    }

    private StatusTransitionManager() {
        // Utility class
    }

    /**
     * Check if a transition from one status to another is valid.
     *
     * @param from Current status
     * @param to   Target status
     * @return true if transition is valid
     */
    public static boolean isValidTransition(final VPRequestStatus from,
            final VPRequestStatus to) {

        if (from == null || to == null) {
            return false;
        }

        Set<VPRequestStatus> validTargets = VALID_TRANSITIONS.get(from);
        return validTargets != null && validTargets.contains(to);
    }

    /**
     * Get valid next states from current status.
     *
     * @param currentStatus Current status
     * @return Set of valid next states
     */
    public static Set<VPRequestStatus> getValidNextStates(final VPRequestStatus currentStatus) {

        if (currentStatus == null) {
            return EnumSet.noneOf(VPRequestStatus.class);
        }

        Set<VPRequestStatus> validTargets = VALID_TRANSITIONS.get(currentStatus);
        return validTargets != null
                ? EnumSet.copyOf(validTargets)
                : EnumSet.noneOf(VPRequestStatus.class);
    }

    /**
     * Check if status is a terminal state (no more transitions possible).
     *
     * @param status Status to check
     * @return true if terminal
     */
    public static boolean isTerminalState(final VPRequestStatus status) {

        if (status == null) {
            return false;
        }
        return status == VPRequestStatus.COMPLETED || status == VPRequestStatus.EXPIRED;
    }

    /**
     * Check if status indicates VP has been submitted.
     *
     * @param status Status to check
     * @return true if VP submitted or completed
     */
    public static boolean hasVPSubmitted(final VPRequestStatus status) {

        if (status == null) {
            return false;
        }
        return status == VPRequestStatus.VP_SUBMITTED || status == VPRequestStatus.COMPLETED;
    }

    /**
     * Check if status indicates request is still waiting for VP.
     *
     * @param status Status to check
     * @return true if still waiting
     */
    public static boolean isWaitingForVP(final VPRequestStatus status) {

        return status == VPRequestStatus.ACTIVE;
    }

    /**
     * Check if status indicates request can still accept VP submission.
     *
     * @param status Status to check
     * @return true if can accept VP
     */
    public static boolean canAcceptVPSubmission(final VPRequestStatus status) {

        return status == VPRequestStatus.ACTIVE;
    }

    /**
     * Validate and perform status transition.
     *
     * @param from Current status
     * @param to   Target status
     * @return The new status if valid, otherwise returns the current status
     * @throws IllegalStateException if transition is invalid and strict mode
     */
    public static VPRequestStatus transition(final VPRequestStatus from,
            final VPRequestStatus to) {

        if (isValidTransition(from, to)) {

            return to;
        }

        return from;
    }

    /**
     * Validate and perform status transition with strict mode.
     *
     * @param from Current status
     * @param to   Target status
     * @return The new status
     * @throws InvalidStatusTransitionException if transition is invalid
     */
    public static VPRequestStatus transitionStrict(final VPRequestStatus from,
            final VPRequestStatus to)
            throws InvalidStatusTransitionException {

        if (!isValidTransition(from, to)) {
            throw new InvalidStatusTransitionException(
                    "Invalid status transition from " + from + " to " + to,
                    from, to);
        }

        return to;
    }

    /**
     * Get the appropriate status string for notifications.
     *
     * @param status   VP request status
     * @param hasError Whether there was an error
     * @return Status string for notifications
     */
    public static String getNotificationStatus(final VPRequestStatus status,
            final boolean hasError) {

        if (status == null) {
            return "UNKNOWN";
        }

        String statusStr = status.name();
        if (hasError && status == VPRequestStatus.VP_SUBMITTED) {
            return statusStr + "_ERROR";
        }
        return statusStr;
    }

    /**
     * Parse status from string.
     *
     * @param statusStr Status string
     * @return VPRequestStatus or null if invalid
     */
    public static VPRequestStatus parseStatus(final String statusStr) {

        if (statusStr == null || statusStr.isEmpty()) {
            return null;
        }

        try {
            // Handle ERROR suffix
            String normalizedStatus = statusStr.replace("_ERROR", "");
            return VPRequestStatus.valueOf(normalizedStatus);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Exception for invalid status transitions.
     */
    public static class InvalidStatusTransitionException extends Exception {

        private static final long serialVersionUID = 1L;

        private final VPRequestStatus fromStatus;
        private final VPRequestStatus toStatus;

        /**
         * Constructor.
         *
         * @param message    Error message
         * @param fromStatus Source status
         * @param toStatus   Target status
         */
        public InvalidStatusTransitionException(final String message,
                final VPRequestStatus fromStatus,
                final VPRequestStatus toStatus) {

            super(message);
            this.fromStatus = fromStatus;
            this.toStatus = toStatus;
        }

        /**
         * Get source status.
         *
         * @return Source status
         */
        public VPRequestStatus getFromStatus() {

            return fromStatus;
        }

        /**
         * Get target status.
         *
         * @return Target status
         */
        public VPRequestStatus getToStatus() {

            return toStatus;
        }
    }
}
