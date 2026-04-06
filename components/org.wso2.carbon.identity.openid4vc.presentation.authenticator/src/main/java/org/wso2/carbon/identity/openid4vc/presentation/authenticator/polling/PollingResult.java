/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import java.io.Serializable;

/**
 * Current status of a VP request returned by status checks.
 */
public class PollingResult implements Serializable {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Polling result status types.
     */
    public enum ResultStatus {

        /**
         * Request is active and waiting for submission.
         */
        WAITING,

        /**
         * Request is submitted or completed.
         */
        SUBMITTED,

        /**
         * Request has expired.
         */
        EXPIRED,

        /**
         * Request not found.
         */
        NOT_FOUND,

        /**
         * Error occurred.
         */
        ERROR
    }

    /**
     * The unique request identifier.
     */
    private final String requestId;

    /**
     * The classification of the result.
     */
    private final ResultStatus resultStatus;

    /**
     * The descriptive status string.
     */
    private final String status;

    /**
     * Error message details if an error occurred.
     */
    private final String errorMessage;

    /**
     * Private constructor for PollingResult.
     *
     * <p>Use static factory methods to create instances.</p>
     *
     * @param requestId    The unique request identifier.
     * @param resultStatus The classification of the result.
     * @param status       The descriptive status string.
     * @param errorMessage Error message details if applicable.
     */
    private PollingResult(final String requestId,
                          final ResultStatus resultStatus,
                          final String status,
                          final String errorMessage) {

        this.requestId = requestId;
        this.resultStatus = resultStatus;
        this.status = status;
        this.errorMessage = errorMessage;
    }

    /**
     * Create a result indicating that the VP submission is still pending.
     *
     * @param requestId The unique request identifier.
     * @return PollingResult for the waiting state.
     */
    public static PollingResult waiting(final String requestId) {

        return new PollingResult(requestId, ResultStatus.WAITING, "ACTIVE", null);
    }

    /**
     * Create a result indicating that the VP has been submitted.
     *
     * @param requestId The unique request identifier.
     * @param status    The status string representing the current state.
     * @return PollingResult for the submitted state.
     */
    public static PollingResult submitted(final String requestId, final String status) {

        return new PollingResult(requestId, ResultStatus.SUBMITTED, status, null);
    }

    /**
     * Create a result indicating that the request has expired.
     *
     * @param requestId The unique request identifier.
     * @return PollingResult for the expired state.
     */
    public static PollingResult expired(final String requestId) {

        return new PollingResult(requestId, ResultStatus.EXPIRED, "EXPIRED", null);
    }

    /**
     * Create a result indicating that the request was not found.
     *
     * @param requestId The unique request identifier.
     * @return PollingResult for the not found state.
     */
    public static PollingResult notFound(final String requestId) {

        return new PollingResult(requestId, ResultStatus.NOT_FOUND, null,
                "Request not found.");
    }

    /**
     * Create a result indicating that an error occurred during polling.
     *
     * @param requestId    The unique request identifier.
     * @param errorMessage Details of the error that occurred.
     * @return PollingResult for the error state.
     */
    public static PollingResult error(final String requestId, final String errorMessage) {

        return new PollingResult(requestId, ResultStatus.ERROR, null, errorMessage);
    }

    /**
     * Get the unique request identifier.
     *
     * @return The request identifier string.
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Get the classification of the result.
     *
     * @return The ResultStatus enum value.
     */
    public ResultStatus getResultStatus() {

        return resultStatus;
    }

    /**
     * Get the descriptive status string.
     *
     * @return The status string value.
     */
    public String getStatus() {

        return status;
    }

    /**
     * Get the error message if any.
     *
     * @return The error message string, or null if no error occurred.
     */
    public String getErrorMessage() {

        return errorMessage;
    }
}
