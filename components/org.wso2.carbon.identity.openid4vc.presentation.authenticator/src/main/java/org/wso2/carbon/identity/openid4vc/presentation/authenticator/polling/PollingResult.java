/*
 * Copyright (c) 20262 LLC. (http://www.wso2.com).
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

    private final String requestId;
    private final ResultStatus resultStatus;
    private final String status;
    private final String errorMessage;

    /**
     * Private constructor - use factory methods.
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
     * Create a result indicating VP submission is still pending.
     *
     * @param requestId Request ID
     * @return PollingResult for waiting state
     */
    public static PollingResult waiting(final String requestId) {

        return new PollingResult(requestId, ResultStatus.WAITING, "ACTIVE", null);
    }

    /**
     * Create a result indicating VP has been submitted.
     *
     * @param requestId Request ID
     * @param status    Status string
     * @return PollingResult for submitted state
     */
    public static PollingResult submitted(final String requestId, final String status) {

        return new PollingResult(requestId, ResultStatus.SUBMITTED, status, null);
    }

    /**
     * Create a result indicating request has expired.
     *
     * @param requestId Request ID
     * @return PollingResult for expired state
     */
    public static PollingResult expired(final String requestId) {

        return new PollingResult(requestId, ResultStatus.EXPIRED, "EXPIRED", null);
    }

    /**
     * Create a result indicating request was not found.
     *
     * @param requestId Request ID
     * @return PollingResult for not found state
     */
    public static PollingResult notFound(final String requestId) {

        return new PollingResult(requestId, ResultStatus.NOT_FOUND, null,
                "Request not found");
    }

    /**
     * Create a result indicating an error occurred.
     *
     * @param requestId    Request ID
     * @param errorMessage Error message
     * @return PollingResult for error state
     */
    public static PollingResult error(final String requestId, final String errorMessage) {

        return new PollingResult(requestId, ResultStatus.ERROR, null, errorMessage);
    }

    /**
     * Get the request ID.
     *
     * @return Request ID
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Get the result status.
     *
     * @return ResultStatus
     */
    public ResultStatus getResultStatus() {

        return resultStatus;
    }

    /**
     * Get the status string.
     *
     * @return Status string
     */
    public String getStatus() {

        return status;
    }

    /**
     * Get error message if any.
     *
     * @return Error message or null
     */
    public String getErrorMessage() {

        return errorMessage;
    }

}
