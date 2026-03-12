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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for API error responses.
 */
public final class ErrorDTO {

    /**
     * Error type string.
     */
    @SerializedName("error")
    private String error;

    /**
     * Error description string.
     */
    @SerializedName("error_description")
    private String errorDescription;

    /**
     * Error code string.
     */
    @SerializedName("error_code")
    private String errorCode;

    /**
     * Default constructor.
     */
    public ErrorDTO() {
    }

    /**
     * Constructor with error code and custom description.
     *
     * @param code          Error code enum
     * @param customDesc    Custom error description
     * @param codeValue     Optional error code value (can be null)
     */
    public ErrorDTO(final ErrorCode code,
                    final String customDesc,
                    final String codeValue) {

        this.error = code.getError();
        this.errorDescription = customDesc;
        this.errorCode = codeValue != null ? codeValue : code.name();
    }

    /**
     * Get the error type.
     *
     * @return Error type
     */
    public String getError() {

        return error;
    }

    /**
     * Set the error type.
     *
     * @param err Error type
     */
    public void setError(final String err) {

        this.error = err;
    }

    /**
     * Get the error description.
     *
     * @return Error description
     */
    public String getErrorDescription() {

        return errorDescription;
    }

    /**
     * Set the error description.
     *
     * @param desc Error description
     */
    public void setErrorDescription(final String desc) {

        this.errorDescription = desc;
    }

    /**
     * Get the error code.
     *
     * @return Error code
     */
    public String getErrorCode() {

        return errorCode;
    }

    /**
     * Set the error code.
     *
     * @param code Error code
     */
    public void setErrorCode(final String code) {

        this.errorCode = code;
    }

    /**
     * Enum defining standard error codes.
     */
    public enum ErrorCode {

        /**
         * Invalid request error.
         */
        INVALID_REQUEST("invalid_request", "Invalid or malformed request"),

        /**
         * Invalid client error.
         */
        INVALID_CLIENT("invalid_client", "Client authentication failed"),

        /**
         * Invalid token error.
         */
        INVALID_TOKEN("invalid_token", "The token is invalid or expired"),

        /**
         * Missing parameter error.
         */
        MISSING_PARAMETER("missing_parameter", "Required parameter missing"),

        /**
         * Presentation definition not found error.
         */
        PRESENTATION_DEFINITION_NOT_FOUND("presentation_definition_not_found",
            "Presentation definition not found"),

        /**
         * VP request not found error.
         */
        VP_REQUEST_NOT_FOUND("vp_request_not_found",
            "VP request was not found"),

        /**
         * VP submission not found error.
         */
        VP_SUBMISSION_NOT_FOUND("vp_submission_not_found",
            "VP submission not found"),

        /**
         * Invalid transaction ID error.
         */
        INVALID_TRANSACTION_ID("invalid_transaction_id",
            "Invalid transaction ID"),

        /**
         * VP request expired error.
         */
        VP_REQUEST_EXPIRED("vp_request_expired", "VP request has expired"),

        /**
         * Verification failed error.
         */
        VERIFICATION_FAILED("verification_failed",
            "Credential verification failed"),

        /**
         * Internal server error.
         */
        INTERNAL_ERROR("server_error", "Internal server error occurred"),

        /**
         * Invalid VP token error.
         */
        INVALID_VP_TOKEN("invalid_vp_token", "Invalid VP token");

        /**
         * Error string.
         */
        private final String error;

        /**
         * Description string.
         */
        private final String description;

        /**
         * Constructor.
         *
         * @param err  Error string
         * @param desc Description string
         */
        ErrorCode(final String err, final String desc) {

            this.error = err;
            this.description = desc;
        }

        /**
         * Get error string.
         *
         * @return Error string
         */
        public String getError() {

            return error;
        }

        /**
         * Get description string.
         *
         * @return Description string
         */
        public String getDescription() {

            return description;
        }
    }

    @Override
    public String toString() {

        return "ErrorDTO{"
                + "error='" + error + '\''
                + ", errorDescription='" + errorDescription + '\''
                + ", errorCode='" + errorCode + '\''
                + '}';
    }
}
