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

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.io.Serializable;

/**
 * DTO for VP request status responses.
 */
public class VPStatusResponseDTO implements Serializable {

    /**
     * Request ID.
     */
    @SerializedName("request_id")
    private String requestId;

    /**
     * Current status (ACTIVE, VP_SUBMITTED, EXPIRED, COMPLETED).
     */
    @SerializedName("status")
    private String status;

    /**
     * Whether VP token has been received.
     */
    @SerializedName("token_received")
    private boolean tokenReceived;

    /**
     * Whether the request has expired.
     */
    @SerializedName("expired")
    private boolean expired;

    /**
     * Error code if any.
     */
    @SerializedName("error")
    private String error;

    /**
     * Error description if any.
     */
    @SerializedName("error_description")
    private String errorDescription;

    /**
     * Transaction ID for result retrieval.
     */
    @SerializedName("transaction_id")
    private String transactionId;

    /**
     * Time remaining until expiry in seconds.
     */
    @SerializedName("expires_in")
    private Long expiresIn;

    /**
     * Builder pattern constructor.
     */
    private VPStatusResponseDTO(final Builder builder) {

        this.requestId = builder.requestId;
        this.status = builder.status;
        this.tokenReceived = builder.tokenReceived;
        this.expired = builder.expired;
        this.error = builder.error;
        this.errorDescription = builder.errorDescription;
        this.transactionId = builder.transactionId;
        this.expiresIn = builder.expiresIn;
    }

    // Getters and Setters

    /**
     * Get request ID.
     *
     * @return Request ID
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Set request ID.
     *
     * @param requestId Request ID
     */
    public void setRequestId(final String requestId) {

        this.requestId = requestId;
    }

    /**
     * Get status.
     *
     * @return Status
     */
    public String getStatus() {

        return status;
    }

    /**
     * Set status.
     *
     * @param status Status
     */
    public void setStatus(final String status) {

        this.status = status;
    }

    /**
     * Check if expired.
     *
     * @return true if expired
     */
    public boolean isExpired() {

        return expired;
    }

    /**
     * Set expired flag.
     *
     * @param expired Expired flag
     */
    public void setExpired(final boolean expired) {

        this.expired = expired;
    }

    /**
     * Get error code.
     *
     * @return Error code
     */
    public String getError() {

        return error;
    }

    /**
     * Set error code.
     *
     * @param error Error code
     */
    public void setError(final String error) {

        this.error = error;
    }

    /**
     * Get error description.
     *
     * @return Error description
     */
    public String getErrorDescription() {

        return errorDescription;
    }

    /**
     * Set error description.
     *
     * @param errorDescription Error description
     */
    public void setErrorDescription(final String errorDescription) {

        this.errorDescription = errorDescription;
    }

    /**
     * Get transaction ID.
     *
     * @return Transaction ID
     */
    public String getTransactionId() {

        return transactionId;
    }

    /**
     * Set transaction ID.
     *
     * @param transactionId Transaction ID
     */
    public void setTransactionId(final String transactionId) {

        this.transactionId = transactionId;
    }

    /**
     * Convert to JSON object.
     *
     * @return JsonObject representation
     */
    public JsonObject toJson() {

        JsonObject json = new JsonObject();

        if (requestId != null) {
            json.addProperty("request_id", requestId);
        }
        json.addProperty("status", status != null ? status : "UNKNOWN");
        json.addProperty("token_received", tokenReceived);
        json.addProperty("expired", expired);

        if (error != null) {
            json.addProperty("error", error);
        }
        if (errorDescription != null) {
            json.addProperty("error_description", errorDescription);
        }
        if (transactionId != null) {
            json.addProperty("transaction_id", transactionId);
        }
        if (expiresIn != null) {
            json.addProperty("expires_in", expiresIn);
        }

        return json;
    }

    /**
     * Builder class for VPStatusResponseDTO.
     */
    public static class Builder {

        private String requestId;
        private String status;
        private boolean tokenReceived;
        private boolean expired;
        private String error;
        private String errorDescription;
        private String transactionId;
        private Long expiresIn;

        /**
         * Set request ID.
         *
         * @param requestId Request ID
         * @return Builder
         */
        public Builder requestId(final String requestId) {

            this.requestId = requestId;
            return this;
        }

        /**
         * Set status.
         *
         * @param status Status string
         * @return Builder
         */
        public Builder status(final String status) {

            this.status = status;
            return this;
        }

        /**
         * Set token received flag.
         *
         * @param tokenReceived Whether VP token has been received
         * @return Builder
         */
        public Builder tokenReceived(final boolean tokenReceived) {

            this.tokenReceived = tokenReceived;
            return this;
        }

        /**
         * Set expired flag.
         *
         * @param expired Whether the request has expired
         * @return Builder
         */
        public Builder expired(final boolean expired) {

            this.expired = expired;
            return this;
        }

        /**
         * Set error code.
         *
         * @param error Error code
         * @return Builder
         */
        public Builder error(final String error) {

            this.error = error;
            return this;
        }

        /**
         * Set error description.
         *
         * @param errorDescription Error description
         * @return Builder
         */
        public Builder errorDescription(final String errorDescription) {

            this.errorDescription = errorDescription;
            return this;
        }

        /**
         * Set transaction ID.
         *
         * @param transactionId Transaction ID
         * @return Builder
         */
        public Builder transactionId(final String transactionId) {

            this.transactionId = transactionId;
            return this;
        }

        /**
         * Set expires-in value.
         *
         * @param expiresIn Time remaining until expiry in seconds
         * @return Builder
         */
        public Builder expiresIn(final Long expiresIn) {

            this.expiresIn = expiresIn;
            return this;
        }

        /**
         * Build the DTO.
         *
         * @return VPStatusResponseDTO
         */
        public VPStatusResponseDTO build() {

            return new VPStatusResponseDTO(this);
        }
    }

    @Override
    public String toString() {

        return "VPStatusResponseDTO{"
                + "requestId='" + requestId + '\''
                + ", status='" + status + '\''
                + ", tokenReceived=" + tokenReceived
                + ", expired=" + expired
                + ", error='" + error + '\''
                + '}';
    }
}
