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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import com.google.gson.annotations.SerializedName;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.Serializable;

/**
 * Model class representing a Verifiable Presentation Submission.
 * This stores the VP token submitted by the wallet along with verification results.
 */
public class VPSubmission implements Serializable {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Unique identifier for the submission.
     */
    private String submissionId;

    /**
     * The ID of the request this submission belongs to.
     */
    @SerializedName("state")
    private String requestId;

    /**
     * The transaction ID associated with the authentication session.
     */
    private String transactionId;

    /**
     * The VP token string submitted by the wallet.
     */
    @SerializedName("vp_token")
    private String vpToken;

    /**
     * The presentation submission JSON string.
     */
    @SerializedName("presentation_submission")
    private String presentationSubmission;

    /**
     * Error code if the submission failed at the wallet side.
     */
    @SerializedName("error")
    private String error;

    /**
     * Error description if the submission failed at the wallet side.
     */
    @SerializedName("error_description")
    private String errorDescription;

    /**
     * The status from the verification component.
     */
    private VerificationResult.VerificationStatus verificationStatus;

    /**
     * Detailed verification results in JSON.
     */
    private String verificationResult;

    /**
     * Timestamp when the submission was received.
     */
    private long submittedAt;

    /**
     * The ID of the tenant where this submission was made.
     */
    private int tenantId;

    /**
     * Default constructor for VPSubmission.
     */
    public VPSubmission() {

    }

    /**
     * Constructor for VPSubmission using the Builder pattern.
     *
     * @param builder The VPSubmission builder.
     */
    private VPSubmission(Builder builder) {

        this.submissionId = builder.submissionId;
        this.requestId = builder.requestId;
        this.transactionId = builder.transactionId;
        this.vpToken = builder.vpToken;
        this.presentationSubmission = builder.presentationSubmission;
        this.error = builder.error;
        this.errorDescription = builder.errorDescription;
        this.verificationStatus = builder.verificationStatus;
        this.verificationResult = builder.verificationResult;
        this.submittedAt = builder.submittedAt;
        this.tenantId = builder.tenantId;
    }

    /**
     * Get the unique identifier for the submission.
     *
     * @return The submission ID string.
     */
    public String getSubmissionId() {

        return submissionId;
    }

    /**
     * Set the unique identifier for the submission.
     *
     * @param submissionId The submission ID string.
     */
    public void setSubmissionId(String submissionId) {

        this.submissionId = submissionId;
    }

    /**
     * Get the request ID associated with this submission.
     *
     * @return The request ID string.
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Set the request ID associated with this submission.
     *
     * @param requestId The request ID string.
     */
    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    /**
     * Get the transaction ID associated with this submission.
     *
     * @return The transaction ID string.
     */
    public String getTransactionId() {

        return transactionId;
    }

    /**
     * Set the transaction ID associated with this submission.
     *
     * @param transactionId The transaction ID string.
     */
    public void setTransactionId(String transactionId) {

        this.transactionId = transactionId;
    }

    /**
     * Get the VP token string.
     *
     * @return The VP token string.
     */
    public String getVpToken() {

        return vpToken;
    }

    /**
     * Set the VP token string.
     *
     * @param vpToken The VP token string.
     */
    public void setVpToken(String vpToken) {

        this.vpToken = vpToken;
    }

    /**
     * Get the presentation submission JSON.
     *
     * @return The presentation submission JSON string.
     */
    public String getPresentationSubmission() {

        return presentationSubmission;
    }

    /**
     * Set the presentation submission JSON.
     *
     * @param presentationSubmission The presentation submission JSON string.
     */
    public void setPresentationSubmission(String presentationSubmission) {

        this.presentationSubmission = presentationSubmission;
    }

    /**
     * Get the error code from the wallet.
     *
     * @return The error code string.
     */
    public String getError() {

        return error;
    }

    /**
     * Set the error code from the wallet.
     *
     * @param error The error code string.
     */
    public void setError(String error) {

        this.error = error;
    }

    /**
     * Get the error description from the wallet.
     *
     * @return The error description string.
     */
    public String getErrorDescription() {

        return errorDescription;
    }

    /**
     * Set the error description from the wallet.
     *
     * @param errorDescription The error description string.
     */
    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }

    /**
     * Get the verification status from the verifier.
     *
     * @return The VerificationStatus enum value.
     */
    public VerificationResult.VerificationStatus getVerificationStatus() {

        return verificationStatus;
    }

    /**
     * Set the verification status from the verifier.
     *
     * @param verificationStatus The VerificationStatus enum value.
     */
    public void setVerificationStatus(VerificationResult.VerificationStatus verificationStatus) {

        this.verificationStatus = verificationStatus;
    }

    /**
     * Get the detailed verification result JSON.
     *
     * @return The verification result JSON string.
     */
    public String getVerificationResult() {

        return verificationResult;
    }

    /**
     * Set the detailed verification result JSON.
     *
     * @param verificationResult The verification result JSON string.
     */
    public void setVerificationResult(String verificationResult) {

        this.verificationResult = verificationResult;
    }

    /**
     * Get the submission timestamp.
     *
     * @return The timestamp in milliseconds.
     */
    public long getSubmittedAt() {

        return submittedAt;
    }

    /**
     * Set the submission timestamp.
     *
     * @param submittedAt The timestamp in milliseconds.
     */
    public void setSubmittedAt(long submittedAt) {

        this.submittedAt = submittedAt;
    }

    /**
     * Get the tenant ID where the submission was made.
     *
     * @return The tenant ID integer.
     */
    public int getTenantId() {

        return tenantId;
    }

    /**
     * Set the tenant ID where the submission was made.
     *
     * @param tenantId The tenant ID integer.
     */
    public void setTenantId(int tenantId) {

        this.tenantId = tenantId;
    }

    /**
     * Check if this submission contains an error from the wallet.
     *
     * @return True if an error is present, false otherwise.
     */
    public boolean hasError() {

        return error != null && !error.trim().isEmpty();
    }

    /**
     * Check if this submission has a VP token.
     *
     * @return True if a VP token is present, false otherwise.
     */
    public boolean hasVpToken() {

        return vpToken != null && !vpToken.trim().isEmpty();
    }

    /**
     * Builder class for generating VPSubmission instances.
     */
    public static class Builder {

        /**
         * Unique identifier for the submission.
         */
        private String submissionId;

        /**
         * The ID of the request this submission belongs to.
         */
        @SerializedName("state")
        private String requestId;

        /**
         * The transaction ID associated with the authentication session.
         */
        private String transactionId;

        /**
         * The VP token string submitted by the wallet.
         */
        @SerializedName("vp_token")
        private String vpToken;

        /**
         * The presentation submission JSON string.
         */
        @SerializedName("presentation_submission")
        private String presentationSubmission;

        /**
         * Error code if the submission failed at the wallet side.
         */
        @SerializedName("error")
        private String error;

        /**
         * Error description if the submission failed at the wallet side.
         */
        @SerializedName("error_description")
        private String errorDescription;

        /**
         * The status from the verification component.
         */
        private VerificationResult.VerificationStatus verificationStatus;

        /**
         * Detailed verification results in JSON.
         */
        private String verificationResult;

        /**
         * Timestamp when the submission was received.
         */
        private long submittedAt;

        /**
         * The ID of the tenant where this submission was made.
         */
        private int tenantId;

        /**
         * Set the submission ID.
         *
         * @param submissionId The submission identifier.
         * @return The builder instance.
         */
        public Builder submissionId(String submissionId) {

            this.submissionId = submissionId;
            return this;
        }

        /**
         * Set the request ID.
         *
         * @param requestId The request identifier.
         * @return The builder instance.
         */
        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }

        /**
         * Set the transaction ID.
         *
         * @param transactionId The transaction identifier.
         * @return The builder instance.
         */
        public Builder transactionId(String transactionId) {

            this.transactionId = transactionId;
            return this;
        }

        /**
         * Set the VP token.
         *
         * @param vpToken The VP token string.
         * @return The builder instance.
         */
        public Builder vpToken(String vpToken) {

            this.vpToken = vpToken;
            return this;
        }

        /**
         * Set the presentation submission JSON.
         *
         * @param presentationSubmission The presentation submission string.
         * @return The builder instance.
         */
        public Builder presentationSubmission(String presentationSubmission) {

            this.presentationSubmission = presentationSubmission;
            return this;
        }

        /**
         * Set the error code.
         *
         * @param error The error code string.
         * @return The builder instance.
         */
        public Builder error(String error) {

            this.error = error;
            return this;
        }

        /**
         * Set the error description.
         *
         * @param errorDescription The error description string.
         * @return The builder instance.
         */
        public Builder errorDescription(String errorDescription) {

            this.errorDescription = errorDescription;
            return this;
        }

        /**
         * Set the verification status.
         *
         * @param verificationStatus The verification status enum.
         * @return The builder instance.
         */
        public Builder verificationStatus(VerificationResult.VerificationStatus verificationStatus) {

            this.verificationStatus = verificationStatus;
            return this;
        }

        /**
         * Set the verification result JSON.
         *
         * @param verificationResult The verification result string.
         * @return The builder instance.
         */
        public Builder verificationResult(String verificationResult) {

            this.verificationResult = verificationResult;
            return this;
        }

        /**
         * Set the submission timestamp.
         *
         * @param submittedAt The timestamp in milliseconds.
         * @return The builder instance.
         */
        public Builder submittedAt(long submittedAt) {

            this.submittedAt = submittedAt;
            return this;
        }

        /**
         * Set the tenant ID.
         *
         * @param tenantId The tenant identifier.
         * @return The builder instance.
         */
        public Builder tenantId(int tenantId) {

            this.tenantId = tenantId;
            return this;
        }

        /**
         * Create the VPSubmission instance.
         *
         * @return A new VPSubmission object.
         */
        public VPSubmission build() {

            return new VPSubmission(this);
        }
    }

    /**
     * Returns a string representation of the VPSubmission.
     *
     * @return String representing the submission.
     */
    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder("VPSubmission{");
        sb.append("submissionId='").append(submissionId).append('\'');
        sb.append(", requestId='").append(requestId).append('\'');
        sb.append(", transactionId='").append(transactionId).append('\'');
        sb.append(", hasVpToken=").append(hasVpToken());
        sb.append(", hasError=").append(hasError());
        sb.append(", verificationStatus=").append(verificationStatus);
        sb.append(", submittedAt=").append(submittedAt);
        sb.append(", tenantId=").append(tenantId);
        sb.append('}');
        return sb.toString();
    }
}
