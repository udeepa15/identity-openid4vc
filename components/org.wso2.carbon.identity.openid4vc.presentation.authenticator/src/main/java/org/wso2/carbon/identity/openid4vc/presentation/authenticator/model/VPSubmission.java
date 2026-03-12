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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;

import java.io.Serializable;

/**
 * Model class representing a Verifiable Presentation Submission.
 * This stores the VP token submitted by the wallet along with verification results.
 */
public class VPSubmission implements Serializable {

    private static final long serialVersionUID = 1L;

    private String submissionId;
    private String requestId;
    private String transactionId;
    private String vpToken;
    private String presentationSubmission;
    private String error;
    private String errorDescription;
    private VCVerificationStatus verificationStatus;
    private String verificationResult;
    private long submittedAt;
    private int tenantId;

    /**
     * Default constructor.
     */
    public VPSubmission() {
    }

    /**
     * Builder pattern constructor.
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

    // Getters and Setters

    public String getSubmissionId() {
        return submissionId;
    }

    public void setSubmissionId(String submissionId) {
        this.submissionId = submissionId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getVpToken() {
        return vpToken;
    }

    public void setVpToken(String vpToken) {
        this.vpToken = vpToken;
    }

    public String getPresentationSubmission() {
        return presentationSubmission;
    }

    public void setPresentationSubmission(String presentationSubmission) {
        this.presentationSubmission = presentationSubmission;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public VCVerificationStatus getVerificationStatus() {
        return verificationStatus;
    }

    public void setVerificationStatus(VCVerificationStatus verificationStatus) {
        this.verificationStatus = verificationStatus;
    }

    public String getVerificationResult() {
        return verificationResult;
    }

    public void setVerificationResult(String verificationResult) {
        this.verificationResult = verificationResult;
    }

    public long getSubmittedAt() {
        return submittedAt;
    }

    public void setSubmittedAt(long submittedAt) {
        this.submittedAt = submittedAt;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Check if this submission contains an error from the wallet.
     *
     * @return true if error is present, false otherwise
     */
    public boolean hasError() {
        return error != null && !error.trim().isEmpty();
    }

    /**
     * Check if this submission has a VP token.
     *
     * @return true if VP token is present, false otherwise
     */
    public boolean hasVpToken() {
        return vpToken != null && !vpToken.trim().isEmpty();
    }

    /**
     * Builder class for VPSubmission.
     */
    public static class Builder {
        private String submissionId;
        private String requestId;
        private String transactionId;
        private String vpToken;
        private String presentationSubmission;
        private String error;
        private String errorDescription;
        private VCVerificationStatus verificationStatus;
        private String verificationResult;
        private long submittedAt;
        private int tenantId;

        public Builder submissionId(String submissionId) {
            this.submissionId = submissionId;
            return this;
        }

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder transactionId(String transactionId) {
            this.transactionId = transactionId;
            return this;
        }

        public Builder vpToken(String vpToken) {
            this.vpToken = vpToken;
            return this;
        }

        public Builder presentationSubmission(String presentationSubmission) {
            this.presentationSubmission = presentationSubmission;
            return this;
        }

        public Builder error(String error) {
            this.error = error;
            return this;
        }

        public Builder errorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
            return this;
        }

        public Builder verificationStatus(VCVerificationStatus verificationStatus) {
            this.verificationStatus = verificationStatus;
            return this;
        }

        public Builder verificationResult(String verificationResult) {
            this.verificationResult = verificationResult;
            return this;
        }

        public Builder submittedAt(long submittedAt) {
            this.submittedAt = submittedAt;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public VPSubmission build() {
            return new VPSubmission(this);
        }
    }

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
