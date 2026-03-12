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

package org.wso2.carbon.identity.openid4vc.presentation.verification.model;

/**
 * Model class representing the result of a revocation status check.
 */
public class RevocationCheckResult {

    /**
     * Status of the credential.
     */
    public enum Status {
        /**
         * Credential is valid (not revoked, not suspended).
         */
        VALID,

        /**
         * Credential has been revoked.
         */
        REVOKED,

        /**
         * Credential has been suspended (temporary).
         */
        SUSPENDED,

        /**
         * Unable to determine status (e.g., network error, unsupported status type).
         */
        UNKNOWN,

        /**
         * Status check was skipped (e.g., no credentialStatus field, check disabled).
         */
        SKIPPED
    }

    private Status status;
    private String statusPurpose;
    private String statusListCredentialUrl;
    private Integer statusIndex;
    private String message;
    private long checkedAt;
    private boolean cached;

    /**
     * Default constructor.
     */
    public RevocationCheckResult() {
        this.checkedAt = System.currentTimeMillis();
    }

    /**
     * Constructor with status.
     *
     * @param status The revocation status
     */
    public RevocationCheckResult(Status status) {
        this.status = status;
        this.checkedAt = System.currentTimeMillis();
    }

    /**
     * Constructor with status and message.
     *
     * @param status  The revocation status
     * @param message Additional message
     */
    public RevocationCheckResult(Status status, String message) {
        this.status = status;
        this.message = message;
        this.checkedAt = System.currentTimeMillis();
    }

    // Static factory methods

    /**
     * Create a result indicating the credential is valid.
     *
     * @return RevocationCheckResult with VALID status
     */
    public static RevocationCheckResult valid() {
        return new RevocationCheckResult(Status.VALID, "Credential is valid");
    }

    /**
     * Create a result indicating the credential is revoked.
     *
     * @param purpose The status purpose (e.g., "revocation")
     * @return RevocationCheckResult with REVOKED status
     */
    public static RevocationCheckResult revoked(String purpose) {
        RevocationCheckResult result = new RevocationCheckResult(Status.REVOKED,
                "Credential has been revoked");
        result.setStatusPurpose(purpose);
        return result;
    }

    /**
     * Create a result indicating the credential is suspended.
     *
     * @param purpose The status purpose
     * @return RevocationCheckResult with SUSPENDED status
     */
    public static RevocationCheckResult suspended(String purpose) {
        RevocationCheckResult result = new RevocationCheckResult(Status.SUSPENDED,
                "Credential has been suspended");
        result.setStatusPurpose(purpose);
        return result;
    }

    /**
     * Create a result indicating the status is unknown.
     *
     * @param message Reason for unknown status
     * @return RevocationCheckResult with UNKNOWN status
     */
    public static RevocationCheckResult unknown(String message) {
        return new RevocationCheckResult(Status.UNKNOWN, message);
    }

    /**
     * Create a result indicating the check was skipped.
     *
     * @param reason Reason for skipping
     * @return RevocationCheckResult with SKIPPED status
     */
    public static RevocationCheckResult skipped(String reason) {
        return new RevocationCheckResult(Status.SKIPPED, reason);
    }

    // Getters and Setters

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getStatusPurpose() {
        return statusPurpose;
    }

    public void setStatusPurpose(String statusPurpose) {
        this.statusPurpose = statusPurpose;
    }

    public String getStatusListCredentialUrl() {
        return statusListCredentialUrl;
    }

    public void setStatusListCredentialUrl(String statusListCredentialUrl) {
        this.statusListCredentialUrl = statusListCredentialUrl;
    }

    public Integer getStatusIndex() {
        return statusIndex;
    }

    public void setStatusIndex(Integer statusIndex) {
        this.statusIndex = statusIndex;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public long getCheckedAt() {
        return checkedAt;
    }

    public void setCheckedAt(long checkedAt) {
        this.checkedAt = checkedAt;
    }

    public boolean isCached() {
        return cached;
    }

    public void setCached(boolean cached) {
        this.cached = cached;
    }

    // Convenience methods

    /**
     * Check if the credential is valid (not revoked or suspended).
     *
     * @return true if valid or skipped
     */
    public boolean isValid() {
        return status == Status.VALID || status == Status.SKIPPED;
    }

    /**
     * Check if the credential is revoked.
     *
     * @return true if revoked
     */
    public boolean isRevoked() {
        return status == Status.REVOKED;
    }

    /**
     * Check if the credential is suspended.
     *
     * @return true if suspended
     */
    public boolean isSuspended() {
        return status == Status.SUSPENDED;
    }

    /**
     * Check if the credential is either revoked or suspended.
     *
     * @return true if revoked or suspended
     */
    public boolean isRevokedOrSuspended() {
        return status == Status.REVOKED || status == Status.SUSPENDED;
    }

    /**
     * Builder class for RevocationCheckResult.
     */
    public static class Builder {

        private final RevocationCheckResult result = new RevocationCheckResult();

        public Builder status(Status status) {
            result.status = status;
            return this;
        }

        public Builder statusPurpose(String statusPurpose) {
            result.statusPurpose = statusPurpose;
            return this;
        }

        public Builder statusListCredentialUrl(String url) {
            result.statusListCredentialUrl = url;
            return this;
        }

        public Builder statusIndex(Integer index) {
            result.statusIndex = index;
            return this;
        }

        public Builder message(String message) {
            result.message = message;
            return this;
        }

        public Builder cached(boolean cached) {
            result.cached = cached;
            return this;
        }

        @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP")
        public RevocationCheckResult build() {
            return result;
        }
    }

    @Override
    public String toString() {
        return "RevocationCheckResult{" +
                "status=" + status +
                ", statusPurpose='" + statusPurpose + '\'' +
                ", message='" + message + '\'' +
                ", cached=" + cached +
                '}';
    }
}
