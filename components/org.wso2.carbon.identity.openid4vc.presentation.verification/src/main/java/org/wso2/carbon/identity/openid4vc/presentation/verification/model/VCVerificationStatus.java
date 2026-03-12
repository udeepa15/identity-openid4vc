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
 * Enum representing the verification status of a Verifiable Credential.
 */
public enum VCVerificationStatus {

    /**
     * Credential verification was successful.
     * All checks passed: signature, expiration, and revocation (if applicable).
     */
    SUCCESS("SUCCESS"),

    /**
     * Credential verification failed due to invalid signature or format.
     */
    INVALID("INVALID"),

    /**
     * Credential has expired based on the expirationDate field.
     */
    EXPIRED("EXPIRED"),

    /**
     * Credential has been revoked by the issuer.
     */
    REVOKED("REVOKED"),

    /**
     * Verification is pending or in progress.
     */
    PENDING("PENDING"),

    /**
     * Verification encountered an error (e.g., network issues, DID resolution failure).
     */
    ERROR("ERROR");

    private final String value;

    VCVerificationStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    /**
     * Get VCVerificationStatus from string value.
     *
     * @param value String value of the status
     * @return VCVerificationStatus enum or null if not found
     */
    public static VCVerificationStatus fromValue(String value) {
        if (value == null) {
            return null;
        }
        for (VCVerificationStatus status : VCVerificationStatus.values()) {
            if (status.value.equalsIgnoreCase(value)) {
                return status;
            }
        }
        return null;
    }

    /**
     * Check if this status represents a successful verification.
     *
     * @return true if SUCCESS, false otherwise
     */
    public boolean isSuccess() {
        return this == SUCCESS;
    }

    /**
     * Check if this status represents a failed verification.
     *
     * @return true if INVALID, EXPIRED, REVOKED, or ERROR
     */
    public boolean isFailure() {
        return this == INVALID || this == EXPIRED || this == REVOKED || this == ERROR;
    }

    @Override
    public String toString() {
        return value;
    }
}
