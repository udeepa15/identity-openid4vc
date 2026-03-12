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

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import com.google.gson.annotations.SerializedName;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;

import java.util.Arrays;

/**
 * Data Transfer Object for individual VC verification result.
 * Provides comprehensive information about each credential's verification
 * status.
 */
public class VCVerificationResultDTO {

    @SerializedName("vcIndex")
    private int vcIndex;

    @SerializedName("verificationStatus")
    private String verificationStatus;

    @SerializedName("credentialType")
    private String credentialType;

    @SerializedName("credentialTypes")
    private String[] credentialTypes;

    @SerializedName("issuer")
    private String issuer;

    @SerializedName("issuerId")
    private String issuerId;

    @SerializedName("subject")
    private String subject;

    @SerializedName("issuanceDate")
    private String issuanceDate;

    @SerializedName("expirationDate")
    private String expirationDate;

    @SerializedName("credentialId")
    private String credentialId;

    @SerializedName("format")
    private String format;

    @SerializedName("signatureValid")
    private Boolean signatureValid;

    @SerializedName("expired")
    private Boolean expired;

    @SerializedName("revoked")
    private Boolean revoked;

    @SerializedName("error")
    private String error;

    @SerializedName("errorDetails")
    private String errorDetails;

    /**
     * Default constructor.
     */
    public VCVerificationResultDTO() {
    }

    /**
     * Constructor for successful verification.
     *
     * @param vcIndex            Index of the VC in the VP
     * @param verificationStatus Verification status
     * @param credentialType     Type of the credential
     * @param issuer             Issuer of the credential
     */
    public VCVerificationResultDTO(int vcIndex, VCVerificationStatus verificationStatus,
            String credentialType, String issuer) {
        this.vcIndex = vcIndex;
        this.verificationStatus = verificationStatus.getValue();
        this.credentialType = credentialType;
        this.issuer = issuer;
    }

    /**
     * Constructor for failed verification.
     *
     * @param vcIndex            Index of the VC in the VP
     * @param verificationStatus Verification status
     * @param error              Error message
     */
    public VCVerificationResultDTO(int vcIndex, VCVerificationStatus verificationStatus, String error) {
        this.vcIndex = vcIndex;
        this.verificationStatus = verificationStatus.getValue();
        this.error = error;
    }

    /**
     * Copy constructor.
     *
     * @param other DTO to copy
     */
    public VCVerificationResultDTO(VCVerificationResultDTO other) {
        this.vcIndex = other.vcIndex;
        this.verificationStatus = other.verificationStatus;
        this.credentialType = other.credentialType;
        this.credentialTypes = other.credentialTypes != null
                ? Arrays.copyOf(other.credentialTypes, other.credentialTypes.length)
                : null;
        this.issuer = other.issuer;
        this.issuerId = other.issuerId;
        this.subject = other.subject;
        this.issuanceDate = other.issuanceDate;
        this.expirationDate = other.expirationDate;
        this.credentialId = other.credentialId;
        this.format = other.format;
        this.signatureValid = other.signatureValid;
        this.expired = other.expired;
        this.revoked = other.revoked;
        this.error = other.error;
        this.errorDetails = other.errorDetails;
    }

    // Getters and Setters

    public int getVcIndex() {
        return vcIndex;
    }

    public void setVcIndex(int vcIndex) {
        this.vcIndex = vcIndex;
    }

    public String getVerificationStatus() {
        return verificationStatus;
    }

    public void setVerificationStatus(String verificationStatus) {
        this.verificationStatus = verificationStatus;
    }

    public void setVerificationStatus(VCVerificationStatus status) {
        this.verificationStatus = status != null ? status.getValue() : null;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setCredentialTypes(String[] credentialTypes) {
        this.credentialTypes = credentialTypes != null ? Arrays.copyOf(credentialTypes, credentialTypes.length) : null;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setIssuanceDate(String issuanceDate) {
        this.issuanceDate = issuanceDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public void setSignatureValid(Boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public Boolean getExpired() {
        return expired;
    }

    public void setExpired(Boolean expired) {
        this.expired = expired;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public void setErrorDetails(String errorDetails) {
        this.errorDetails = errorDetails;
    }

    /**
     * Get verification status as enum.
     *
     * @return VCVerificationStatus enum or null
     */
    public VCVerificationStatus getVerificationStatusEnum() {
        return VCVerificationStatus.fromValue(verificationStatus);
    }

    /**
     * Check if verification was successful.
     *
     * @return true if SUCCESS
     */
    public boolean isSuccess() {
        VCVerificationStatus status = getVerificationStatusEnum();
        return status != null && status.isSuccess();
    }

    /**
     * Builder class for comprehensive result construction.
     */
    public static class Builder {

        private final VCVerificationResultDTO dto = new VCVerificationResultDTO();

        public Builder issuer(String issuer) {
            dto.setIssuer(issuer);
            return this;
        }

        public Builder format(String format) {
            dto.setFormat(format);
            return this;
        }

        public Builder expired(Boolean expired) {
            dto.setExpired(expired);
            return this;
        }

        public Builder error(String error) {
            dto.setError(error);
            return this;
        }

        public VCVerificationResultDTO build() {
            return new VCVerificationResultDTO(dto);
        }
    }

    @Override
    public String toString() {
        return "VCVerificationResultDTO{" +
                "vcIndex=" + vcIndex +
                ", verificationStatus='" + verificationStatus + '\'' +
                ", credentialType='" + credentialType + '\'' +
                ", issuer='" + issuer + '\'' +
                ", format='" + format + '\'' +
                ", signatureValid=" + signatureValid +
                ", expired=" + expired +
                ", revoked=" + revoked +
                ", error='" + error + '\'' +
                '}';
    }
}
