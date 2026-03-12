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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model class representing a Verifiable Credential.
 * Supports both JSON-LD and JWT credential formats as per W3C VC Data Model.
 */
public class VerifiableCredential {

    /**
     * Credential format types.
     */
    public enum Format {
        JSON_LD("ldp_vc"),
        JWT("jwt_vc"),
        JWT_JSON("jwt_vc_json"),
        SD_JWT("vc+sd-jwt");

        private final String value;

        Format(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static Format fromValue(String value) {
            for (Format format : values()) {
                if (format.value.equals(value)) {
                    return format;
                }
            }
            return null;
        }
    }

    // Core fields
    private String id;
    private List<String> context;
    private List<String> type;
    private String issuer;
    private String issuerId; // Extracted from issuer if object
    private String issuerName;
    private Date issuanceDate;
    private Date expirationDate;
    private Map<String, Object> credentialSubject;
    private String credentialSubjectId;

    // Credential status for revocation checking
    private CredentialStatus credentialStatus;

    // Proof for JSON-LD credentials
    private Proof proof;

    // Format information
    private Format format;
    private String rawCredential; // Original credential string

    // JWT-specific fields
    private String jwtHeader;
    private String jwtPayload;
    private String jwtSignature;
    private Map<String, Object> jwtClaims;

    // SD-JWT specific fields
    private List<String> disclosures;
    private String keyBindingJwt;

    // Verification metadata
    private boolean signatureVerified;
    private boolean expirationChecked;
    private boolean revocationChecked;

    /**
     * Default constructor.
     */
    public VerifiableCredential() {
        this.context = new ArrayList<>();
        this.type = new ArrayList<>();
        this.credentialSubject = new HashMap<>();
    }

    /**
     * Inner class representing credential status for revocation checking.
     */
    public static class CredentialStatus {
        private String id;
        private String type;
        private String statusPurpose;
        private String statusListIndex;
        private String statusListCredential;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getStatusPurpose() {
            return statusPurpose;
        }

        public void setStatusPurpose(String statusPurpose) {
            this.statusPurpose = statusPurpose;
        }

        public String getStatusListIndex() {
            return statusListIndex;
        }

        public void setStatusListIndex(String statusListIndex) {
            this.statusListIndex = statusListIndex;
        }

        public String getStatusListCredential() {
            return statusListCredential;
        }

        public void setStatusListCredential(String statusListCredential) {
            this.statusListCredential = statusListCredential;
        }

        public boolean isStatusList2021() {
            return "StatusList2021Entry".equals(type) || "StatusList2021".equals(type);
        }
    }

    /**
     * Inner class representing the proof object for JSON-LD credentials.
     */
    public static class Proof {
        private String type;
        private String created;
        private String verificationMethod;
        private String proofPurpose;
        private String proofValue;
        private String jws;
        private String challenge;
        private String domain;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getCreated() {
            return created;
        }

        public void setCreated(String created) {
            this.created = created;
        }

        public String getVerificationMethod() {
            return verificationMethod;
        }

        public void setVerificationMethod(String verificationMethod) {
            this.verificationMethod = verificationMethod;
        }

        public String getProofPurpose() {
            return proofPurpose;
        }

        public void setProofPurpose(String proofPurpose) {
            this.proofPurpose = proofPurpose;
        }

        public String getProofValue() {
            return proofValue;
        }

        public void setProofValue(String proofValue) {
            this.proofValue = proofValue;
        }

        public String getJws() {
            return jws;
        }

        public void setJws(String jws) {
            this.jws = jws;
        }

        public String getChallenge() {
            return challenge;
        }

        public void setChallenge(String challenge) {
            this.challenge = challenge;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        /**
         * Check if this is an Ed25519 signature.
         */
        public boolean isEd25519() {
            return type != null && (type.contains("Ed25519") || type.equals("Ed25519Signature2020")
                    || type.equals("Ed25519Signature2018"));
        }

        /**
         * Check if this is a JSON Web Signature.
         */
        public boolean isJsonWebSignature() {
            return type != null && type.contains("JsonWebSignature");
        }
    }

    // Getters and Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getContext() {
        return context != null ? new ArrayList<>(context) : null;
    }

    public void setContext(List<String> context) {
        this.context = context != null ? new ArrayList<>(context) : null;
    }

    public void addContext(String ctx) {
        if (this.context == null) {
            this.context = new ArrayList<>();
        }
        this.context.add(ctx);
    }

    public List<String> getType() {
        return type != null ? new ArrayList<>(type) : null;
    }

    public void setType(List<String> type) {
        this.type = type != null ? new ArrayList<>(type) : null;
    }

    public void addType(String t) {
        if (this.type == null) {
            this.type = new ArrayList<>();
        }
        this.type.add(t);
    }

    /**
     * Get the primary credential type (first non-VerifiableCredential type).
     */
    public String getPrimaryType() {
        if (type != null) {
            for (String t : type) {
                if (!"VerifiableCredential".equals(t)) {
                    return t;
                }
            }
        }
        return "VerifiableCredential";
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerId() {
        return issuerId != null ? issuerId : issuer;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public Date getIssuanceDate() {
        return issuanceDate != null ? new Date(issuanceDate.getTime()) : null;
    }

    public void setIssuanceDate(Date issuanceDate) {
        this.issuanceDate = issuanceDate != null ? new Date(issuanceDate.getTime()) : null;
    }

    public Date getExpirationDate() {
        return expirationDate != null ? new Date(expirationDate.getTime()) : null;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate != null ? new Date(expirationDate.getTime()) : null;
    }

    public Map<String, Object> getCredentialSubject() {
        return credentialSubject != null ? new HashMap<>(credentialSubject) : null;
    }

    public void setCredentialSubject(Map<String, Object> credentialSubject) {
        this.credentialSubject = credentialSubject != null ? new HashMap<>(credentialSubject) : null;
    }

    public String getCredentialSubjectId() {
        return credentialSubjectId;
    }

    public void setCredentialSubjectId(String credentialSubjectId) {
        this.credentialSubjectId = credentialSubjectId;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP")
    public CredentialStatus getCredentialStatus() {
        return credentialStatus;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setCredentialStatus(CredentialStatus credentialStatus) {
        this.credentialStatus = credentialStatus;
    }

    public boolean hasCredentialStatus() {
        return credentialStatus != null;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP")
    public Proof getProof() {
        return proof;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setProof(Proof proof) {
        this.proof = proof;
    }

    public Format getFormat() {
        return format;
    }

    public void setFormat(Format format) {
        this.format = format;
    }

    public String getRawCredential() {
        return rawCredential;
    }

    public void setRawCredential(String rawCredential) {
        this.rawCredential = rawCredential;
    }

    public boolean isJsonLd() {
        return format == Format.JSON_LD;
    }

    public boolean isJwt() {
        return format == Format.JWT || format == Format.JWT_JSON;
    }

    public boolean isSdJwt() {
        return format == Format.SD_JWT;
    }

    public String getJwtHeader() {
        return jwtHeader;
    }

    public void setJwtHeader(String jwtHeader) {
        this.jwtHeader = jwtHeader;
    }

    public String getJwtPayload() {
        return jwtPayload;
    }

    public void setJwtPayload(String jwtPayload) {
        this.jwtPayload = jwtPayload;
    }

    public String getJwtSignature() {
        return jwtSignature;
    }

    public void setJwtSignature(String jwtSignature) {
        this.jwtSignature = jwtSignature;
    }

    public Map<String, Object> getJwtClaims() {
        return jwtClaims != null ? new HashMap<>(jwtClaims) : null;
    }

    public void setJwtClaims(Map<String, Object> jwtClaims) {
        this.jwtClaims = jwtClaims != null ? new HashMap<>(jwtClaims) : null;
    }

    public List<String> getDisclosures() {
        return disclosures != null ? new ArrayList<>(disclosures) : null;
    }

    public void setDisclosures(List<String> disclosures) {
        this.disclosures = disclosures != null ? new ArrayList<>(disclosures) : null;
    }

    public void addDisclosure(String disclosure) {
        if (this.disclosures == null) {
            this.disclosures = new ArrayList<>();
        }
        this.disclosures.add(disclosure);
    }

    public String getKeyBindingJwt() {
        return keyBindingJwt;
    }

    public void setKeyBindingJwt(String keyBindingJwt) {
        this.keyBindingJwt = keyBindingJwt;
    }

    public boolean isSignatureVerified() {
        return signatureVerified;
    }

    public void setSignatureVerified(boolean signatureVerified) {
        this.signatureVerified = signatureVerified;
    }

    public boolean isExpirationChecked() {
        return expirationChecked;
    }

    public void setExpirationChecked(boolean expirationChecked) {
        this.expirationChecked = expirationChecked;
    }

    public boolean isRevocationChecked() {
        return revocationChecked;
    }

    public void setRevocationChecked(boolean revocationChecked) {
        this.revocationChecked = revocationChecked;
    }

    /**
     * Check if the credential has expired based on expirationDate.
     *
     * @return true if expired
     */
    public boolean isExpired() {
        if (expirationDate == null) {
            return false;
        }
        return new Date().after(expirationDate);
    }

    /**
     * Check if the credential is not yet valid based on issuanceDate.
     *
     * @return true if not yet valid
     */
    public boolean isNotYetValid() {
        if (issuanceDate == null) {
            return false;
        }
        return new Date().before(issuanceDate);
    }

    /**
     * Get the verification method from the proof.
     *
     * @return Verification method URI or null
     */
    public String getVerificationMethod() {
        if (proof != null) {
            return proof.getVerificationMethod();
        }
        return null;
    }

    /**
     * Get a claim value from the credential subject.
     *
     * @param claimName The claim name
     * @return The claim value or null
     */
    public Object getClaim(String claimName) {
        if (credentialSubject != null) {
            return credentialSubject.get(claimName);
        }
        return null;
    }

    /**
     * Get a string claim value from the credential subject.
     *
     * @param claimName The claim name
     * @return The claim value as string or null
     */
    public String getStringClaim(String claimName) {
        Object value = getClaim(claimName);
        return value != null ? value.toString() : null;
    }

    @Override
    public String toString() {
        return "VerifiableCredential{" +
                "id='" + id + '\'' +
                ", type=" + type +
                ", issuer='" + getIssuerId() + '\'' +
                ", format=" + format +
                ", expired=" + isExpired() +
                '}';
    }
}
