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
import java.util.List;
import java.util.Map;

/**
 * Model class representing a Verifiable Presentation.
 * Supports both JSON-LD VP and JWT VP formats as per OpenID4VP specification.
 */
public class VerifiablePresentation {

    /**
     * VP format types.
     */
    public enum Format {
        JSON_LD("ldp_vp"),
        JWT("jwt_vp"),
        JWT_JSON("jwt_vp_json");

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
    private String holder;
    private Date issuanceDate;
    private String nonce;

    // Verifiable Credentials contained in this VP
    private List<VerifiableCredential> verifiableCredentials;

    // Proof for JSON-LD VPs
    private VerifiableCredential.Proof proof;

    // Format information
    private Format format;
    private String rawPresentation;

    // JWT-specific fields
    private String jwtHeader;
    private String jwtPayload;
    private String jwtSignature;
    private Map<String, Object> jwtClaims;

    // Verification metadata
    private boolean signatureVerified;
    private boolean holderBindingVerified;

    /**
     * Default constructor.
     */
    public VerifiablePresentation() {
        this.context = new ArrayList<>();
        this.type = new ArrayList<>();
        this.verifiableCredentials = new ArrayList<>();
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

    public String getHolder() {
        return holder;
    }

    public void setHolder(String holder) {
        this.holder = holder;
    }

    public Date getIssuanceDate() {
        return issuanceDate != null ? new Date(issuanceDate.getTime()) : null;
    }

    public void setIssuanceDate(Date issuanceDate) {
        this.issuanceDate = issuanceDate != null ? new Date(issuanceDate.getTime()) : null;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public List<VerifiableCredential> getVerifiableCredentials() {
        return verifiableCredentials != null ? new ArrayList<>(verifiableCredentials) : null;
    }

    public void setVerifiableCredentials(List<VerifiableCredential> verifiableCredentials) {
        this.verifiableCredentials = verifiableCredentials != null ? new ArrayList<>(verifiableCredentials) : null;
    }

    public void addVerifiableCredential(VerifiableCredential vc) {
        if (this.verifiableCredentials == null) {
            this.verifiableCredentials = new ArrayList<>();
        }
        this.verifiableCredentials.add(vc);
    }

    /**
     * Get the number of credentials in this presentation.
     *
     * @return Number of credentials
     */
    public int getCredentialCount() {
        return verifiableCredentials != null ? verifiableCredentials.size() : 0;
    }

    /**
     * Get a credential by index.
     *
     * @param index The credential index
     * @return The credential or null if index is out of bounds
     */
    public VerifiableCredential getCredential(int index) {
        if (verifiableCredentials != null && index >= 0 && index < verifiableCredentials.size()) {
            return verifiableCredentials.get(index);
        }
        return null;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP")
    public VerifiableCredential.Proof getProof() {
        return proof;
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setProof(VerifiableCredential.Proof proof) {
        this.proof = proof;
    }

    public Format getFormat() {
        return format;
    }

    public void setFormat(Format format) {
        this.format = format;
    }

    public String getRawPresentation() {
        return rawPresentation;
    }

    public void setRawPresentation(String rawPresentation) {
        this.rawPresentation = rawPresentation;
    }

    public boolean isJsonLd() {
        return format == Format.JSON_LD;
    }

    public boolean isJwt() {
        return format == Format.JWT || format == Format.JWT_JSON;
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
        return jwtClaims != null ? new java.util.HashMap<>(jwtClaims) : null;
    }

    public void setJwtClaims(Map<String, Object> jwtClaims) {
        this.jwtClaims = jwtClaims != null ? new java.util.HashMap<>(jwtClaims) : null;
    }

    public boolean isSignatureVerified() {
        return signatureVerified;
    }

    public void setSignatureVerified(boolean signatureVerified) {
        this.signatureVerified = signatureVerified;
    }

    public boolean isHolderBindingVerified() {
        return holderBindingVerified;
    }

    public void setHolderBindingVerified(boolean holderBindingVerified) {
        this.holderBindingVerified = holderBindingVerified;
    }

    /**
     * Get the issuer (subject) from JWT claims.
     *
     * @return The issuer/subject or null
     */
    public String getJwtSubject() {
        if (jwtClaims != null && jwtClaims.containsKey("sub")) {
            return jwtClaims.get("sub").toString();
        }
        return null;
    }

    /**
     * Get the audience from JWT claims.
     *
     * @return The audience or null
     */
    public String getJwtAudience() {
        if (jwtClaims != null && jwtClaims.containsKey("aud")) {
            Object aud = jwtClaims.get("aud");
            if (aud instanceof List) {
                List<?> audList = (List<?>) aud;
                return !audList.isEmpty() ? audList.get(0).toString() : null;
            }
            return aud.toString();
        }
        return null;
    }

    /**
     * Get the nonce from JWT claims.
     *
     * @return The nonce or null
     */
    public String getJwtNonce() {
        if (jwtClaims != null && jwtClaims.containsKey("nonce")) {
            return jwtClaims.get("nonce").toString();
        }
        return nonce;
    }

    /**
     * Check if all credentials in this presentation have valid signatures.
     *
     * @return true if all credentials are signature verified
     */
    public boolean areAllCredentialsVerified() {
        if (verifiableCredentials == null || verifiableCredentials.isEmpty()) {
            return false;
        }
        for (VerifiableCredential vc : verifiableCredentials) {
            if (!vc.isSignatureVerified()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if any credential in this presentation has expired.
     *
     * @return true if any credential is expired
     */
    public boolean hasExpiredCredential() {
        if (verifiableCredentials != null) {
            for (VerifiableCredential vc : verifiableCredentials) {
                if (vc.isExpired()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get the first expired credential.
     *
     * @return The first expired credential or null
     */
    public VerifiableCredential getFirstExpiredCredential() {
        if (verifiableCredentials != null) {
            for (VerifiableCredential vc : verifiableCredentials) {
                if (vc.isExpired()) {
                    return vc;
                }
            }
        }
        return null;
    }

    /**
     * Get all credential types in this presentation.
     *
     * @return List of credential types
     */
    public List<String> getAllCredentialTypes() {
        List<String> types = new ArrayList<>();
        if (verifiableCredentials != null) {
            for (VerifiableCredential vc : verifiableCredentials) {
                types.add(vc.getPrimaryType());
            }
        }
        return types;
    }

    /**
     * Get all credential issuers in this presentation.
     *
     * @return List of issuer IDs
     */
    public List<String> getAllIssuers() {
        List<String> issuers = new ArrayList<>();
        if (verifiableCredentials != null) {
            for (VerifiableCredential vc : verifiableCredentials) {
                String issuer = vc.getIssuerId();
                if (issuer != null && !issuers.contains(issuer)) {
                    issuers.add(issuer);
                }
            }
        }
        return issuers;
    }

    @Override
    public String toString() {
        return "VerifiablePresentation{" +
                "id='" + id + '\'' +
                ", holder='" + holder + '\'' +
                ", format=" + format +
                ", credentialCount=" + getCredentialCount() +
                ", signatureVerified=" + signatureVerified +
                '}';
    }
}
