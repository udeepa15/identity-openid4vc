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

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model representing a trusted verifier entity.
 * Trusted verifiers are authorized to request credential presentations.
 */
public class TrustedVerifier {

    private String id;
    private String did;
    private String clientId;
    private String name;
    private String description;
    private String organizationName;
    private String organizationUrl;
    private String logoUrl;
    private List<String> allowedRedirectUris;
    private List<String> allowedCredentialTypes;
    private List<String> allowedScopes;
    private TrustLevel trustLevel;
    private VerifierStatus status;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant expiresAt;
    private Map<String, Object> metadata;

    /**
     * Default constructor.
     */
    public TrustedVerifier() {
        this.allowedRedirectUris = new ArrayList<>();
        this.allowedCredentialTypes = new ArrayList<>();
        this.allowedScopes = new ArrayList<>();
        this.metadata = new HashMap<>();
        this.trustLevel = TrustLevel.STANDARD;
        this.status = VerifierStatus.ACTIVE;
    }

    // Getters and Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getOrganizationUrl() {
        return organizationUrl;
    }

    public void setOrganizationUrl(String organizationUrl) {
        this.organizationUrl = organizationUrl;
    }

    public String getLogoUrl() {
        return logoUrl;
    }

    public void setLogoUrl(String logoUrl) {
        this.logoUrl = logoUrl;
    }

    public List<String> getAllowedRedirectUris() {
        return allowedRedirectUris != null ? new ArrayList<>(allowedRedirectUris) : null;
    }

    public void setAllowedRedirectUris(List<String> allowedRedirectUris) {
        this.allowedRedirectUris = allowedRedirectUris != null ? new ArrayList<>(allowedRedirectUris)
                : new ArrayList<>();
    }

    public List<String> getAllowedCredentialTypes() {
        return allowedCredentialTypes != null ? new ArrayList<>(allowedCredentialTypes) : null;
    }

    public void setAllowedCredentialTypes(List<String> allowedCredentialTypes) {
        this.allowedCredentialTypes = allowedCredentialTypes != null ? new ArrayList<>(allowedCredentialTypes)
                : new ArrayList<>();
    }

    public List<String> getAllowedScopes() {
        return allowedScopes != null ? new ArrayList<>(allowedScopes) : null;
    }

    public void setAllowedScopes(List<String> allowedScopes) {
        this.allowedScopes = allowedScopes != null ? new ArrayList<>(allowedScopes) : new ArrayList<>();
    }

    public TrustLevel getTrustLevel() {
        return trustLevel;
    }

    public void setTrustLevel(TrustLevel trustLevel) {
        this.trustLevel = trustLevel;
    }

    public VerifierStatus getStatus() {
        return status;
    }

    public void setStatus(VerifierStatus status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Map<String, Object> getMetadata() {
        return metadata != null ? new HashMap<>(metadata) : null;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
    }

    // Utility methods

    /**
     * Check if the verifier is currently active.
     *
     * @return true if active
     */
    public boolean isActive() {
        if (status != VerifierStatus.ACTIVE) {
            return false;
        }
        if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
            return false;
        }
        return true;
    }

    /**
     * Check if the verifier allows a specific credential type.
     *
     * @param credentialType the credential type to check
     * @return true if allowed or no restrictions
     */
    public boolean allowsCredentialType(String credentialType) {
        // Empty list means all types are allowed
        if (allowedCredentialTypes.isEmpty()) {
            return true;
        }
        return allowedCredentialTypes.contains(credentialType);
    }

    /**
     * Check if the verifier allows a specific redirect URI.
     *
     * @param redirectUri the redirect URI to check
     * @return true if allowed or no restrictions
     */
    public boolean allowsRedirectUri(String redirectUri) {
        // Empty list means all URIs are allowed
        if (allowedRedirectUris.isEmpty()) {
            return true;
        }
        return allowedRedirectUris.contains(redirectUri);
    }

    /**
     * Add a metadata entry.
     *
     * @param key   the key
     * @param value the value
     */
    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }

    /**
     * Get a metadata value.
     *
     * @param key the key
     * @return the value or null
     */
    public Object getMetadataValue(String key) {
        return metadata.get(key);
    }

    /**
     * Trust levels for verifiers.
     */
    public enum TrustLevel {
        /**
         * Basic trust - limited credential types.
         */
        BASIC,

        /**
         * Standard trust - typical access.
         */
        STANDARD,

        /**
         * Elevated trust - broader access.
         */
        ELEVATED,

        /**
         * Full trust - unrestricted access (use with caution).
         */
        FULL
    }

    /**
     * Status of the verifier.
     */
    public enum VerifierStatus {
        /**
         * Verifier is active and can make requests.
         */
        ACTIVE,

        /**
         * Verifier is temporarily suspended.
         */
        SUSPENDED,

        /**
         * Verifier has been revoked.
         */
        REVOKED,

        /**
         * Verifier is pending approval.
         */
        PENDING
    }

    /**
     * Builder for TrustedVerifier.
     */
    public static class Builder {
        private final TrustedVerifier verifier;

        public Builder() {
            this.verifier = new TrustedVerifier();
        }

        public Builder id(String id) {
            verifier.setId(id);
            return this;
        }

        public Builder did(String did) {
            verifier.setDid(did);
            return this;
        }

        public Builder clientId(String clientId) {
            verifier.setClientId(clientId);
            return this;
        }

        public Builder name(String name) {
            verifier.setName(name);
            return this;
        }

        public Builder description(String description) {
            verifier.setDescription(description);
            return this;
        }

        public Builder organizationName(String organizationName) {
            verifier.setOrganizationName(organizationName);
            return this;
        }

        public Builder organizationUrl(String organizationUrl) {
            verifier.setOrganizationUrl(organizationUrl);
            return this;
        }

        public Builder logoUrl(String logoUrl) {
            verifier.setLogoUrl(logoUrl);
            return this;
        }

        public Builder allowedRedirectUris(List<String> uris) {
            verifier.setAllowedRedirectUris(uris);
            return this;
        }

        public Builder addAllowedRedirectUri(String uri) {
            verifier.getAllowedRedirectUris().add(uri);
            return this;
        }

        public Builder allowedCredentialTypes(List<String> types) {
            verifier.setAllowedCredentialTypes(types);
            return this;
        }

        public Builder addAllowedCredentialType(String type) {
            verifier.getAllowedCredentialTypes().add(type);
            return this;
        }

        public Builder allowedScopes(List<String> scopes) {
            verifier.setAllowedScopes(scopes);
            return this;
        }

        public Builder addAllowedScope(String scope) {
            verifier.getAllowedScopes().add(scope);
            return this;
        }

        public Builder trustLevel(TrustLevel trustLevel) {
            verifier.setTrustLevel(trustLevel);
            return this;
        }

        public Builder status(VerifierStatus status) {
            verifier.setStatus(status);
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            verifier.setCreatedAt(createdAt);
            return this;
        }

        public Builder updatedAt(Instant updatedAt) {
            verifier.setUpdatedAt(updatedAt);
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            verifier.setExpiresAt(expiresAt);
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            verifier.setMetadata(metadata);
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            verifier.addMetadata(key, value);
            return this;
        }

        @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP")
        public TrustedVerifier build() {
            return verifier;
        }
    }
}
