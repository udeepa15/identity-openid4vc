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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.TrustedVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.TrustedVerifierService;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of TrustedVerifierService.
 * Manages trusted verifiers with in-memory storage and caching.
 * In production, this should be backed by a persistent store.
 */
public class TrustedVerifierServiceImpl implements TrustedVerifierService {

    // In-memory storage for trusted verifiers (tenant -> verifierId -> verifier)
    private final Map<String, Map<String, TrustedVerifier>> verifierStore = new ConcurrentHashMap<>();

    // DID index for quick lookup (tenant -> did -> verifierId)
    private final Map<String, Map<String, String>> didIndex = new ConcurrentHashMap<>();

    // Client ID index for quick lookup (tenant -> clientId -> verifierId)
    private final Map<String, Map<String, String>> clientIdIndex = new ConcurrentHashMap<>();

    // Configuration settings per tenant
    private final Map<String, TenantConfig> tenantConfigs = new ConcurrentHashMap<>();

    // Default strict verification mode
    private boolean defaultStrictMode = false;

    // Default redirect URI validation mode
    private RedirectUriValidationMode defaultRedirectUriMode = RedirectUriValidationMode.RELAXED;

    @Override
    public boolean isVerifierTrusted(String verifierDid, String tenantDomain) {
        if (StringUtils.isBlank(verifierDid)) {
            return false;
        }

        // If strict mode is disabled, all verifiers are considered trusted
        if (!isStrictVerificationEnabled(tenantDomain)) {
            return true;
        }

        // Check if verifier exists and is active
        Optional<TrustedVerifier> verifier = getTrustedVerifier(verifierDid, tenantDomain);
        return verifier.isPresent() && verifier.get().isActive();
    }

    @Override
    public boolean isVerifierTrustedByClientId(String clientId, String tenantDomain) {
        if (StringUtils.isBlank(clientId)) {
            return false;
        }

        // If strict mode is disabled, all verifiers are considered trusted
        if (!isStrictVerificationEnabled(tenantDomain)) {
            return true;
        }

        Optional<TrustedVerifier> verifier = getTrustedVerifierByClientId(clientId, tenantDomain);
        return verifier.isPresent() && verifier.get().isActive();
    }

    @Override
    public Optional<TrustedVerifier> getTrustedVerifier(String verifierDid, String tenantDomain) {
        if (StringUtils.isBlank(verifierDid) || StringUtils.isBlank(tenantDomain)) {
            return Optional.empty();
        }

        Map<String, String> tenantDidIndex = didIndex.get(tenantDomain);
        if (tenantDidIndex == null) {
            return Optional.empty();
        }

        String verifierId = tenantDidIndex.get(verifierDid);
        if (verifierId == null) {
            return Optional.empty();
        }

        Map<String, TrustedVerifier> tenantVerifiers = verifierStore.get(tenantDomain);
        if (tenantVerifiers == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(tenantVerifiers.get(verifierId));
    }

    @Override
    public Optional<TrustedVerifier> getTrustedVerifierByClientId(String clientId, String tenantDomain) {
        if (StringUtils.isBlank(clientId) || StringUtils.isBlank(tenantDomain)) {
            return Optional.empty();
        }

        Map<String, String> tenantClientIdIndex = clientIdIndex.get(tenantDomain);
        if (tenantClientIdIndex == null) {
            return Optional.empty();
        }

        String verifierId = tenantClientIdIndex.get(clientId);
        if (verifierId == null) {
            return Optional.empty();
        }

        Map<String, TrustedVerifier> tenantVerifiers = verifierStore.get(tenantDomain);
        if (tenantVerifiers == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(tenantVerifiers.get(verifierId));
    }

    @Override
    public List<TrustedVerifier> getTrustedVerifiers(String tenantDomain) throws VPException {
        if (StringUtils.isBlank(tenantDomain)) {
            return new ArrayList<>();
        }

        Map<String, TrustedVerifier> tenantVerifiers = verifierStore.get(tenantDomain);
        if (tenantVerifiers == null) {
            return new ArrayList<>();
        }

        return new ArrayList<>(tenantVerifiers.values());
    }

    @Override
    public TrustedVerifier addTrustedVerifier(TrustedVerifier trustedVerifier, String tenantDomain)
            throws VPException {

        validateVerifier(trustedVerifier);

        // Generate ID if not provided
        if (StringUtils.isBlank(trustedVerifier.getId())) {
            trustedVerifier.setId(UUID.randomUUID().toString());
        }

        // Set timestamps
        Instant now = Instant.now();
        trustedVerifier.setCreatedAt(now);
        trustedVerifier.setUpdatedAt(now);

        // Store verifier
        verifierStore
                .computeIfAbsent(tenantDomain, k -> new ConcurrentHashMap<>())
                .put(trustedVerifier.getId(), trustedVerifier);

        // Update indexes
        if (StringUtils.isNotBlank(trustedVerifier.getDid())) {
            didIndex
                    .computeIfAbsent(tenantDomain, k -> new ConcurrentHashMap<>())
                    .put(trustedVerifier.getDid(), trustedVerifier.getId());
        }

        if (StringUtils.isNotBlank(trustedVerifier.getClientId())) {
            clientIdIndex
                    .computeIfAbsent(tenantDomain, k -> new ConcurrentHashMap<>())
                    .put(trustedVerifier.getClientId(), trustedVerifier.getId());
        }

        return trustedVerifier;
    }

    @Override
    public TrustedVerifier updateTrustedVerifier(String verifierId, TrustedVerifier trustedVerifier,
            String tenantDomain) throws VPException {

        Map<String, TrustedVerifier> tenantVerifiers = verifierStore.get(tenantDomain);
        if (tenantVerifiers == null || !tenantVerifiers.containsKey(verifierId)) {
            throw new VPException("Trusted verifier not found: " + verifierId);
        }

        TrustedVerifier existing = tenantVerifiers.get(verifierId);

        // Update indexes if DID changed
        if (!StringUtils.equals(existing.getDid(), trustedVerifier.getDid())) {
            Map<String, String> tenantDidIndex = didIndex.get(tenantDomain);
            if (tenantDidIndex != null && existing.getDid() != null) {
                tenantDidIndex.remove(existing.getDid());
            }
            if (StringUtils.isNotBlank(trustedVerifier.getDid())) {
                didIndex
                        .computeIfAbsent(tenantDomain, k -> new ConcurrentHashMap<>())
                        .put(trustedVerifier.getDid(), verifierId);
            }
        }

        // Update indexes if client ID changed
        if (!StringUtils.equals(existing.getClientId(), trustedVerifier.getClientId())) {
            Map<String, String> tenantClientIdIndex = clientIdIndex.get(tenantDomain);
            if (tenantClientIdIndex != null && existing.getClientId() != null) {
                tenantClientIdIndex.remove(existing.getClientId());
            }
            if (StringUtils.isNotBlank(trustedVerifier.getClientId())) {
                clientIdIndex
                        .computeIfAbsent(tenantDomain, k -> new ConcurrentHashMap<>())
                        .put(trustedVerifier.getClientId(), verifierId);
            }
        }

        // Preserve ID and creation time
        trustedVerifier.setId(verifierId);
        trustedVerifier.setCreatedAt(existing.getCreatedAt());
        trustedVerifier.setUpdatedAt(Instant.now());

        // Update store
        tenantVerifiers.put(verifierId, trustedVerifier);

        return trustedVerifier;
    }

    @Override
    public void removeTrustedVerifier(String verifierId, String tenantDomain) throws VPException {
        Map<String, TrustedVerifier> tenantVerifiers = verifierStore.get(tenantDomain);
        if (tenantVerifiers == null) {
            return;
        }

        TrustedVerifier removed = tenantVerifiers.remove(verifierId);
        if (removed == null) {
            return;
        }

        // Clean up indexes
        if (StringUtils.isNotBlank(removed.getDid())) {
            Map<String, String> tenantDidIndex = didIndex.get(tenantDomain);
            if (tenantDidIndex != null) {
                tenantDidIndex.remove(removed.getDid());
            }
        }

        if (StringUtils.isNotBlank(removed.getClientId())) {
            Map<String, String> tenantClientIdIndex = clientIdIndex.get(tenantDomain);
            if (tenantClientIdIndex != null) {
                tenantClientIdIndex.remove(removed.getClientId());
            }
        }

    }

    @Override
    public boolean validateVerifierRequest(String verifierDid, List<String> requestedCredentialTypes,
            String tenantDomain) {

        if (StringUtils.isBlank(verifierDid)) {
            return false;
        }

        Optional<TrustedVerifier> verifierOpt = getTrustedVerifier(verifierDid, tenantDomain);
        if (!verifierOpt.isPresent()) {
            // If strict mode is disabled, allow the request
            return !isStrictVerificationEnabled(tenantDomain);
        }

        TrustedVerifier verifier = verifierOpt.get();

        // Check if verifier is active
        if (!verifier.isActive()) {
            return false;
        }

        // Check if all requested credential types are allowed
        if (requestedCredentialTypes != null && !requestedCredentialTypes.isEmpty()) {
            for (String credentialType : requestedCredentialTypes) {
                if (!verifier.allowsCredentialType(credentialType)) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public boolean isStrictVerificationEnabled(String tenantDomain) {
        TenantConfig config = tenantConfigs.get(tenantDomain);
        if (config != null) {
            return config.strictMode;
        }
        return defaultStrictMode;
    }

    @Override
    public RedirectUriValidationMode getRedirectUriValidationMode(String tenantDomain) {
        TenantConfig config = tenantConfigs.get(tenantDomain);
        if (config != null && config.redirectUriMode != null) {
            return config.redirectUriMode;
        }
        return defaultRedirectUriMode;
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean validateRedirectUri(String verifierDid, String redirectUri, String tenantDomain) {
        RedirectUriValidationMode mode = getRedirectUriValidationMode(tenantDomain);

        if (mode == RedirectUriValidationMode.DISABLED) {
            return true;
        }

        if (StringUtils.isBlank(redirectUri)) {
            return false;
        }

        Optional<TrustedVerifier> verifierOpt = getTrustedVerifier(verifierDid, tenantDomain);

        if (mode == RedirectUriValidationMode.STRICT) {
            // Must match pre-registered URI exactly
            if (!verifierOpt.isPresent()) {
                return !isStrictVerificationEnabled(tenantDomain);
            }
            return verifierOpt.get().allowsRedirectUri(redirectUri);
        }

        if (mode == RedirectUriValidationMode.RELAXED) {
            // Must match verifier's domain
            if (!verifierOpt.isPresent()) {
                return true; // Can't validate domain without verifier info
            }

            TrustedVerifier verifier = verifierOpt.get();
            String organizationUrl = verifier.getOrganizationUrl();

            if (StringUtils.isBlank(organizationUrl)) {
                return true; // No organization URL to validate against
            }

            try {
                URI redirectUriParsed = new URI(redirectUri);
                URI organizationUriParsed = new URI(organizationUrl);

                String redirectHost = redirectUriParsed.getHost();
                String organizationHost = organizationUriParsed.getHost();

                // Check if redirect host matches or is subdomain of organization
                return redirectHost.equals(organizationHost) ||
                        redirectHost.endsWith("." + organizationHost);
            } catch (Exception e) {
                return false;
            }
        }

        return true;
    }

    @Override
    public void clearCache() {
        // No separate cache in this implementation, but method is available for future
        // use
    }

    // Configuration methods

    /**
     * Set strict verification mode for a tenant.
     *
     * @param tenantDomain the tenant domain
     * @param strictMode   true to enable strict mode
     */
    public void setStrictVerificationEnabled(String tenantDomain, boolean strictMode) {
        tenantConfigs
                .computeIfAbsent(tenantDomain, k -> new TenantConfig()).strictMode = strictMode;
    }

    /**
     * Set redirect URI validation mode for a tenant.
     *
     * @param tenantDomain the tenant domain
     * @param mode         the validation mode
     */
    public void setRedirectUriValidationMode(String tenantDomain, RedirectUriValidationMode mode) {
        tenantConfigs
                .computeIfAbsent(tenantDomain, k -> new TenantConfig()).redirectUriMode = mode;
    }

    /**
     * Set default strict verification mode.
     *
     * @param strictMode true to enable strict mode by default
     */
    public void setDefaultStrictMode(boolean strictMode) {
        this.defaultStrictMode = strictMode;
    }

    /**
     * Set default redirect URI validation mode.
     *
     * @param mode the default validation mode
     */
    public void setDefaultRedirectUriMode(RedirectUriValidationMode mode) {
        this.defaultRedirectUriMode = mode;
    }

    // Helper methods

    /**
     * Validate a trusted verifier.
     */
    private void validateVerifier(TrustedVerifier verifier) throws VPException {
        if (verifier == null) {
            throw new VPException("Trusted verifier cannot be null");
        }

        if (StringUtils.isBlank(verifier.getDid()) && StringUtils.isBlank(verifier.getClientId())) {
            throw new VPException("Trusted verifier must have either a DID or client ID");
        }

        if (StringUtils.isBlank(verifier.getName())) {
            throw new VPException("Trusted verifier must have a name");
        }
    }

    /**
     * Tenant-specific configuration.
     */
    private static class TenantConfig {
        boolean strictMode = false;
        RedirectUriValidationMode redirectUriMode = null;
    }
}
