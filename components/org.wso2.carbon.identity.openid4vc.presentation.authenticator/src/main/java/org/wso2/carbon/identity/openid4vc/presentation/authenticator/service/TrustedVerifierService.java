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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.TrustedVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.util.List;
import java.util.Optional;

/**
 * Service interface for managing trusted verifiers.
 * Trusted verifiers are external entities that are authorized to request credential presentations.
 */
public interface TrustedVerifierService {

    /**
     * Check if a verifier is trusted based on its DID.
     *
     * @param verifierDid the DID of the verifier
     * @param tenantDomain the tenant domain
     * @return true if the verifier is trusted
     */
    boolean isVerifierTrusted(String verifierDid, String tenantDomain);

    /**
     * Check if a verifier is trusted based on its client ID.
     *
     * @param clientId the OAuth client ID of the verifier
     * @param tenantDomain the tenant domain
     * @return true if the verifier is trusted
     */
    boolean isVerifierTrustedByClientId(String clientId, String tenantDomain);

    /**
     * Get a trusted verifier by DID.
     *
     * @param verifierDid the DID of the verifier
     * @param tenantDomain the tenant domain
     * @return the trusted verifier if found
     */
    Optional<TrustedVerifier> getTrustedVerifier(String verifierDid, String tenantDomain);

    /**
     * Get a trusted verifier by client ID.
     *
     * @param clientId the OAuth client ID
     * @param tenantDomain the tenant domain
     * @return the trusted verifier if found
     */
    Optional<TrustedVerifier> getTrustedVerifierByClientId(String clientId, String tenantDomain);

    /**
     * Get all trusted verifiers for a tenant.
     *
     * @param tenantDomain the tenant domain
     * @return list of trusted verifiers
     * @throws VPException if an error occurs
     */
    List<TrustedVerifier> getTrustedVerifiers(String tenantDomain) throws VPException;

    /**
     * Add a new trusted verifier.
     *
     * @param trustedVerifier the verifier to add
     * @param tenantDomain the tenant domain
     * @return the added verifier with generated ID
     * @throws VPException if an error occurs
     */
    TrustedVerifier addTrustedVerifier(TrustedVerifier trustedVerifier, String tenantDomain) 
            throws VPException;

    /**
     * Update an existing trusted verifier.
     *
     * @param verifierId the verifier ID
     * @param trustedVerifier the updated verifier data
     * @param tenantDomain the tenant domain
     * @return the updated verifier
     * @throws VPException if an error occurs
     */
    TrustedVerifier updateTrustedVerifier(String verifierId, TrustedVerifier trustedVerifier, 
            String tenantDomain) throws VPException;

    /**
     * Remove a trusted verifier.
     *
     * @param verifierId the verifier ID
     * @param tenantDomain the tenant domain
     * @throws VPException if an error occurs
     */
    void removeTrustedVerifier(String verifierId, String tenantDomain) throws VPException;

    /**
     * Validate a verifier's request based on its permissions.
     * Checks if the verifier is allowed to request the specified credential types.
     *
     * @param verifierDid the DID of the verifier
     * @param requestedCredentialTypes the credential types being requested
     * @param tenantDomain the tenant domain
     * @return true if the request is valid
     */
    boolean validateVerifierRequest(String verifierDid, List<String> requestedCredentialTypes, 
            String tenantDomain);

    /**
     * Check if strict verification mode is enabled.
     * When enabled, only registered trusted verifiers can make requests.
     * When disabled, any verifier with valid DID can make requests.
     *
     * @param tenantDomain the tenant domain
     * @return true if strict verification is enabled
     */
    boolean isStrictVerificationEnabled(String tenantDomain);

    /**
     * Get the redirect URI validation mode.
     *
     * @param tenantDomain the tenant domain
     * @return the validation mode (STRICT, RELAXED, DISABLED)
     */
    RedirectUriValidationMode getRedirectUriValidationMode(String tenantDomain);

    /**
     * Validate a redirect URI for a verifier.
     *
     * @param verifierDid the DID of the verifier
     * @param redirectUri the redirect URI to validate
     * @param tenantDomain the tenant domain
     * @return true if the redirect URI is valid for this verifier
     */
    boolean validateRedirectUri(String verifierDid, String redirectUri, String tenantDomain);

    /**
     * Clear cached verifier data.
     */
    void clearCache();

    /**
     * Enum for redirect URI validation modes.
     */
    enum RedirectUriValidationMode {
        /**
         * Only pre-registered redirect URIs are allowed.
         */
        STRICT,
        
        /**
         * Redirect URIs must match the verifier's domain.
         */
        RELAXED,
        
        /**
         * No redirect URI validation (not recommended for production).
         */
        DISABLED
    }
}
