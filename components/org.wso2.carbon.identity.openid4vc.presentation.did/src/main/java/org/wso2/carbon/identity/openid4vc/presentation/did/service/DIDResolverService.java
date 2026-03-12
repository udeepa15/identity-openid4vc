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

package org.wso2.carbon.identity.openid4vc.presentation.did.service;

import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;

import java.security.PublicKey;

/**
 * Service interface for DID (Decentralized Identifier) resolution.
 * Resolves DIDs to their corresponding DID Documents and extracts verification keys.
 * 
 * Supported DID methods:
 * - did:web - Web-based DIDs resolved via HTTPS
 * - did:jwk - DIDs containing embedded JWK
 * - did:key - DIDs containing embedded public key
 */
public interface DIDResolverService {

    /**
     * Resolve a DID to its DID Document.
     *
     * @param did The DID to resolve (e.g., "did:web:example.com")
     * @return The resolved DID Document
     * @throws DIDResolutionException If resolution fails
     */
    DIDDocument resolve(String did) throws DIDResolutionException;

    /**
     * Resolve a DID with caching support.
     *
     * @param did        The DID to resolve
     * @param useCache   Whether to use cached document if available
     * @return The resolved DID Document
     * @throws DIDResolutionException If resolution fails
     */
    DIDDocument resolve(String did, boolean useCache) throws DIDResolutionException;

    /**
     * Get a public key from a DID for signature verification.
     *
     * @param did   The DID
     * @param keyId Optional key ID (verification method ID). If null, returns the first
     *              assertion method or authentication key.
     * @return The public key
     * @throws DIDResolutionException If resolution fails or key not found
     */
    PublicKey getPublicKey(String did, String keyId) throws DIDResolutionException;

    /**
     * Get the public key for a specific verification method reference.
     *
     * @param verificationMethodRef The full verification method reference 
     *                               (e.g., "did:web:example.com#key-1")
     * @return The public key
     * @throws DIDResolutionException If resolution fails or key not found
     */
    PublicKey getPublicKeyFromReference(String verificationMethodRef) throws DIDResolutionException;

    /**
     * Check if a DID method is supported.
     *
     * @param did The DID to check
     * @return true if the DID method is supported
     */
    boolean isSupported(String did);

    /**
     * Get the DID method from a DID string.
     *
     * @param did The DID
     * @return The method name (e.g., "web", "jwk", "key")
     */
    String getMethod(String did);

    /**
     * Get the list of supported DID methods.
     *
     * @return Array of supported method names
     */
    String[] getSupportedMethods();

    /**
     * Clear the resolution cache for a specific DID.
     *
     * @param did The DID to remove from cache
     */
    void clearCache(String did);

    /**
     * Clear all cached DID documents.
     */
    void clearAllCache();

    /**
     * Validate a DID string format.
     *
     * @param did The DID to validate
     * @return true if valid DID format
     */
    boolean isValidDID(String did);

    /**
     * Extract the identifier-specific part from a DID.
     *
     * @param did The full DID
     * @return The identifier-specific part
     */
    String getIdentifier(String did);
}
