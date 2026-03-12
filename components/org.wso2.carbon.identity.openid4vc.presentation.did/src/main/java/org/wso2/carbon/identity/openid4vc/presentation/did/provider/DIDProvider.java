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

package org.wso2.carbon.identity.openid4vc.presentation.did.provider;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;

/**
 * Interface for DID Providers supported by the system.
 * Implementations handle specific DID methods (did:web, did:key, etc.)
 */
public interface DIDProvider {

    /**
     * Get the supported DID method name (e.g., "key", "web", "jwk").
     * 
     * @return DID method name
     */
    String getName();

    /**
     * Get the full DID for the given tenant/context.
     * 
     * @param tenantId Tenant ID
     * @param baseUrl  Base URL (needed for did:web)
     * @return DID string
     * @throws VPException if generation fails
     */
    String getDID(int tenantId, String baseUrl) throws VPException;



    /**
     * Get the Key ID to be used in the JWT header.
     * 
     * @param tenantId Tenant ID
     * @param baseUrl  Base URL
     * @return Key ID (e.g., did:key:abc#key-1)
     * @throws VPException if generation fails
     */
    String getSigningKeyId(int tenantId, String baseUrl) throws VPException;



    /**
     * Get the signing algorithm used by this provider.
     * 
     * @return JWSAlgorithm
     */
    JWSAlgorithm getSigningAlgorithm();



    /**
     * Get the JWS Signer for the tenant's key.
     * 
     * @param tenantId Tenant ID
     * @return JWSSigner
     * @throws VPException if signer creation fails
     */
    JWSSigner getSigner(int tenantId) throws VPException;



    /**
     * Generate the DID Document object.
     * 
     * @param tenantId Tenant ID
     * @param baseUrl  Base URL
     * @return DIDDocument model
     * @throws VPException if generation fails
     */
    DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException;


}
