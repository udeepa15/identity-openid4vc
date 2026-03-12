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

import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;

/**
 * Service interface for managing DID Documents for WSO2 Identity Server.
 * Handles generation, retrieval, and key management for the server's DID.
 */
public interface DIDDocumentService {

    /**
     * Get the DID Document for the current tenant/domain.
     * Generates a new DID document with keys if one doesn't exist.
     * 
     * @param domain The domain name (e.g., "localhost:9443" or "example.com")
     * @param tenantId The tenant ID
     * @return DID Document as JSON string
     * @throws DIDDocumentException if document generation fails
     */
    String getDIDDocument(String domain, int tenantId) throws DIDDocumentException;

    /**
     * Get the DID Document model for the current tenant/domain.
     * 
     * @param domain The domain name
     * @param tenantId The tenant ID
     * @return DIDDocument object
     * @throws DIDDocumentException if document generation fails
     */
    DIDDocument getDIDDocumentObject(String domain, int tenantId) throws DIDDocumentException;

    /**
     * Get the DID identifier for the given domain.
     * Format: did:web:domain
     * 
     * @param domain The domain name
     * @return DID string (e.g., "did:web:example.com")
     */
    String getDID(String domain);

}
