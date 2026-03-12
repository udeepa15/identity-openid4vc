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

package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of DIDDocumentService.
 * Generates and manages DID Documents for WSO2 Identity Server using did:key
 * method. The did:key method is self-contained - the public key is encoded
 * directly in the DID identifier.
 */
public class DIDDocumentServiceImpl implements DIDDocumentService {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    @Override
    public String getDIDDocument(String domain, int tenantId) throws DIDDocumentException {
        DIDDocument doc = getDIDDocumentObject(domain, tenantId);
        return convertToJson(doc);
    }

    @Override
    public DIDDocument getDIDDocumentObject(String domain, int tenantId) throws DIDDocumentException {
        try {
            // Since this method backs the .well-known/did.json endpoint, it implies did:web
            DIDProvider provider = DIDProviderFactory.getProvider("web");
            return provider.getDIDDocument(tenantId, domain);
        } catch (VPException e) {
            String errorMsg = "Failed to generate DID document for tenant: " + tenantId;
            throw new DIDDocumentException(errorMsg, e);
        }
    }

    @Override
    public String getDID(String domain) {
        try {
            // Default to did:web for domain-based lookup
            DIDProvider provider = DIDProviderFactory.getProvider("web");
            return provider.getDID(-1234, domain);
        } catch (VPException e) {
            return "did:web:" + domain.replace(":", "%3A");
        }
    }

    /**
     * Get DID for a specific tenant.
     * 
     * @param tenantId The tenant ID
     * @param tenantDomain The tenant domain
     * @return DID identifier (defaults to did:web)
     * @throws DIDDocumentException if generation fails
     */
    public String getDID(int tenantId, String tenantDomain) throws DIDDocumentException {
        try {
            // Default to did:web
            String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil
                    .getTenantAwareBaseUrl(tenantDomain);
            DIDProvider provider = DIDProviderFactory.getProvider("web");
            return provider.getDID(tenantId, baseUrl);
        } catch (VPException e) {
            throw new DIDDocumentException("Failed to generate DID for tenant: " + tenantId, e);
        }
    }



    /**
     * Convert DID Document to JSON string.
     * Uses a custom serialization to match W3C DID spec format.
     * 
     * @param doc DIDDocument object
     * @return JSON string
     */
    private String convertToJson(DIDDocument doc) {
        Map<String, Object> jsonMap = new HashMap<>();

        jsonMap.put("@context", doc.getContext());
        jsonMap.put("id", doc.getId());

        if (doc.getController() != null) {
            jsonMap.put("controller", doc.getController());
        }

        if (doc.getAlsoKnownAs() != null && !doc.getAlsoKnownAs().isEmpty()) {
            jsonMap.put("alsoKnownAs", doc.getAlsoKnownAs());
        }

        // Verification methods
        if (doc.getVerificationMethod() != null && !doc.getVerificationMethod().isEmpty()) {
            java.util.List<Map<String, Object>> vmList = new ArrayList<>();
            for (DIDDocument.VerificationMethod vm : doc.getVerificationMethod()) {
                Map<String, Object> vmMap = new HashMap<>();
                vmMap.put("id", vm.getId());
                vmMap.put("type", vm.getType());
                vmMap.put("controller", vm.getController());

                if (vm.getPublicKeyJwkMap() != null) {
                    vmMap.put("publicKeyJwk", vm.getPublicKeyJwkMap());
                } else if (vm.getPublicKeyMultibase() != null) {
                    vmMap.put("publicKeyMultibase", vm.getPublicKeyMultibase());
                } else if (vm.getPublicKeyBase58() != null) {
                    vmMap.put("publicKeyBase58", vm.getPublicKeyBase58());
                }

                vmList.add(vmMap);
            }
            jsonMap.put("verificationMethod", vmList);
        }

        // Verification relationships
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            jsonMap.put("authentication", doc.getAuthentication());
        }

        if (doc.getAssertionMethod() != null && !doc.getAssertionMethod().isEmpty()) {
            jsonMap.put("assertionMethod", doc.getAssertionMethod());
        }

        if (doc.getKeyAgreement() != null && !doc.getKeyAgreement().isEmpty()) {
            jsonMap.put("keyAgreement", doc.getKeyAgreement());
        }

        if (doc.getCapabilityInvocation() != null && !doc.getCapabilityInvocation().isEmpty()) {
            jsonMap.put("capabilityInvocation", doc.getCapabilityInvocation());
        }

        if (doc.getCapabilityDelegation() != null && !doc.getCapabilityDelegation().isEmpty()) {
            jsonMap.put("capabilityDelegation", doc.getCapabilityDelegation());
        }

        // Services
        if (doc.getService() != null && !doc.getService().isEmpty()) {
            jsonMap.put("service", doc.getService());
        }

        return GSON.toJson(jsonMap);
    }
}
