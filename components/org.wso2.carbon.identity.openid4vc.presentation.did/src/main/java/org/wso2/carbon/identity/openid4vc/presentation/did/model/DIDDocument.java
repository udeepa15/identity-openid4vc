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

package org.wso2.carbon.identity.openid4vc.presentation.did.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model class representing a DID Document as per W3C DID Core specification.
 * Contains verification methods and public keys needed for signature
 * verification.
 */
public class DIDDocument {

    // Core fields
    private String id;
    private List<String> context;
    private String controller;
    private List<String> alsoKnownAs;

    // Verification methods
    private List<VerificationMethod> verificationMethod;
    private List<String> authentication;
    private List<String> assertionMethod;
    private List<String> keyAgreement;
    private List<String> capabilityInvocation;
    private List<String> capabilityDelegation;

    // Services
    private List<Service> service;

    // Raw document
    private String rawDocument;
    private Map<String, Object> rawMap;

    /**
     * Default constructor.
     */
    public DIDDocument() {
        this.context = new ArrayList<>();
        this.verificationMethod = new ArrayList<>();
        this.authentication = new ArrayList<>();
        this.assertionMethod = new ArrayList<>();
    }

    /**
     * Inner class representing a verification method (public key).
     */
    public static class VerificationMethod {
        private String id;
        private String type;
        private String controller;
        private String publicKeyJwk; // JSON string of JWK
        private Map<String, Object> publicKeyJwkMap;
        private String publicKeyMultibase;
        private String publicKeyBase58;
        private String publicKeyBase64;
        private String publicKeyHex;
        private String publicKeyPem;

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

        public String getController() {
            return controller;
        }

        public void setController(String controller) {
            this.controller = controller;
        }

        public String getPublicKeyJwk() {
            return publicKeyJwk;
        }

        public void setPublicKeyJwk(String publicKeyJwk) {
            this.publicKeyJwk = publicKeyJwk;
        }

        public Map<String, Object> getPublicKeyJwkMap() {
            return publicKeyJwkMap != null ? new HashMap<>(publicKeyJwkMap) : null;
        }

        public void setPublicKeyJwkMap(Map<String, Object> publicKeyJwkMap) {
            this.publicKeyJwkMap = publicKeyJwkMap != null ? new HashMap<>(publicKeyJwkMap) : null;
        }

        public String getPublicKeyMultibase() {
            return publicKeyMultibase;
        }

        public void setPublicKeyMultibase(String publicKeyMultibase) {
            this.publicKeyMultibase = publicKeyMultibase;
        }

        public String getPublicKeyBase58() {
            return publicKeyBase58;
        }

        public void setPublicKeyBase58(String publicKeyBase58) {
            this.publicKeyBase58 = publicKeyBase58;
        }

        public String getPublicKeyBase64() {
            return publicKeyBase64;
        }

        public void setPublicKeyBase64(String publicKeyBase64) {
            this.publicKeyBase64 = publicKeyBase64;
        }

        public String getPublicKeyHex() {
            return publicKeyHex;
        }

        public void setPublicKeyHex(String publicKeyHex) {
            this.publicKeyHex = publicKeyHex;
        }

        public String getPublicKeyPem() {
            return publicKeyPem;
        }

        public void setPublicKeyPem(String publicKeyPem) {
            this.publicKeyPem = publicKeyPem;
        }

        /**
         * Check if this is a JsonWebKey2020 type.
         */
        public boolean isJsonWebKey() {
            return "JsonWebKey2020".equals(type) || "JsonWebKey".equals(type);
        }

        /**
         * Check if this is an Ed25519VerificationKey2020 type.
         */
        public boolean isEd25519Key() {
            return type != null && type.contains("Ed25519");
        }

        /**
         * Check if this is an EcdsaSecp256k1 key.
         */
        public boolean isEcdsaSecp256k1Key() {
            return type != null && type.contains("EcdsaSecp256k1");
        }

        /**
         * Get the key ID without the DID prefix.
         */
        public String getKeyIdFragment() {
            if (id != null && id.contains("#")) {
                return id.substring(id.indexOf("#") + 1);
            }
            return id;
        }

        /**
         * Check if this method has a public key in any format.
         */
        public boolean hasPublicKey() {
            return publicKeyJwk != null || publicKeyJwkMap != null
                    || publicKeyMultibase != null || publicKeyBase58 != null
                    || publicKeyBase64 != null || publicKeyHex != null
                    || publicKeyPem != null;
        }

        @Override
        public String toString() {
            return "VerificationMethod{" +
                    "id='" + id + '\'' +
                    ", type='" + type + '\'' +
                    '}';
        }
    }

    /**
     * Inner class representing a DID service endpoint.
     */
    public static class Service {
        private String id;
        private String type;
        private String serviceEndpoint;
        private Map<String, Object> serviceEndpointMap;

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

        public String getServiceEndpoint() {
            return serviceEndpoint;
        }

        public void setServiceEndpoint(String serviceEndpoint) {
            this.serviceEndpoint = serviceEndpoint;
        }

        public Map<String, Object> getServiceEndpointMap() {
            return serviceEndpointMap != null ? new HashMap<>(serviceEndpointMap) : null;
        }

        public void setServiceEndpointMap(Map<String, Object> serviceEndpointMap) {
            this.serviceEndpointMap = serviceEndpointMap != null ? new HashMap<>(serviceEndpointMap) : null;
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

    public String getController() {
        return controller;
    }

    public void setController(String controller) {
        this.controller = controller;
    }

    public List<String> getAlsoKnownAs() {
        return alsoKnownAs != null ? new ArrayList<>(alsoKnownAs) : null;
    }

    public void setAlsoKnownAs(List<String> alsoKnownAs) {
        this.alsoKnownAs = alsoKnownAs != null ? new ArrayList<>(alsoKnownAs) : null;
    }

    public List<VerificationMethod> getVerificationMethod() {
        return verificationMethod != null ? new ArrayList<>(verificationMethod) : null;
    }

    public void setVerificationMethod(List<VerificationMethod> verificationMethod) {
        this.verificationMethod = verificationMethod != null ? new ArrayList<>(verificationMethod) : null;
    }

    public void addVerificationMethod(VerificationMethod method) {
        if (this.verificationMethod == null) {
            this.verificationMethod = new ArrayList<>();
        }
        this.verificationMethod.add(method);
    }

    public List<String> getAuthentication() {
        return authentication != null ? new ArrayList<>(authentication) : null;
    }

    public void setAuthentication(List<String> authentication) {
        this.authentication = authentication != null ? new ArrayList<>(authentication) : null;
    }

    public List<String> getAssertionMethod() {
        return assertionMethod != null ? new ArrayList<>(assertionMethod) : null;
    }

    public void setAssertionMethod(List<String> assertionMethod) {
        this.assertionMethod = assertionMethod != null ? new ArrayList<>(assertionMethod) : null;
    }

    public List<String> getKeyAgreement() {
        return keyAgreement != null ? new ArrayList<>(keyAgreement) : null;
    }

    public void setKeyAgreement(List<String> keyAgreement) {
        this.keyAgreement = keyAgreement != null ? new ArrayList<>(keyAgreement) : null;
    }

    public List<String> getCapabilityInvocation() {
        return capabilityInvocation != null ? new ArrayList<>(capabilityInvocation) : null;
    }

    public void setCapabilityInvocation(List<String> capabilityInvocation) {
        this.capabilityInvocation = capabilityInvocation != null ? new ArrayList<>(capabilityInvocation) : null;
    }

    public List<String> getCapabilityDelegation() {
        return capabilityDelegation != null ? new ArrayList<>(capabilityDelegation) : null;
    }

    public void setCapabilityDelegation(List<String> capabilityDelegation) {
        this.capabilityDelegation = capabilityDelegation != null ? new ArrayList<>(capabilityDelegation) : null;
    }

    public List<Service> getService() {
        return service != null ? new ArrayList<>(service) : null;
    }

    public void setService(List<Service> service) {
        this.service = service != null ? new ArrayList<>(service) : null;
    }

    public String getRawDocument() {
        return rawDocument;
    }

    public void setRawDocument(String rawDocument) {
        this.rawDocument = rawDocument;
    }

    public Map<String, Object> getRawMap() {
        return rawMap != null ? new HashMap<>(rawMap) : null;
    }

    public void setRawMap(Map<String, Object> rawMap) {
        this.rawMap = rawMap != null ? new HashMap<>(rawMap) : null;
    }

    /**
     * Find a verification method by its ID.
     *
     * @param methodId The verification method ID (can be full ID or fragment)
     * @return The verification method or null if not found
     */
    public VerificationMethod findVerificationMethod(String methodId) {
        if (verificationMethod == null || methodId == null) {
            return null;
        }

        // Try exact match first
        for (VerificationMethod method : verificationMethod) {
            if (methodId.equals(method.getId())) {
                return method;
            }
        }

        // Try fragment match
        String fragment = methodId.contains("#") ? methodId.substring(methodId.indexOf("#") + 1) : methodId;
        for (VerificationMethod method : verificationMethod) {
            if (method.getId() != null && method.getId().endsWith("#" + fragment)) {
                return method;
            }
        }

        return null;
    }

    /**
     * Get the first verification method for assertion (signing).
     *
     * @return The first assertion method or null
     */
    public VerificationMethod getFirstAssertionMethod() {
        if (assertionMethod != null && !assertionMethod.isEmpty()) {
            String methodRef = assertionMethod.get(0);
            return findVerificationMethod(methodRef);
        }
        // Fall back to first verification method
        if (verificationMethod != null && !verificationMethod.isEmpty()) {
            return verificationMethod.get(0);
        }
        return null;
    }

    /**
     * Get the first authentication method.
     *
     * @return The first authentication method or null
     */
    public VerificationMethod getFirstAuthenticationMethod() {
        if (authentication != null && !authentication.isEmpty()) {
            String methodRef = authentication.get(0);
            return findVerificationMethod(methodRef);
        }
        return getFirstAssertionMethod();
    }

    /**
     * Get all verification methods as a map keyed by ID.
     *
     * @return Map of method ID to VerificationMethod
     */
    public Map<String, VerificationMethod> getVerificationMethodMap() {
        Map<String, VerificationMethod> map = new HashMap<>();
        if (verificationMethod != null) {
            for (VerificationMethod method : verificationMethod) {
                if (method.getId() != null) {
                    map.put(method.getId(), method);
                    // Also add by fragment
                    String fragment = method.getKeyIdFragment();
                    if (fragment != null && !fragment.equals(method.getId())) {
                        map.put(fragment, method);
                    }
                }
            }
        }
        return map;
    }

    /**
     * Check if this DID document has any verification methods.
     *
     * @return true if there are verification methods
     */
    public boolean hasVerificationMethods() {
        return verificationMethod != null && !verificationMethod.isEmpty();
    }

    /**
     * Find a service by type.
     *
     * @param serviceType The service type to find
     * @return The service or null if not found
     */
    public Service findServiceByType(String serviceType) {
        if (service != null && serviceType != null) {
            for (Service svc : service) {
                if (serviceType.equals(svc.getType())) {
                    return svc;
                }
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "DIDDocument{" +
                "id='" + id + '\'' +
                ", verificationMethodCount=" + (verificationMethod != null ? verificationMethod.size() : 0) +
                '}';
    }
}
