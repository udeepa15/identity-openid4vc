/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.did.provider.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.BCEd25519Signer;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Base58;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * DID Provider implementation for 'did:web' method.
 * Supports RSA (default via KeyStore), EdDSA and ES256 (via DIDKeyManager).
 */
public class DIDWebProvider implements DIDProvider {

    @Override
    public String getName() {
        return "web";
    }

    @Override
    public String getDID(int tenantId, String baseUrl) throws VPException {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new VPException("Base URL is required for did:web generation");
        }
        String domain = baseUrl.replace("https://", "").replace("http://", "");
        if (domain.endsWith("/")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        // Encode port colon if present
        if (domain.contains(":")) {
            domain = domain.replace(":", "%3A");
        }
        // Encode path slashes to colons for did:web specification
        if (domain.contains("/")) {
            domain = domain.replace("/", ":");
        }
        return "did:web:" + domain;
    }

    @Override
    public String getSigningKeyId(int tenantId, String baseUrl) throws VPException {
        return getDID(tenantId, baseUrl) + "#ed25519";
    }

    @Override
    public JWSAlgorithm getSigningAlgorithm() {
        return JWSAlgorithm.EdDSA;
    }

    @Override
    public JWSSigner getSigner(int tenantId) throws VPException {
        try {
            // Use KeyStore for EdDSA keys
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            String edKeyAlias = getEdDSAKeyAlias(tenantId);
            PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey(edKeyAlias);
            
            // Convert PrivateKey to OctetKeyPair for BCEd25519Signer
            OctetKeyPair keyPair = convertToOctetKeyPair(privateKey, keyStoreManager, edKeyAlias);
            return BCEd25519Signer.create(keyPair);
        } catch (Exception e) {
            throw new VPException("Error creating signer for did:web", e);
        }
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("DE_MIGHT_IGNORE")
    public DIDDocument getDIDDocument(int tenantId, String baseUrl) throws VPException {
        try {
            String did = getDID(tenantId, baseUrl);

            DIDDocument didDocument = new DIDDocument();
            didDocument.setId(did);

            // Add Standard Contexts
            List<String> contexts = new ArrayList<>();
            contexts.add("https://www.w3.org/ns/did/v1");
            contexts.add("https://w3id.org/security/suites/ed25519-2020/v1");
            didDocument.setContext(contexts);

            List<DIDDocument.VerificationMethod> verificationMethods = new ArrayList<>();
            List<String> relationships = new ArrayList<>();

            try {
                String keyId = getSigningKeyId(tenantId, baseUrl);
                
                // Use KeyStore for EdDSA keys
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                String edKeyAlias = getEdDSAKeyAlias(tenantId);
                java.security.PublicKey publicKey = keyStoreManager.getDefaultPublicKey(edKeyAlias);

                DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
                vm.setId(keyId);
                vm.setController(did);
                vm.setType("Ed25519VerificationKey2020");

                // Convert PublicKey to multibase format
                String multibase = convertPublicKeyToMultibase(publicKey);
                vm.setPublicKeyMultibase(multibase);

                verificationMethods.add(vm);
                relationships.add(keyId);

            } catch (Exception e) {
                org.apache.commons.logging.LogFactory.getLog(DIDWebProvider.class)
                        .error("Error while generating verification method for did:web", e);
            }
            didDocument.setVerificationMethod(verificationMethods);
            didDocument.setAuthentication(relationships);
            didDocument.setAssertionMethod(relationships);

            return didDocument;

        } catch (Exception e) {
            throw new VPException("Error generating DID Document for did:web", e);
        }
    }

    /**
     * Convert PublicKey to multibase format for DID document.
     * 
     * @param publicKey The public key from KeyStore
     * @return Multibase encoded string
     * @throws Exception if conversion fails
     */
    private String convertPublicKeyToMultibase(java.security.PublicKey publicKey) throws Exception {
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        // Extract raw Ed25519 public key (32 bytes at the end)
        byte[] rawPublicKey = java.util.Arrays.copyOfRange(publicKeyBytes, 
                publicKeyBytes.length - 32, publicKeyBytes.length);
        
        // Prepend multicodec prefix for Ed25519-pub (0xed01)
        byte[] multicodecKey = new byte[34];
        multicodecKey[0] = (byte) 0xed;
        multicodecKey[1] = (byte) 0x01;
        System.arraycopy(rawPublicKey, 0, multicodecKey, 2, 32);
        
        return "z" + Base58.encode(multicodecKey);
    }

    /**
     * Get the EdDSA key alias for the given tenant.
     */
    private String getEdDSAKeyAlias(int tenantId) throws VPException {
        try {
            String tenantDomain = org.wso2.carbon.utils.multitenancy
                    .MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            if (tenantId != org.wso2.carbon.utils.multitenancy
                    .MultitenantConstants.SUPER_TENANT_ID) {
                tenantDomain = org.wso2.carbon.context.PrivilegedCarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain();
            }

            java.security.KeyStore keystore = org.wso2.carbon.identity.core
                    .IdentityKeyStoreResolver.getInstance()
                    .getKeyStore(tenantDomain, org.wso2.carbon.identity.core
                            .util.IdentityKeyStoreResolverConstants
                            .InboundProtocol.OAUTH);

            if (keystore != null) {
                java.util.Enumeration<String> enumeration = keystore.aliases();
                while (enumeration.hasMoreElements()) {
                    String alias = enumeration.nextElement();
                    if (keystore.isKeyEntry(alias)) {
                        java.security.cert.Certificate cert = keystore
                                .getCertificate(alias);
                        if (cert != null && cert.getPublicKey() instanceof
                                java.security.interfaces.EdECPublicKey) {
                            return alias;
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new VPException(
                    "Failed to retrieve EdDSA key alias for tenant: " +
                            tenantId, e);
        }
        throw new VPException(
                "No EdDSA key found in the keystore for tenant: " + tenantId);
    }

    /**
     * Convert PrivateKey to OctetKeyPair for EdDSA signing.
     */
    private OctetKeyPair convertToOctetKeyPair(PrivateKey privateKey, 
                                                KeyStoreManager keyStoreManager, 
                                                String alias) throws Exception {
        java.security.PublicKey publicKey = keyStoreManager.getDefaultPublicKey(alias);
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] publicKeyBytes = publicKey.getEncoded();
        
        byte[] rawPrivateKey = java.util.Arrays.copyOfRange(privateKeyBytes, 
                privateKeyBytes.length - 32, privateKeyBytes.length);
        byte[] rawPublicKey = java.util.Arrays.copyOfRange(publicKeyBytes, 
                publicKeyBytes.length - 32, publicKeyBytes.length);
        
        com.nimbusds.jose.util.Base64URL x = com.nimbusds.jose.util.Base64URL.encode(rawPublicKey);
        com.nimbusds.jose.util.Base64URL d = com.nimbusds.jose.util.Base64URL.encode(rawPrivateKey);
        
        return new OctetKeyPair.Builder(com.nimbusds.jose.jwk.Curve.Ed25519, x).d(d).build();
    }
}
