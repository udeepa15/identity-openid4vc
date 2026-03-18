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

package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for DIDDocumentServiceImpl.
 */
public class DIDDocumentServiceImplTest {

    /**
     * Tests successful DID document object retrieval.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDDocumentObject() throws Exception {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        DIDDocument doc = new DIDDocument();
        doc.setId("did:web:example.com");
        doc.setContext(Arrays.asList("https://www.w3.org/ns/did/v1"));
        when(provider.getDIDDocument(-1234, "https://example.com")).thenReturn(doc);

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class)) {
            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);

            DIDDocument result = service.getDIDDocumentObject("https://example.com", -1234);
            Assert.assertNotNull(result);
            Assert.assertEquals(result.getId(), "did:web:example.com");
        }
    }

    /**
     * Tests DID document JSON conversion path.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDDocumentJson() throws Exception {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        DIDDocument doc = new DIDDocument();
        doc.setId("did:web:example.com");
        doc.setContext(Arrays.asList("https://www.w3.org/ns/did/v1"));
        when(provider.getDIDDocument(-1234, "https://example.com")).thenReturn(doc);

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class)) {
            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);

            String json = service.getDIDDocument("https://example.com", -1234);
            Assert.assertTrue(json.contains("\"id\": \"did:web:example.com\""));
            Assert.assertTrue(json.contains("\"@context\""));
        }
    }

    /**
     * Tests DIDDocumentException wrapping behavior.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDDocumentException.class)
    public void testGetDIDDocumentObjectFailure() throws Exception {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        when(provider.getDIDDocument(-1234, "https://example.com")).thenThrow(new VPException("failed"));

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class)) {
            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);

            service.getDIDDocumentObject("https://example.com", -1234);
        }
    }

    /**
     * Tests getDID fallback and success paths.
     */
    @Test
    public void testGetDIDPaths() {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class)) {
            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);

            try {
                when(provider.getDID(-1234, "example.com")).thenReturn("did:web:example.com");
            } catch (VPException e) {
                Assert.fail("Unexpected exception during setup", e);
            }
            Assert.assertEquals(service.getDID("example.com"), "did:web:example.com");

            try {
                when(provider.getDID(-1234, "example.com:9443")).thenThrow(new VPException("failed"));
            } catch (VPException e) {
                Assert.fail("Unexpected exception during setup", e);
            }
            Assert.assertEquals(service.getDID("example.com:9443"), "did:web:example.com%3A9443");
        }
    }

    /**
     * Tests tenant-specific DID retrieval.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDForTenant() throws Exception {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class);
             MockedStatic<OpenID4VPUtil> utilMockedStatic = mockStatic(OpenID4VPUtil.class)) {

            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);
            utilMockedStatic.when(() -> OpenID4VPUtil.getTenantAwareBaseUrl("foo.com"))
                    .thenReturn("https://foo.com");
            when(provider.getDID(1, "https://foo.com")).thenReturn("did:web:foo.com");

            String did = service.getDID(1, "foo.com");
            Assert.assertEquals(did, "did:web:foo.com");
        }
    }

    /**
     * Tests JSON conversion with all optional DID document sections.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetDIDDocumentJsonWithAllSections() throws Exception {
        DIDDocumentServiceImpl service = new DIDDocumentServiceImpl();
        DIDProvider provider = mock(DIDProvider.class);

        DIDDocument document = new DIDDocument();
        document.setId("did:web:all.example.com");
        document.setContext(Arrays.asList("https://www.w3.org/ns/did/v1"));
        document.setController("did:web:all.example.com");
        document.setAlsoKnownAs(Arrays.asList("did:web:alias.example.com"));

        DIDDocument.VerificationMethod verificationMethod = new DIDDocument.VerificationMethod();
        verificationMethod.setId("did:web:all.example.com#key-1");
        verificationMethod.setType("JsonWebKey2020");
        verificationMethod.setController("did:web:all.example.com");
        java.util.Map<String, Object> jwk = new java.util.HashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", "AQAB");
        verificationMethod.setPublicKeyJwkMap(jwk);
        document.setVerificationMethod(Arrays.asList(verificationMethod));

        document.setAuthentication(Arrays.asList("did:web:all.example.com#key-1"));
        document.setAssertionMethod(Arrays.asList("did:web:all.example.com#key-1"));
        document.setKeyAgreement(Arrays.asList("did:web:all.example.com#key-1"));
        document.setCapabilityInvocation(Arrays.asList("did:web:all.example.com#key-1"));
        document.setCapabilityDelegation(Arrays.asList("did:web:all.example.com#key-1"));

        DIDDocument.Service serviceEntry = new DIDDocument.Service();
        serviceEntry.setId("did:web:all.example.com#svc");
        serviceEntry.setType("LinkedDomains");
        serviceEntry.setServiceEndpoint("https://all.example.com");
        document.setService(Arrays.asList(serviceEntry));

        when(provider.getDIDDocument(-1234, "https://all.example.com")).thenReturn(document);

        try (MockedStatic<DIDProviderFactory> factoryMockedStatic = mockStatic(DIDProviderFactory.class)) {
            factoryMockedStatic.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(provider);

            String json = service.getDIDDocument("https://all.example.com", -1234);
            Assert.assertTrue(json.contains("\"alsoKnownAs\""));
            Assert.assertTrue(json.contains("\"verificationMethod\""));
            Assert.assertTrue(json.contains("\"authentication\""));
            Assert.assertTrue(json.contains("\"assertionMethod\""));
            Assert.assertTrue(json.contains("\"keyAgreement\""));
            Assert.assertTrue(json.contains("\"capabilityInvocation\""));
            Assert.assertTrue(json.contains("\"capabilityDelegation\""));
            Assert.assertTrue(json.contains("\"service\""));
        }
    }
}
