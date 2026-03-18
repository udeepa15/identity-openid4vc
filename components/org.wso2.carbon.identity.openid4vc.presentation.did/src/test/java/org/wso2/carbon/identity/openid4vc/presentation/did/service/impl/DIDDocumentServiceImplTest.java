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
}
