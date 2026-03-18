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

package org.wso2.carbon.identity.openid4vc.presentation.did.model;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for DIDDocument model.
 */
public class DIDDocumentTest {

    /**
     * Tests basic setters, getters and defensive copy behavior.
     */
    @Test
    public void testSettersGettersAndDefensiveCopies() {
        DIDDocument document = new DIDDocument();

        List<String> contexts = new ArrayList<>();
        contexts.add("https://www.w3.org/ns/did/v1");
        document.setContext(contexts);

        List<String> contextResult = document.getContext();
        contextResult.add("modified");
        Assert.assertEquals(document.getContext().size(), 1);

        DIDDocument.VerificationMethod vm = new DIDDocument.VerificationMethod();
        vm.setId("did:web:example.com#key-1");
        vm.setType("JsonWebKey2020");
        vm.setController("did:web:example.com");
        vm.setPublicKeyJwk("{}");
        vm.setPublicKeyBase58("abc");
        vm.setPublicKeyMultibase("z123");
        vm.setPublicKeyPem("pem");

        Map<String, Object> jwkMap = new HashMap<>();
        jwkMap.put("kty", "OKP");
        vm.setPublicKeyJwkMap(jwkMap);

        Map<String, Object> returnedJwkMap = vm.getPublicKeyJwkMap();
        returnedJwkMap.put("x", "changed");
        Assert.assertFalse(vm.getPublicKeyJwkMap().containsKey("x"));

        document.addVerificationMethod(vm);
        Assert.assertEquals(document.getVerificationMethod().size(), 1);
        Assert.assertTrue(vm.toString().contains("key-1"));
    }

    /**
     * Tests verification method lookup and assertion method resolution.
     */
    @Test
    public void testFindVerificationMethodAndFirstAssertionMethod() {
        DIDDocument document = new DIDDocument();

        DIDDocument.VerificationMethod vm1 = new DIDDocument.VerificationMethod();
        vm1.setId("did:web:example.com#key-1");
        document.addVerificationMethod(vm1);

        DIDDocument.VerificationMethod vm2 = new DIDDocument.VerificationMethod();
        vm2.setId("did:web:example.com#key-2");
        document.addVerificationMethod(vm2);

        List<String> assertion = new ArrayList<>();
        assertion.add("did:web:example.com#key-2");
        document.setAssertionMethod(assertion);

        Assert.assertEquals(document.findVerificationMethod("did:web:example.com#key-1"), vm1);
        Assert.assertEquals(document.findVerificationMethod("key-2"), vm2);
        Assert.assertEquals(document.getFirstAssertionMethod(), vm2);
        Assert.assertNull(document.findVerificationMethod(null));
    }

    /**
     * Tests service and other list fields behavior.
     */
    @Test
    public void testServiceAndListFields() {
        DIDDocument document = new DIDDocument();

        DIDDocument.Service service = new DIDDocument.Service();
        service.setId("did:web:example.com#service-1");
        service.setType("LinkedDomains");
        service.setServiceEndpoint("https://example.com");

        Map<String, Object> endpointMap = new HashMap<>();
        endpointMap.put("uri", "https://example.com");
        service.setServiceEndpointMap(endpointMap);

        List<DIDDocument.Service> services = new ArrayList<>();
        services.add(service);
        document.setService(services);

        List<String> auth = new ArrayList<>();
        auth.add("did:web:example.com#key-1");
        document.setAuthentication(auth);

        List<String> agreement = new ArrayList<>();
        agreement.add("did:web:example.com#key-agree");
        document.setKeyAgreement(agreement);

        document.setId("did:web:example.com");
        document.setController("did:web:example.com");
        document.setRawDocument("{}");

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("id", "did:web:example.com");
        document.setRawMap(rawMap);

        List<String> capabilityInvocation = new ArrayList<>();
        capabilityInvocation.add("did:web:example.com#invoke");
        document.setCapabilityInvocation(capabilityInvocation);

        List<String> capabilityDelegation = new ArrayList<>();
        capabilityDelegation.add("did:web:example.com#delegate");
        document.setCapabilityDelegation(capabilityDelegation);

        List<String> aliases = new ArrayList<>();
        aliases.add("did:web:alias.example.com");
        document.setAlsoKnownAs(aliases);

        Assert.assertEquals(document.getService().size(), 1);
        Assert.assertEquals(document.getAuthentication().size(), 1);
        Assert.assertEquals(document.getKeyAgreement().size(), 1);
        Assert.assertEquals(document.getCapabilityInvocation().size(), 1);
        Assert.assertEquals(document.getCapabilityDelegation().size(), 1);
        Assert.assertEquals(document.getAlsoKnownAs().size(), 1);
        Assert.assertEquals(document.getRawDocument(), "{}");
        Assert.assertTrue(document.getRawMap().containsKey("id"));
        Assert.assertEquals(service.getServiceEndpoint(), "https://example.com");
        Assert.assertTrue(service.getServiceEndpointMap().containsKey("uri"));
        Assert.assertTrue(document.toString().contains("did:web:example.com"));
    }
}
