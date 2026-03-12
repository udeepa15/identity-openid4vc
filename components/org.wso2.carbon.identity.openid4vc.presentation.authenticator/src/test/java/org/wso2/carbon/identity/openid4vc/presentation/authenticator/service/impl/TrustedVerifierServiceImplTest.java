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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.TrustedVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.TrustedVerifierService;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class TrustedVerifierServiceImplTest {

    private TrustedVerifierServiceImpl trustedVerifierService;
    private static final String TENANT = "carbon.super";

    @BeforeMethod
    public void setUp() {
        trustedVerifierService = new TrustedVerifierServiceImpl();
    }

    @Test
    public void testAddAndGetTrustedVerifier() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:example:123");
        verifier.setName("Test Verifier");
        verifier.setStatus(TrustedVerifier.VerifierStatus.ACTIVE);

        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(verifier, TENANT);
        assertNotNull(added.getId());

        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifier("did:example:123", TENANT);
        assertTrue(retrieved.isPresent());
        assertEquals(retrieved.get().getName(), "Test Verifier");
    }

    @Test
    public void testGetTrustedVerifierByClientId() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setClientId("test-client");
        verifier.setName("Client Verifier");
        
        trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        Optional<TrustedVerifier> retrieved = trustedVerifierService.getTrustedVerifierByClientId(
                "test-client", TENANT);
        assertTrue(retrieved.isPresent());
        assertEquals(retrieved.get().getName(), "Client Verifier");
    }

    @Test
    public void testIsVerifierTrustedStrictDefault() throws VPException {
        // Default is strictMode = false, so all are trusted
        assertTrue(trustedVerifierService.isVerifierTrusted("did:any", TENANT));
    }

    @Test
    public void testIsVerifierTrustedStrictEnabled() throws VPException {
        trustedVerifierService.setStrictVerificationEnabled(TENANT, true);
        
        // Not registered -> not trusted
        assertFalse(trustedVerifierService.isVerifierTrusted("did:unregistered", TENANT));

        // Registered -> trusted
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:registered");
        verifier.setName("Registered");
        verifier.setStatus(TrustedVerifier.VerifierStatus.ACTIVE);
        trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        assertTrue(trustedVerifierService.isVerifierTrusted("did:registered", TENANT));
    }

    @Test
    public void testUpdateTrustedVerifier() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:old");
        verifier.setName("Old Name");
        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        TrustedVerifier updatedVerifier = new TrustedVerifier();
        updatedVerifier.setName("New Name");
        updatedVerifier.setDid("did:new");
        trustedVerifierService.updateTrustedVerifier(added.getId(), updatedVerifier, TENANT);

        assertTrue(trustedVerifierService.getTrustedVerifier("did:new", TENANT).isPresent());
        assertFalse(trustedVerifierService.getTrustedVerifier("did:old", TENANT).isPresent());
        assertEquals(trustedVerifierService.getTrustedVerifier("did:new", TENANT).get().getName(), "New Name");
    }

    @Test
    public void testRemoveTrustedVerifier() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:remove");
        verifier.setName("Remove Me");
        TrustedVerifier added = trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        trustedVerifierService.removeTrustedVerifier(added.getId(), TENANT);
        assertFalse(trustedVerifierService.getTrustedVerifier("did:remove", TENANT).isPresent());
    }

    @Test
    public void testValidateVerifierRequest() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:req");
        verifier.setName("Req Verifier");
        verifier.setStatus(TrustedVerifier.VerifierStatus.ACTIVE);
        List<String> allowedTypes = new ArrayList<>();
        allowedTypes.add("VerifiableCredential");
        verifier.setAllowedCredentialTypes(allowedTypes);
        trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        List<String> requestedTypes = new ArrayList<>();
        requestedTypes.add("VerifiableCredential");
        assertTrue(trustedVerifierService.validateVerifierRequest("did:req", requestedTypes, TENANT));

        requestedTypes.add("SpecialCredential");
        assertFalse(trustedVerifierService.validateVerifierRequest("did:req", requestedTypes, TENANT));
    }

    @Test
    public void testValidateRedirectUriRelaxed() throws VPException {
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:uri");
        verifier.setName("URI Verifier");
        verifier.setOrganizationUrl("https://example.com");
        trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        // Relaxed mode (default)
        assertTrue(trustedVerifierService.validateRedirectUri("did:uri", "https://example.com/callback", TENANT));
        assertTrue(trustedVerifierService.validateRedirectUri("did:uri", "https://sub.example.com", TENANT));
        assertFalse(trustedVerifierService.validateRedirectUri("did:uri", "https://another.com", TENANT));
    }

    @Test
    public void testValidateRedirectUriStrict() throws VPException {
        trustedVerifierService.setRedirectUriValidationMode(TENANT,
                TrustedVerifierService.RedirectUriValidationMode.STRICT);
        
        TrustedVerifier verifier = new TrustedVerifier();
        verifier.setDid("did:strict");
        verifier.setName("Strict Verifier");
        List<String> uris = new ArrayList<>();
        uris.add("https://example.com/callback");
        verifier.setAllowedRedirectUris(uris);
        trustedVerifierService.addTrustedVerifier(verifier, TENANT);

        assertTrue(trustedVerifierService.validateRedirectUri("did:strict", "https://example.com/callback", TENANT));
        assertFalse(trustedVerifierService.validateRedirectUri("did:strict", "https://example.com/other", TENANT));
    }
}
