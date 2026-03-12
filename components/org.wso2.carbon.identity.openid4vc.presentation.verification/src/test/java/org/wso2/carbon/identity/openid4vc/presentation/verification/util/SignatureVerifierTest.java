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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.testng.Assert.assertThrows;

public class SignatureVerifierTest {

    private SignatureVerifier signatureVerifier;


    private PublicKey rsaPublicKey;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        signatureVerifier = new SignatureVerifier();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        rsaPublicKey = kp.getPublic();
    }

    @Test
    public void testVerifyJwtSignatureMissingParams() {
        assertThrows(CredentialVerificationException.class, () -> 
            signatureVerifier.verifyJwtSignature(null, rsaPublicKey, "RS256"));
        assertThrows(CredentialVerificationException.class, () -> 
            signatureVerifier.verifyJwtSignature("jwt", null, "RS256"));
    }

    @Test
    public void testVerifyJwtSignatureInvalidFormat() {
        assertThrows(CredentialVerificationException.class, () -> 
            signatureVerifier.verifyJwtSignature("invalid.jwt", rsaPublicKey, "RS256"));
    }

    @Test
    public void testVerifyLinkedDataSignatureMissingParams() {
        assertThrows(CredentialVerificationException.class, () -> 
            signatureVerifier.verifyLinkedDataSignature(null, rsaPublicKey, "Ed25519Signature2018", "val"));
    }

    // Actual signature verification would require valid signed JWTs matching the generated keys,
    // which is better suited for integration tests or using static test vectors.
    // For unit tests, we focus on input validation and algorithm handling logic.
}
