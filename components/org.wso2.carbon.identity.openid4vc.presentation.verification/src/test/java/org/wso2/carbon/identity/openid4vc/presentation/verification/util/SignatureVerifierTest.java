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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

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

    @Test
        public void testVerifyLinkedDataSignatureGenericProofTypeWithRandomSignatureThrows() {

        String proofValue = Base64.getUrlEncoder().withoutPadding().encodeToString("random-signature".getBytes());
        assertThrows(CredentialVerificationException.class,
            () -> signatureVerifier.verifyLinkedDataSignature(
                "{\"k\":\"v\"}", rsaPublicKey, "UnknownProofType", proofValue));
    }

    @Test
    public void testVerifyLinkedDataSignatureInvalidJwsFormat() {

        assertThrows(CredentialVerificationException.class, () ->
                signatureVerifier.verifyLinkedDataSignature(
                        "doc", rsaPublicKey, "JsonWebSignature2020", "invalid-jws"));
    }

    @Test
    public void testVerifyJwtSignatureUnsupportedAlgorithmInJcaFallback() throws Exception {

        KeyPairGenerator dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA");
        dsaKeyPairGenerator.initialize(1024);
        PublicKey dsaPublicKey = dsaKeyPairGenerator.generateKeyPair().getPublic();

        String jwt = "aGVhZGVy.cGF5bG9hZA.c2ln";
        assertThrows(CredentialVerificationException.class,
                () -> signatureVerifier.verifyJwtSignature(jwt, dsaPublicKey, "UNSUPPORTED"));
    }

    @Test
    public void testPrivateGetJcaAlgorithmAndHeaderParsing() throws Exception {

        Method getJcaAlgorithm = SignatureVerifier.class.getDeclaredMethod("getJcaAlgorithm", String.class);
        getJcaAlgorithm.setAccessible(true);

        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "RS256"), "SHA256withRSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "RS384"), "SHA384withRSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "RS512"), "SHA512withRSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "ES256"), "SHA256withECDSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "ES384"), "SHA384withECDSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "ES512"), "SHA512withECDSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "ES256K"), "SHA256withECDSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "EdDSA"), "EdDSA");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "PS256"), "SHA256withRSAandMGF1");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "PS384"), "SHA384withRSAandMGF1");
        assertEquals(getJcaAlgorithm.invoke(signatureVerifier, "PS512"), "SHA512withRSAandMGF1");

        try {
            getJcaAlgorithm.invoke(signatureVerifier, "BAD_ALG");
            fail("Expected exception for unsupported JWT algorithm");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof CredentialVerificationException);
        }

        Method extractAlgorithm = SignatureVerifier.class
                .getDeclaredMethod("extractAlgorithmFromHeader", String.class);
        extractAlgorithm.setAccessible(true);

        assertEquals(extractAlgorithm.invoke(signatureVerifier, "{\"alg\":\"RS256\"}"), "RS256");

        try {
            extractAlgorithm.invoke(signatureVerifier, "{\"typ\":\"JWT\"}");
            fail("Expected exception for missing alg in JWT header");
        } catch (InvocationTargetException e) {
            assertNotNull(e.getCause());
        }

        try {
            extractAlgorithm.invoke(signatureVerifier, "not-json");
            fail("Expected exception for malformed JWT header");
        } catch (InvocationTargetException e) {
            assertNotNull(e.getCause());
        }
    }

    @Test
    public void testPrivateEcdsaAndProofDecodingHelpers() throws Exception {

        Method convertJwtEcdsaToDer = SignatureVerifier.class
                .getDeclaredMethod("convertJwtEcdsaToDer", byte[].class, String.class);
        convertJwtEcdsaToDer.setAccessible(true);

        byte[] compact64 = new byte[64];
        compact64[0] = 1;
        compact64[32] = 1;
        byte[] der = (byte[]) convertJwtEcdsaToDer.invoke(signatureVerifier, compact64, "ES256");
        assertNotNull(der);
        assertTrue(der.length > 0);

        byte[] unchanged = (byte[]) convertJwtEcdsaToDer.invoke(signatureVerifier, compact64, "UNKNOWN");
        assertEquals(unchanged.length, compact64.length);

        Method trimLeadingZeros = SignatureVerifier.class.getDeclaredMethod("trimLeadingZeros", byte[].class);
        trimLeadingZeros.setAccessible(true);
        byte[] trimmed = (byte[]) trimLeadingZeros.invoke(signatureVerifier, new byte[]{0, 0, 1, 2});
        assertEquals(trimmed.length, 2);
        assertEquals(trimmed[0], 1);

        Method base58Decode = SignatureVerifier.class.getDeclaredMethod("base58Decode", String.class);
        base58Decode.setAccessible(true);
        byte[] empty = (byte[]) base58Decode.invoke(signatureVerifier, "");
        assertEquals(empty.length, 0);
        byte[] invalid = (byte[]) base58Decode.invoke(signatureVerifier, "0OIl");
        assertEquals(invalid.length, 0);
        byte[] valid = (byte[]) base58Decode.invoke(signatureVerifier, "1112");
        assertTrue(valid.length >= 1);

        Method decodeProofValue = SignatureVerifier.class.getDeclaredMethod("decodeProofValue", String.class);
        decodeProofValue.setAccessible(true);

        String base64Proof = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("proof".getBytes(StandardCharsets.UTF_8));
        byte[] proofBytes = (byte[]) decodeProofValue.invoke(signatureVerifier, base64Proof);
        assertEquals(new String(proofBytes, StandardCharsets.UTF_8), "proof");

        try {
            decodeProofValue.invoke(signatureVerifier, "z0");
            fail("Expected exception for undecodable base58 proof");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof CredentialVerificationException);
        }
    }

    // Actual signature verification would require valid signed JWTs matching the generated keys,
    // which is better suited for integration tests or using static test vectors.
    // For unit tests, we focus on input validation and algorithm handling logic.
}
