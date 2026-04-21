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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.Jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class SignatureVerifierTest {

    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;

    @BeforeMethod
    public void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        rsaPublicKey = kp.getPublic();
        rsaPrivateKey = kp.getPrivate();
    }

    @Test
    public void testVerifyJwtSignature() throws Exception {
        String jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256, "user-1");
        boolean verified = SignatureVerifier.verifyJwtSignature(jwt, rsaPublicKey, "RS256");
        assertTrue(verified);
    }

    @Test
    public void testVerifyJwtSignature_AlgorithmMismatch() throws Exception {
        String jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256, "user-1");
        // Pass RS384 as expected, but the JWT is RS256
        assertThrows(VerificationException.class,
                () -> SignatureVerifier.verifyJwtSignature(jwt, rsaPublicKey, "RS384"));
    }

    @Test
    public void testVerifySignatureWithInvalidJwt() {
        assertThrows(VerificationException.class, () -> SignatureVerifier.verifySignature(null));
    }

    @Test
    public void testVerifySignature_NoneAlgorithmRejected() throws Exception {
        // Use a raw JWT string with "alg": "none" to bypass builder-level restrictions.
        
        String noneJwt = 
        "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL3RydXN0ZWQuaXNzdWVyLmV4YW1wbGUiLCJzdWIiOiJ1c2VyLTEifQ.";
        
        assertThrows(Exception.class, () -> {
            SignedJWT signedJWT = SignedJWT.parse(noneJwt);
            SignatureVerifier.verifySignature(signedJWT);
        });
    }

    @Test
    public void testVerifySignature_UnsupportedAlgorithmRejected() throws Exception {
        // HS256 is not in the ALLOWED_ALGORITHMS list (only asymmetric ones)
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issuer("https://trusted.issuer.example")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse("HS256"))
                        .type(JOSEObjectType.JWT)
                        .build(),
                claimsSet);

        assertThrows(VerificationException.class, () -> SignatureVerifier.verifySignature(signedJWT));
    }

    @Test
    public void testVerifyExpiration() throws Exception {
        Jwt payload = new Jwt();
        long now = System.currentTimeMillis();
        payload.setExp(now - 100000); // 100s ago

        assertThrows(VerificationException.class, () -> SignatureVerifier.verifyExpiration(payload));

        payload.setExp(now + 100000); // 100s in future
        SignatureVerifier.verifyExpiration(payload); // Should not throw
    }

    @Test
    public void testHttpClientUtil() {
        assertThrows(VerificationException.class, () -> HttpClientUtil.fetchJson("invalid-url"));
    }

    @Test
    public void testVerifySignature_IssuerSpoofingProtection() throws Exception {
        // Create a JWT with an HTTPS issuer but a DID in the kid header
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issuer("https://trusted.issuer.example")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .keyID("did:key:attacker#key")
                        .build(),
                claimsSet);

        signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaPrivateKey));

        // Before the fix, this would have attempted DID resolution (did:key:attacker).
        // After the fix, it remains an HTTPS issuer and attempts JWKS resolution
        // (which will fail in this test environment).
        // We expect it to fail with JWKS resolution error or similar, NOT DID resolution error.
        try {
            SignatureVerifier.verifySignature(signedJWT);
        } catch (VerificationException e) {
            assertTrue(!e.getErrorCode().name().contains("DID"), 
                    "Should not attempt DID resolution for HTTPS issuer: "
                            + e.getMessage());
        }
    }

    private String buildSignedJwt(PrivateKey privateKey, JWSAlgorithm algorithm, String subject)
            throws JOSEException {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("https://issuer.example")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(algorithm)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claimsSet);

        signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(privateKey));
        return signedJWT.serialize();
    }
}
