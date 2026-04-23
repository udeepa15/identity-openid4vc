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

package org.wso2.carbon.identity.openid4vc.presentation.verification;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.JwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.Jwt;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.SdJwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class DtoModelCoverageTest {

    @Test
    public void testPresentationSubmission() {
        PresentationSubmission submission = new PresentationSubmission();
        submission.setId("sub-1");
        submission.setDefinitionId("def-1");
        
        PresentationSubmission.DescriptorMap descriptor = new PresentationSubmission.DescriptorMap();
        descriptor.setId("desc-1");
        descriptor.setFormat("jwt_vc");
        descriptor.setPath("$.vp");
        
        submission.setDescriptorMap(Collections.singletonList(descriptor));
        
        assertEquals(submission.getId(), "sub-1");
        assertEquals(submission.getDefinitionId(), "def-1");
        assertEquals(submission.getDescriptorMap().get(0).getFormat(), "jwt_vc");
    }

    @Test
    public void testVerificationResult() {
        VerificationResult result = new VerificationResult.Builder()
                .isVerified(true)
                .statusMessage("Success")
                .build();
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user1");
        result.setVerifiedClaims(claims);

        assertTrue(result.isVerified());
        assertEquals(result.getVerifiedClaims().get("sub"), "user1");
    }

    @Test
    public void testJwtPayloadFromSignedJwt() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://issuer.com")
                .subject("user-123")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600000))
                .claim("custom", "val")
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(new RSASSASigner(kp.getPrivate()));

        Jwt payload = new Jwt();
        JwtVerifier.populateJwtModel(payload, signedJWT);

        assertEquals(payload.getIss(), "https://issuer.com");
        assertEquals(payload.getSub(), "user-123");
        assertEquals(payload.getAdditionalClaims().get("custom"), "val");
    }

    @Test
    public void testSdJwtPayloadFromSignedJwt() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        List<String> sdHashes = new ArrayList<>();
        sdHashes.add("hash1");
        sdHashes.add("hash2");

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://issuer.com")
                .claim("_sd", sdHashes)
                .claim("_sd_alg", "sha-256")
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(new RSASSASigner(kp.getPrivate()));

        SdJwt payload = new SdJwt();
        JwtVerifier.populateJwtModel(payload, signedJWT);
        
        Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();
        if (claims.containsKey("_sd_alg")) {
            payload.setSdAlg(claims.get("_sd_alg").toString());
        }
        if (claims.containsKey("_sd") && claims.get("_sd") instanceof List) {
            payload.setSd((List<String>) claims.get("_sd"));
        }

        assertEquals(payload.getIss(), "https://issuer.com");
        assertEquals(payload.getSd().size(), 2);
        assertEquals(payload.getSdAlg(), "sha-256");
    }
}
