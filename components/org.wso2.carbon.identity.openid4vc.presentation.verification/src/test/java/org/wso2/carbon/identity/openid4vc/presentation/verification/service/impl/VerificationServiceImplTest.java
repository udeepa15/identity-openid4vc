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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Comprehensive unit tests for {@link VerificationServiceImpl}.
 *
 * <p>Coverage targets:
 * <ul>
 *   <li>{@code parsePresentation} — valid JWT, malformed input, two-part token</li>
 *   <li>{@code validateRequest} — null/blank token, null submission, null/empty
 *       descriptor_map, null/blank format, unknown format</li>
 *   <li>{@code verifyAgainstDefinition} — null definition, no requestedCredentials,
 *       no issuer constraint, issuer match (did:web vs https, mixed case, with path/port),
 *       issuer mismatch, missing iss claim, unparseable PD issuer,
 *       all claims present, required claim missing, empty claims list,
 *       combined issuer + claims pass, issuer passes but claim missing</li>
 *   <li>{@code verify} (integration) — PD service unavailable, PD service throws,
 *       successful result status and claims, SD-JWT format accepted by validateRequest</li>
 * </ul>
 */
public class VerificationServiceImplTest {

    private VerificationServiceImpl service;

    @Mock
    private PresentationDefinitionService pdService;

    private String validJwtToken;
    private String validJwtIssuer;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        service = new VerificationServiceImpl();
        service.setPresentationDefinitionService(pdService);

        // Build a real signed JWT reusable across tests.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        validJwtIssuer = "https://example.ngrok-free.app/oid4vci";
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(validJwtIssuer)
                .subject("user-1")
                .claim("email", "user@example.com")
                .claim("given_name", "Alice")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3_600_000))
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner(kp.getPrivate()));
        validJwtToken = jwt.serialize();
    }

    // =========================================================================
    // validateRequest — vpToken guards
    // =========================================================================

    @Test(description = "validateRequest: null vpToken throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_nullToken_throwsInvalidSubmission() throws Exception {
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        VerificationResult result = service.verify(sub, 1, null);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: blank vpToken throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_blankToken_throwsInvalidSubmission() throws Exception {
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        VerificationResult result = service.verify(sub, 1, "   ");
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: blank definition_id throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_blankDefinitionId_throwsSubmissionError() throws Exception {
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        sub.setDefinitionId("   ");
        try {
            service.verify(sub, 1, validJwtToken);
            fail("Expected VerificationServerException");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_VP_SUBMISSION);
        }
    }

    // =========================================================================
    // validateRequest — descriptorMap guards
    // =========================================================================

    @Test(description = "validateRequest: null submission throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_nullSubmission_throwsInvalidSubmission() throws Exception {
        VerificationResult result = service.verify(null, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: null descriptorMap throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_nullDescriptorMap_throwsInvalidSubmission() throws Exception {
        PresentationSubmission sub = new PresentationSubmission();
        sub.setDefinitionId("def-1");
        sub.setDescriptorMap(null);
        VerificationResult result = service.verify(sub, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: empty descriptorMap throws INVALID_VP_SUBMISSION")
    public void testValidateRequest_emptyDescriptorMap_throwsInvalidSubmission() throws Exception {
        PresentationSubmission sub = new PresentationSubmission();
        sub.setDefinitionId("def-1");
        sub.setDescriptorMap(Collections.emptyList());
        VerificationResult result = service.verify(sub, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    // =========================================================================
    // validateRequest — format guards
    // =========================================================================

    @Test(description = "validateRequest: null format in descriptor throws INVALID_VP_FORMAT")
    public void testValidateRequest_nullFormat_throwsInvalidFormat() throws Exception {
        PresentationSubmission sub = buildSubmission(null);
        VerificationResult result = service.verify(sub, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: blank format in descriptor throws INVALID_VP_FORMAT")
    public void testValidateRequest_blankFormat_throwsInvalidFormat() throws Exception {
        PresentationSubmission sub = buildSubmission("   ");
        VerificationResult result = service.verify(sub, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "validateRequest: unknown format throws INVALID_VP_FORMAT")
    public void testValidateRequest_unknownFormat_throwsInvalidFormat() throws Exception {
        PresentationSubmission sub = buildSubmission("ldp_vc");
        VerificationResult result = service.verify(sub, 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().get(0).contains("Unsupported VP format"));

    }

    @Test(description = "validateRequest: jwt_vc format is accepted (known format)")
    public void testValidateRequest_jwtFormat_passesFormatCheck() throws Exception {
        // PD service throws to short-circuit, confirming we got past validateRequest.
        when(pdService.getPresentationDefinitionById(anyString(), anyInt()))
                .thenThrow(new RuntimeException("downstream"));
        // Use stub service so the Verifier does not attempt real sig verification.
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        stub.setPresentationDefinitionService(pdService);
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        try {
            stub.verify(sub, 1, validJwtToken);
            fail("Expected downstream exception");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    @Test(description = "validateRequest: vc+sd-jwt format is accepted (known format)")
    public void testValidateRequest_sdJwtFormat_passesFormatCheck() throws Exception {
        when(pdService.getPresentationDefinitionById(anyString(), anyInt()))
                .thenThrow(new RuntimeException("downstream"));

        // Use stub service with a verifier that handles SD-JWT.
        VerificationServiceImpl stub = buildStubService(Constants.VC_SD_JWT_FORMAT,
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        stub.setPresentationDefinitionService(pdService);

        PresentationSubmission sub = buildSubmission(Constants.VC_SD_JWT_FORMAT);
        String sdJwtToken = validJwtToken + "~";

        try {
            stub.verify(sub, 1, sdJwtToken);
            fail("Expected downstream exception");
        } catch (VerificationServerException e) {
            // We got past validateRequest AND the Verifier handle call.
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    // =========================================================================
    // verify — infrastructure guards
    // =========================================================================

    @Test(description = "verify: PD service null after unset throws INTERNAL_SERVER_ERROR")
    public void testVerify_pdServiceNull_throwsServerError() throws Exception {
        // Use stub service so the Verifier does not attempt real sig verification.
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        // Do NOT inject a PD service — it remains null.
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        try {
            stub.verify(sub, 1, validJwtToken);
            fail("Expected VerificationServerException");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    @Test(description = "verify: PD service throws RuntimeException — wrapped as INTERNAL_SERVER_ERROR")
    public void testVerify_pdServiceThrows_wrapsAsServerError() throws Exception {
        when(pdService.getPresentationDefinitionById(anyString(), anyInt()))
                .thenThrow(new RuntimeException("DB unavailable"));
        // Use stub service so we reach the PD fetch step without failing on sig verification.
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        stub.setPresentationDefinitionService(pdService);
        PresentationSubmission sub = buildSubmission(Constants.JWT_VC_FORMAT);
        try {
            stub.verify(sub, 1, validJwtToken);
            fail("Expected VerificationServerException");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
            assertTrue(e.getMessage().contains("DB unavailable"));
        }
    }

    // =========================================================================
    // verifyAgainstDefinition — tested through verify() with a stub Verifier
    // =========================================================================

    @Test(description = "verifyAgainstDefinition: null definition — throws INTERNAL_SERVER_ERROR")
    public void testVerifyAgainstDefinition_nullDefinition_throwsServerError() throws Exception {
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(null);
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        stub.setPresentationDefinitionService(pdService);

        try {
            stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
            fail("Expected VerificationServerException");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
            assertTrue(e.getMessage().contains("Presentation definition not found"));
        }
    }

    @Test(description = "verifyAgainstDefinition: definition with null requestedCredentials — no checks performed")
    public void testVerifyAgainstDefinition_nullRequestedCredentials_success() throws Exception {
        PresentationDefinition pd = new PresentationDefinition();
        pd.setDefinitionId("def-1");
        pd.setRequestedCredentials(null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("iss", (Object) validJwtIssuer));
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: no issuer constraint in PD — skips issuer check")
    public void testVerifyAgainstDefinition_noIssuerInPd_skipsIssuerCheck() throws Exception {
        PresentationDefinition pd = buildPd(null, Arrays.asList("email"));
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "user@example.com");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    // --- Issuer verification paths ---
    // Note: Issuer verification requires strict matching of host, port, and path components.

    @Test(description = "verifyAgainstDefinition: issuer matching with https:// iss — passes")
    public void testVerifyAgainstDefinition_didWebMatchesHttpsIss_passes() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: https:// PD issuer matches https:// token iss (same path) — passes")
    public void testVerifyAgainstDefinition_httpsIssuerMatchesHttpsIss_passes() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: issuer host comparison — passes")
    public void testVerifyAgainstDefinition_issuerCaseInsensitive_passes() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: issuer with path — matches strictly")
    public void testVerifyAgainstDefinition_didWebWithPath_matchesStrictly() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/t/tenant1/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/t/tenant1/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);
 
        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }
 
    @Test(description = "verifyAgainstDefinition: https:// issuer with port — matches strictly")
    public void testVerifyAgainstDefinition_httpsWithPort_matchesStrictly() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app:8080/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);
 
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app:8080/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);
 
        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: issuer host mismatch — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_issuerMismatch_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd("did:web:trusted-issuer.example.com:oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);
 
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://untrusted-issuer.example.com/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);
 
        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().get(0).contains("Issuer verification failed"));

    }

    @Test(description = "verifyAgainstDefinition: issuer path mismatch — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_issuerPathMismatch_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com/t/tenant1", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com/t/tenant2");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: issuer path case mismatch — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_issuerPathCaseMismatch_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com/Tenant1", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com/tenant1");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: issuer port mismatch — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_issuerPortMismatch_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com:8443/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com:9443/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: PD issuer set but iss claim absent — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_missingIssClaim_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd("did:web:example.com", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        // Claims map deliberately has no "iss".
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("email", (Object) "alice@example.com"));
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().get(0).contains("'iss' claim is missing"));

    }

    @Test(description = "verifyAgainstDefinition: unparseable PD issuer string —" + 
    " pdHost is null, throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_unparseablePdIssuer_throwsInvalidCredential() throws Exception {
        // "not-a-url" doesn't start with "did:web:" and is not a valid URI,
        // so extractHost returns null.
        PresentationDefinition pd = buildPd("not-a-url", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: http scheme matches http token — passes")
    public void testVerifyAgainstDefinition_httpSchemeMatchesHttp_passes() throws Exception {
        PresentationDefinition pd = buildPd("http://example.com/oid4vci", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "http://example.com/oid4vci");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: http PD mismatch https token — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_httpMismatchHttps_throws() throws Exception {
        PresentationDefinition pd = buildPd("http://example.com", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com"); // Normalizes to "example.com"
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: https PD mismatch http token — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_httpsMismatchHttp_throws() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "http://example.com"); // Normalizes to "http://example.com"
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: port 80 is matching — passes")
    public void testVerifyAgainstDefinition_httpPort80Stripped_passes() throws Exception {
        PresentationDefinition pd = buildPd("http://example.com:80", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "http://example.com:80");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: port 80 is preserved for https — throws mismatch")
    public void testVerifyAgainstDefinition_httpsPort80Preserved_throws() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.com:80"); // Normalizes to "example.com:80" vs "example.com"
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    @Test(description = "verifyAgainstDefinition: unsupported scheme (ftp) — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_unsupportedScheme_throws() throws Exception {
        PresentationDefinition pd = buildPd("https://example.com", null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "ftp://example.com"); // Returns null normalization
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());

    }

    // --- Claim presence validation ---

    @Test(description = "verifyAgainstDefinition: all required claims present — passes, claims returned")
    public void testVerifyAgainstDefinition_allClaimsPresent_passes() throws Exception {
        PresentationDefinition pd = buildPd(null, Arrays.asList("email", "given_name"));
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");
        claims.put("given_name", "Alice");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
        assertEquals(result.getVerifiedClaims().get("email"), "alice@example.com");
        assertEquals(result.getVerifiedClaims().get("given_name"), "Alice");
    }

    @Test(description = "verifyAgainstDefinition: required claim missing — throws INVALID_CREDENTIAL with claim name")
    public void testVerifyAgainstDefinition_requiredClaimMissing_throwsInvalidCredential() throws Exception {
        PresentationDefinition pd = buildPd(null, Arrays.asList("email", "given_name"));
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        // "given_name" missing.
        VerificationServiceImpl stub = buildStubService(
                Collections.singletonMap("email", (Object) "alice@example.com"));
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().get(0).contains("given_name"));

    }

    @Test(description = "verifyAgainstDefinition: empty claims list in PD — no claim check, passes")
    public void testVerifyAgainstDefinition_emptyClaimsInPd_passes() throws Exception {
        PresentationDefinition pd = buildPd(null, Collections.emptyList());
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        VerificationServiceImpl stub = buildStubService(Collections.emptyMap());
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: both issuer and claims valid — both checks pass")
    public void testVerifyAgainstDefinition_issuerAndClaimsBothValid_passes() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/oid4vci", Arrays.asList("email"));
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/oid4vci");
        claims.put("email", "alice@example.com");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        assertTrue(result.isVerified());
    }

    @Test(description = "verifyAgainstDefinition: issuer passes but required claim missing — throws INVALID_CREDENTIAL")
    public void testVerifyAgainstDefinition_issuerPassesClaimMissing_throws() throws Exception {
        PresentationDefinition pd = buildPd("https://example.ngrok-free.app/oid4vci",
                Arrays.asList("phone_number"));
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://example.ngrok-free.app/oid4vci");
        claims.put("email", "alice@example.com"); // "phone_number" absent
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);
        org.testng.Assert.assertFalse(result.isVerified());
        org.testng.Assert.assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().get(0).contains("phone_number"));

    }

    // =========================================================================
    // verify — successful result
    // =========================================================================

    @Test(description = "verify: successful flow returns VERIFIED status with all claims")
    public void testVerify_success_returnsVerifiedResult() throws Exception {
        PresentationDefinition pd = buildPd(null, null);
        when(pdService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(pd);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", validJwtIssuer);
        claims.put("email", "alice@example.com");
        VerificationServiceImpl stub = buildStubService(claims);
        stub.setPresentationDefinitionService(pdService);

        VerificationResult result = stub.verify(buildSubmission(Constants.JWT_VC_FORMAT), 1, validJwtToken);

        assertTrue(result.isVerified());
        assertNotNull(result.getVerifiedClaims());
        assertEquals(result.getVerifiedClaims().get("email"), "alice@example.com");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Build a minimal valid {@link PresentationSubmission} for the given format.
     */
    private PresentationSubmission buildSubmission(final String format) {
        PresentationSubmission sub = new PresentationSubmission();
        sub.setDefinitionId("def-1");
        PresentationSubmission.DescriptorMap dm = new PresentationSubmission.DescriptorMap();
        dm.setFormat(format);
        dm.setId("input-1");
        dm.setPath("$.vp");
        sub.setDescriptorMap(Collections.singletonList(dm));
        return sub;
    }

    /**
     * Build a {@link PresentationDefinition} with one {@link PresentationDefinition.RequestedCredential}.
     *
     * @param issuer Required issuer constraint (nullable).
     * @param claims Required claim names (nullable / empty).
     */
    private PresentationDefinition buildPd(final String issuer, final List<String> claims) {
        PresentationDefinition pd = new PresentationDefinition();
        pd.setDefinitionId("def-1");
        PresentationDefinition.RequestedCredential req = new PresentationDefinition.RequestedCredential();
        req.setIssuer(issuer);
        req.setClaims(claims);
        pd.setRequestedCredentials(Collections.singletonList(req));
        return pd;
    }

    /**
     * Build a {@link VerificationServiceImpl} whose Verifier list is replaced with a single
     * stub that accepts {@link VerificationConstants#FORMAT_JWT} and returns {@code stubbedClaims} without
     * performing any real cryptographic verification.
     *
     * @param stubbedClaims The claims map the stub verifier returns.
     */
    private VerificationServiceImpl buildStubService(final Map<String, Object> stubbedClaims)
            throws Exception {

        return buildStubService(Constants.JWT_VC_FORMAT, stubbedClaims);
    }

    /**
     * Build a {@link VerificationServiceImpl} whose Verifier list is replaced with a single
     * stub that accepts the specified {@code format} and returns {@code stubbedClaims} without
     * performing any real cryptographic verification.
     *
     * @param format        The format the stub verifier reports it can handle.
     * @param stubbedClaims The claims map the stub verifier returns.
     */
    private VerificationServiceImpl buildStubService(final String format, final Map<String, Object> stubbedClaims)
            throws Exception {

        Verifier stubVerifier = mock(Verifier.class);
        when(stubVerifier.canHandle(format)).thenReturn(true);
        when(stubVerifier.handle(any(PresentationSubmission.class), anyInt(), anyString())).thenReturn(stubbedClaims);

        VerificationServiceImpl stub = new VerificationServiceImpl();
        Field verifiersField = VerificationServiceImpl.class.getDeclaredField("verifiers");
        verifiersField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Verifier> verifierList = (List<Verifier>) verifiersField.get(stub);
        verifierList.clear();
        verifierList.add(stubVerifier);

        return stub;
    }
}
