/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.JsonObject;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DescriptorMapDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PathNestedDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPVerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiablePresentation;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class DtoModelCoverageTest {

    @Test
    public void testPathNestedAndDescriptorMapDTO() {

        PathNestedDTO nested = new PathNestedDTO();
        nested.setFormat("vc+sd-jwt");
        nested.setPath("$.verifiableCredential[0]");
        assertEquals(nested.getFormat(), "vc+sd-jwt");
        assertEquals(nested.getPath(), "$.verifiableCredential[0]");
        assertTrue(nested.toString().contains("format='vc+sd-jwt'"));

        DescriptorMapDTO descriptor = new DescriptorMapDTO();
        assertFalse(descriptor.isValid());
        descriptor.setId("input-1");
        descriptor.setFormat("jwt_vp");
        descriptor.setPath("$");
        assertTrue(descriptor.isValid());
        assertEquals(descriptor.getId(), "input-1");
        assertEquals(descriptor.getFormat(), "jwt_vp");
        assertEquals(descriptor.getPath(), "$");
        assertTrue(descriptor.toString().contains("DescriptorMapDTO"));
    }

    @Test
    public void testPresentationSubmissionDTOWithReflectionSetDescriptorMap() throws Exception {

        PresentationSubmissionDTO dto = new PresentationSubmissionDTO();
        dto.setId("sub-1");
        dto.setDefinitionId("def-1");

        DescriptorMapDTO descriptor = new DescriptorMapDTO();
        descriptor.setId("input-1");
        descriptor.setFormat("ldp_vp");
        descriptor.setPath("$");

        List<DescriptorMapDTO> list = new ArrayList<>();
        list.add(descriptor);

        Field f = PresentationSubmissionDTO.class.getDeclaredField("descriptorMap");
        f.setAccessible(true);
        f.set(dto, list);

        assertTrue(dto.isValid());
        List<DescriptorMapDTO> copy = dto.getDescriptorMap();
        assertEquals(copy.size(), 1);
        copy.clear();
        assertEquals(dto.getDescriptorMap().size(), 1);
        assertTrue(dto.toString().contains("definitionId='def-1'"));
    }

    @Test
    public void testVPSubmissionDTO() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        assertFalse(dto.hasError());
        assertFalse(dto.hasVpToken());
        assertFalse(dto.isValid());

        dto.setVpToken("token");
        JsonObject submission = new JsonObject();
        submission.addProperty("id", "sub");
        dto.setPresentationSubmission(submission);
        dto.setState("state");
        assertTrue(dto.hasVpToken());
        assertTrue(dto.isValid());

        JsonObject returned = dto.getPresentationSubmission();
        returned.addProperty("new", "value");
        assertNull(dto.getPresentationSubmission().get("new"));

        dto.setError("invalid_request");
        dto.setErrorDescription("bad");
        assertTrue(dto.hasError());
        assertTrue(dto.toString().contains("hasError=true"));
    }

    @Test
    public void testVCVerificationResultDTO() {

        VCVerificationResultDTO ok = new VCVerificationResultDTO(1, VCVerificationStatus.SUCCESS,
                "Employee", "did:web:issuer");
        assertEquals(ok.getVcIndex(), 1);
        assertTrue(ok.isSuccess());
        assertEquals(ok.getVerificationStatusEnum(), VCVerificationStatus.SUCCESS);

        ok.setCredentialTypes(new String[]{"A", "B"});
        ok.setVerificationStatus(VCVerificationStatus.REVOKED);
        assertEquals(ok.getVerificationStatus(), "REVOKED");

        VCVerificationResultDTO fail = new VCVerificationResultDTO(2, VCVerificationStatus.INVALID, "bad-sig");
        assertFalse(fail.isSuccess());
        assertEquals(fail.getError(), "bad-sig");

        VCVerificationResultDTO built = new VCVerificationResultDTO.Builder()
                .issuer("issuer-1")
                .format("jwt_vc")
                .expired(Boolean.FALSE)
                .error("none")
                .build();
        assertEquals(built.getIssuer(), "issuer-1");
        assertEquals(built.getFormat(), "jwt_vc");
        assertEquals(built.getExpired(), Boolean.FALSE);
        assertEquals(built.getError(), "none");
        assertTrue(built.toString().contains("VCVerificationResultDTO"));
    }

    @Test
    public void testVPVerificationResponseDTO() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "alice");

        VPVerificationResponseDTO success = VPVerificationResponseDTO.success(claims, "jwt_vp", "nonce-1", "aud-1");
        assertTrue(success.isValid());
        assertEquals(success.getFormatDetected(), "jwt_vp");
        assertEquals(success.getNonce(), "nonce-1");
        assertEquals(success.getAudience(), "aud-1");
        assertEquals(success.getVerifiedClaims().get("sub"), "alice");

        boolean unmodifiable = false;
        try {
            success.getVerifiedClaims().put("k", "v");
        } catch (UnsupportedOperationException e) {
            unmodifiable = true;
        }
        assertTrue(unmodifiable);

        VPVerificationResponseDTO fail = VPVerificationResponseDTO.failure("invalid", "ldp_vp");
        assertFalse(fail.isValid());
        assertEquals(fail.getErrorMessage(), "invalid");
        assertEquals(fail.getFormatDetected(), "ldp_vp");
        assertTrue(fail.getVerifiedClaims().isEmpty());
    }

    @Test
    public void testVCVerificationStatusEnum() {

        assertEquals(VCVerificationStatus.fromValue("success"), VCVerificationStatus.SUCCESS);
        assertNull(VCVerificationStatus.fromValue("UNKNOWN_VALUE"));
        assertNull(VCVerificationStatus.fromValue(null));
        assertTrue(VCVerificationStatus.SUCCESS.isSuccess());
        assertTrue(VCVerificationStatus.ERROR.isFailure());
        assertEquals(VCVerificationStatus.EXPIRED.toString(), "EXPIRED");
    }

    @Test
    public void testVerifiableCredentialModelAndInnerClasses() {

        VerifiableCredential vc = new VerifiableCredential();
        vc.setId("vc1");
        vc.addContext("ctx1");
        vc.addType("VerifiableCredential");
        vc.addType("EmployeeCredential");
        vc.setIssuer("issuer");
        vc.setIssuerId("issuer-id");
        vc.setIssuerName("Issuer Name");

        Date now = new Date();
        vc.setIssuanceDate(now);
        vc.setExpirationDate(new Date(System.currentTimeMillis() + 60_000));

        Map<String, Object> subject = new HashMap<>();
        subject.put("id", "did:example:sub");
        subject.put("name", "Alice");
        vc.setCredentialSubject(subject);
        vc.setCredentialSubjectId("did:example:sub");

        VerifiableCredential.CredentialStatus status = new VerifiableCredential.CredentialStatus();
        status.setType("StatusList2021Entry");
        status.setStatusListIndex("10");
        status.setStatusListCredential("https://example.com/sl");
        vc.setCredentialStatus(status);

        VerifiableCredential.Proof proof = new VerifiableCredential.Proof();
        proof.setType("Ed25519Signature2020");
        proof.setVerificationMethod("did:web:issuer#key-1");
        proof.setProofValue("abc");
        vc.setProof(proof);

        vc.setFormat(VerifiableCredential.Format.JWT);
        vc.setRawCredential("h.p.s");
        vc.setJwtHeader("h");
        vc.setJwtPayload("p");
        vc.setJwtSignature("s");
        vc.setJwtClaims(subject);
        vc.addDisclosure("d1");
        vc.setKeyBindingJwt("kb");
        vc.setSignatureVerified(true);
        vc.setExpirationChecked(true);
        vc.setRevocationChecked(true);

        assertEquals(vc.getPrimaryType(), "EmployeeCredential");
        assertEquals(vc.getIssuerId(), "issuer-id");
        assertTrue(vc.hasCredentialStatus());
        assertTrue(vc.getCredentialStatus().isStatusList2021());
        assertTrue(vc.getProof().isEd25519());
        assertFalse(vc.getProof().isJsonWebSignature());
        assertTrue(vc.isJwt());
        assertFalse(vc.isJsonLd());
        assertFalse(vc.isSdJwt());
        assertFalse(vc.isExpired());
        assertEquals(vc.getClaim("name"), "Alice");
        assertTrue(vc.toString().contains("VerifiableCredential"));

        vc.setFormat(VerifiableCredential.Format.JSON_LD);
        assertTrue(vc.isJsonLd());
        vc.setFormat(VerifiableCredential.Format.SD_JWT);
        assertTrue(vc.isSdJwt());
    }

    @Test
    public void testVerifiablePresentationModel() {

        VerifiablePresentation vp = new VerifiablePresentation();
        vp.setId("vp1");
        vp.addContext("ctx");
        vp.addType("VerifiablePresentation");
        vp.setHolder("did:web:holder");
        vp.setIssuanceDate(new Date());
        vp.setNonce("nonce-1");

        VerifiableCredential vc = new VerifiableCredential();
        vc.setId("vc1");
        vp.addVerifiableCredential(vc);

        Map<String, Object> claims = new HashMap<>();
        claims.put("nonce", "nonce-jwt");
        vp.setJwtClaims(claims);

        vp.setFormat(VerifiablePresentation.Format.JWT);
        vp.setRawPresentation("raw");
        vp.setJwtHeader("h");
        vp.setJwtPayload("p");
        vp.setJwtSignature("s");
        vp.setSignatureVerified(true);
        vp.setHolderBindingVerified(true);

        assertTrue(vp.isJwt());
        assertFalse(vp.isJsonLd());
        assertEquals(vp.getCredentialCount(), 1);
        assertEquals(vp.getJwtNonce(), "nonce-jwt");

        vp.setFormat(VerifiablePresentation.Format.JSON_LD);
        assertTrue(vp.isJsonLd());
        assertTrue(vp.toString().contains("VerifiablePresentation"));
    }

    @Test
    public void testRevocationCheckResultModel() {

        RevocationCheckResult valid = RevocationCheckResult.valid();
        assertTrue(valid.isValid());
        assertFalse(valid.isRevoked());

        RevocationCheckResult skipped = RevocationCheckResult.skipped("disabled");
        assertTrue(skipped.isValid());

        RevocationCheckResult unknown = RevocationCheckResult.unknown("network");
        assertFalse(unknown.isValid());

        RevocationCheckResult built = new RevocationCheckResult.Builder()
                .status(RevocationCheckResult.Status.REVOKED)
                .statusPurpose("revocation")
                .statusListCredentialUrl("https://example.com/sl")
                .statusIndex(5)
                .message("revoked")
                .build();

        assertTrue(built.isRevoked());
        assertTrue(built.isRevokedOrSuspended());
        built.setStatus(RevocationCheckResult.Status.SUSPENDED);
        assertTrue(built.isSuspended());
        built.setCached(true);
        built.setCheckedAt(123L);
        assertTrue(built.isCached());
        assertEquals(built.getCheckedAt(), 123L);
        assertTrue(built.toString().contains("status="));
    }
}
