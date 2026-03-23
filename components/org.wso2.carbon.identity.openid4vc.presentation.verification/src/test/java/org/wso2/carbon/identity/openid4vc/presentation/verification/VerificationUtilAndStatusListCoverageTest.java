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
import com.google.gson.JsonParser;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl.StatusListServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationUtil;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class VerificationUtilAndStatusListCoverageTest {

    @Test
    public void testVerificationUtilBasicHelpers() throws Exception {

        assertEquals(VerificationUtil.removeCRLF("a\nb\rc"), "a_b_c");
        assertNull(VerificationUtil.removeCRLF(null));

        assertNotNull(VerificationUtil.createHash("abc"));
        assertNotNull(VerificationUtil.createHash("abc", "SHA-384"));

        boolean invalidAlg = false;
        try {
            VerificationUtil.createHash("abc", "NOPE");
        } catch (NoSuchAlgorithmException e) {
            invalidAlg = true;
        }
        assertTrue(invalidAlg);

        assertEquals(VerificationUtil.resolveHashAlgorithm(null), "SHA-256");
        assertEquals(VerificationUtil.resolveHashAlgorithm("sha-256"), "SHA-256");
        assertEquals(VerificationUtil.resolveHashAlgorithm("sha-384"), "SHA-384");
        assertEquals(VerificationUtil.resolveHashAlgorithm("sha-512"), "SHA-512");

        boolean invalidSdAlg = false;
        try {
            VerificationUtil.resolveHashAlgorithm("md5");
        } catch (NoSuchAlgorithmException e) {
            invalidSdAlg = true;
        }
        assertTrue(invalidSdAlg);

        assertEquals(VerificationUtil.hashDocument("hello", "SHA-256").length, 32);
        assertEquals(VerificationUtil.normalizeContentType("application/jwt; charset=UTF-8"), "application/jwt");
        assertNull(VerificationUtil.normalizeContentType(null));
        assertNotNull(VerificationUtil.parseDate("2025-01-01T10:10:10Z"));
        assertNotNull(VerificationUtil.parseDate("2025-01-01"));
        assertNull(VerificationUtil.parseDate("bad-date"));
        assertNull(VerificationUtil.parseDate(""));
    }

    @Test
    public void testVerificationUtilJsonJwtAndClaims() throws Exception {

        Object parsed = VerificationUtil.parseJsonElement(
            JsonParser.parseString("{\"k\":1,\"b\":true,\"a\":[\"x\"]}"));
        assertTrue(parsed instanceof Map);

        String payloadJson = "{\"nonce\":\"n1\",\"aud\":\"aud1\",\"vp\":{\"verifiableCredential\":" +
            "[{\"credentialSubject\":{\"name\":\"Alice\",\"age\":30}}]}}";
        String part = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        Map<String, Object> jwtPart = VerificationUtil.parseJwtPart(part);
        assertEquals(jwtPart.get("nonce"), "n1");

        String jwtVp = buildJwt("{\"alg\":\"HS256\"}", payloadJson);
        assertEquals(VerificationUtil.detectFormat(jwtVp), VerificationUtil.CONTENT_TYPE_JWT);
        assertEquals(VerificationUtil.detectFormat("header.payload.signature~"), VerificationUtil.CONTENT_TYPE_SD_JWT);
        assertEquals(VerificationUtil.detectFormat("{\"vp\":{}}"), VerificationUtil.CONTENT_TYPE_VC_LD_JSON);

        String[] nonceAud = VerificationUtil.extractNonceAndAudienceFromVpToken(jwtVp, "jwt_vp");
        assertEquals(nonceAud[0], "n1");
        assertEquals(nonceAud[1], "aud1");

        String ldpVp = "{\"proof\":{\"challenge\":\"c1\",\"domain\":\"d1\"}}";
        String[] ldpNonceAud = VerificationUtil.extractNonceAndAudienceFromVpToken(ldpVp, "ldp_vp");
        assertEquals(ldpNonceAud[0], "c1");
        assertEquals(ldpNonceAud[1], "d1");

        String kbPayload = "{\"nonce\":\"sn\",\"aud\":[\"sa\"]}";
        String sd = "issuer.jwt~disclosure~" + buildJwt("{\"alg\":\"HS256\"}", kbPayload);
        String[] sdNonceAud = VerificationUtil.extractNonceAndAudienceFromVpToken(
            sd, VerificationUtil.NORMALIZED_VC_SD_JWT);
        assertEquals(sdNonceAud[0], "sn");
        assertEquals(sdNonceAud[1], "sa");

        Map<String, Object> claimsJwt = VerificationUtil.extractClaimsFromVpToken(jwtVp, "jwt_vp");
        assertEquals(claimsJwt.get("name"), "Alice");

        String jsonVp = "{\"verifiableCredential\":{\"credentialSubject\":{\"city\":\"Colombo\"}}}";
        Map<String, Object> claimsJson = VerificationUtil.extractClaimsFromVpToken(jsonVp, "ldp_vp");
        assertEquals(claimsJson.get("city"), "Colombo");

        JsonObject vpData = JsonParser.parseString(
                "{\"vp\":{\"verifiableCredential\":[{\"credentialSubject\":{\"x\":\"y\",\"num\":2}}]}}")
                .getAsJsonObject();
        Map<String, Object> flattened = new java.util.HashMap<>();
        VerificationUtil.flattenVpCredentialSubject(vpData, flattened);
        assertEquals(flattened.get("x"), "y");
        assertEquals(flattened.get("num").toString(), "2");
    }

    @Test
    public void testVerificationUtilSubmissionAndHost() throws Exception {

        String submission = "{\"descriptor_map\":[{\"id\":\"id1\",\"format\":\"vc_sd_jwt\",\"path\":\"$\"}]}";
        assertEquals(VerificationUtil.extractFormatFromSubmission(submission), VerificationUtil.NORMALIZED_VC_SD_JWT);

        boolean failedMissing = false;
        try {
            VerificationUtil.extractFormatFromSubmission("{\"descriptor_map\":[]}");
        } catch (CredentialVerificationException e) {
            failedMissing = true;
        }
        assertTrue(failedMissing);

        boolean failedInvalid = false;
        try {
            VerificationUtil.extractFormatFromSubmission("not-json");
        } catch (CredentialVerificationException e) {
            failedInvalid = true;
        }
        assertTrue(failedInvalid);

        assertEquals(VerificationUtil.extractHost("did:web:example.com:user"), "example.com");
        assertEquals(VerificationUtil.extractHost("https://example.org/path"), "example.org");
        assertEquals(VerificationUtil.extractHost("LOCALHOST"), "localhost");
        assertNull(VerificationUtil.extractHost(null));
    }

    @Test
    public void testStatusListServiceBranchesAndBitChecks() throws Exception {

        StatusListServiceImpl service = new StatusListServiceImpl();
        service.setRevocationCheckEnabled(false);
        RevocationCheckResult disabled =
            service.checkRevocationStatus(new VerifiableCredential.CredentialStatus());
        assertTrue(disabled.isValid());

        service.setRevocationCheckEnabled(true);
        RevocationCheckResult noStatus = service.checkRevocationStatus(null);
        assertTrue(noStatus.isValid());

        VerifiableCredential.CredentialStatus unsupported = new VerifiableCredential.CredentialStatus();
        unsupported.setType("OtherType");
        RevocationCheckResult unknown = service.checkRevocationStatus(unsupported);
        assertFalse(unknown.isValid());

        VerifiableCredential.CredentialStatus missingUrl = new VerifiableCredential.CredentialStatus();
        missingUrl.setType("StatusList2021Entry");
        missingUrl.setStatusListIndex("0");
        RevocationCheckResult missingUrlResult = service.checkRevocationStatus(missingUrl);
        assertFalse(missingUrlResult.isValid());

        VerifiableCredential.CredentialStatus invalidIndex = new VerifiableCredential.CredentialStatus();
        invalidIndex.setType("BitstringStatusListEntry");
        invalidIndex.setStatusListCredential("https://example.com/sl");
        invalidIndex.setStatusListIndex("abc");
        RevocationCheckResult invalidIndexResult = service.checkRevocationStatus(invalidIndex);
        assertFalse(invalidIndexResult.isValid());

        assertFalse(service.isBitSet(null, 0));
        assertFalse(service.isBitSet(new byte[0], 0));
        assertTrue(service.isBitSet(new byte[]{(byte) 0x80}, 0));
        assertTrue(service.isBitSet(new byte[]{(byte) 0x01}, 7));
        assertFalse(service.isBitSet(new byte[]{(byte) 0x00}, 0));
        assertFalse(service.isBitSet(new byte[]{(byte) 0x00}, 8));

        service.clearCache();
        assertTrue(service.isRevocationCheckEnabled());
    }

    @Test
    public void testStatusListServiceDecodeAndErrorPathsViaReflection() throws Exception {

        StatusListServiceImpl service = new StatusListServiceImpl();

        boolean invalidUrlError = false;
        try {
            service.fetchAndDecodeStatusList("ftp://invalid");
        } catch (RevocationCheckException e) {
            invalidUrlError = true;
        }
        assertTrue(invalidUrlError);

        boolean checkStatusListError = false;
        try {
            service.checkStatusList2021("invalid-url", 0, "revocation");
        } catch (RevocationCheckException e) {
            checkStatusListError = true;
        }
        assertTrue(checkStatusListError);

        Method extractEncodedList = StatusListServiceImpl.class
                .getDeclaredMethod("extractEncodedList", String.class);
        extractEncodedList.setAccessible(true);

        String encoded = toEncodedGzip(new byte[]{(byte) 0x80});
        String validCredential = "{\"credentialSubject\":{\"encodedList\":\"" + encoded + "\"}}";
        String extracted = (String) extractEncodedList.invoke(service, validCredential);
        assertEquals(extracted, encoded);

        boolean missingEncodedList = false;
        try {
            extractEncodedList.invoke(service, "{\"credentialSubject\":{}} ");
        } catch (Exception e) {
            missingEncodedList = true;
        }
        assertTrue(missingEncodedList);

        Method decodeStatusList = StatusListServiceImpl.class
            .getDeclaredMethod("decodeStatusList", String.class);
        decodeStatusList.setAccessible(true);
        byte[] decoded = (byte[]) decodeStatusList.invoke(service, encoded);
        assertEquals(decoded.length, 1);

        boolean decodeError = false;
        try {
            decodeStatusList.invoke(service, "%%%invalid%%%base64");
        } catch (Exception e) {
            decodeError = true;
        }
        assertTrue(decodeError);

        Class<?> nestedClass = Class.forName(StatusListServiceImpl.class.getName() + "$CachedStatusList");
        Constructor<?> constructor = nestedClass.getDeclaredConstructor(byte[].class);
        constructor.setAccessible(true);
        Object cacheEntry = constructor.newInstance(new byte[]{1});
        Method getBitstring = nestedClass.getDeclaredMethod("getBitstring");
        getBitstring.setAccessible(true);
        assertEquals(((byte[]) getBitstring.invoke(cacheEntry))[0], 1);
        Method isExpired = nestedClass.getDeclaredMethod("isExpired");
        isExpired.setAccessible(true);
        assertFalse((boolean) isExpired.invoke(cacheEntry));
    }

    @Test
    public void testExceptionConstructorsAndFactories() {

        CredentialVerificationException e1 = new CredentialVerificationException("msg");
        assertEquals(e1.getMessage(), "msg");

        CredentialVerificationException e2 =
            new CredentialVerificationException(VCVerificationStatus.INVALID, "bad");
        assertEquals(e2.getVerificationStatus(), VCVerificationStatus.INVALID);

        CredentialVerificationException e3 =
            new CredentialVerificationException(VCVerificationStatus.REVOKED, 2, "revoked");
        assertEquals(e3.getVcIndex(), 2);

        CredentialVerificationException e4 = new CredentialVerificationException("m", new RuntimeException("c"));
        assertNotNull(e4.getCause());

        RevocationCheckException r1 = new RevocationCheckException("r1");
        assertEquals(r1.getMessage(), "r1");

        RevocationCheckException r2 = RevocationCheckException.networkError(
            "https://example.com/sl", new RuntimeException("n"));
        assertTrue(r2.getMessage().contains("https://example.com/sl"));

        RevocationCheckException r3 = RevocationCheckException.invalidStatusList("https://example.com/sl", "bad-json");
        assertTrue(r3.getMessage().contains("bad-json"));

        RevocationCheckException r4 = RevocationCheckException.decodingError(new RuntimeException("decode"));
        assertTrue(r4.getMessage().contains("decode"));

        VPSubmissionValidationException vpe = new VPSubmissionValidationException("invalid-submission");
        assertEquals(vpe.getMessage(), "invalid-submission");
    }

    private static String buildJwt(String headerJson, String payloadJson) {

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("sig".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + signature;
    }

    private static String toEncodedGzip(byte[] input) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(input);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}
