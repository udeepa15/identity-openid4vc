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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDResolverService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.StatusListService;

import java.util.Date;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VCVerificationServiceTest {

    private VCVerificationServiceImpl vcVerificationService;

    @Mock
    private DIDResolverService didResolverService;

    @Mock
    private StatusListService statusListService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        vcVerificationService = new VCVerificationServiceImpl(didResolverService, statusListService);
    }

    @Test
    public void testParseJwtCredential() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUuY29tIiwic3ViIjoiZGlkOmtleTp6NkxreFdyN3NLUXlTdWJzR005clAxdzVRTXpBOU" +
                "JUVG5rZ1VqSFF6UzZqTmdzWSIsImp0aSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY3JlZGVudGlhbHMvMTIzNDUiLCJuYmYiOjE" +
                "3MjIzMTI0MDAsImV4cCI6MTkyMjMxMjQwMCwiaWF0IjoxNzIyMzEyNDAwLCJ2YyI6eyJAd29udGV4dCI6WyJodHRwczovL3d3" +
                "dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wb" +
                "GUvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkV4YW1wbGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdW" +
                "JqZWN0Ijp7ImlkIjoiZGlkOmtleTp6NkxreFdyN3NLUXlTdWJzR005clAxdzVRTXpBOUJUVG5rZ1VqSFF6UzZqTmdzWSIsImZ" +
                "hbWlseU5hbWUiOiJEb2UiLCJnaXZlbk5hbWUiOiJKb2huIn19fQ.signature";

        VerifiableCredential credential = vcVerificationService.parseCredential(jwt, "application/jwt");

        assertNotNull(credential);
        assertEquals(credential.getFormat(), VerifiableCredential.Format.JWT);
        assertEquals(credential.getIssuerId(), "did:web:example.com");
        assertEquals(credential.getId(), "https://example.com/credentials/12345");
        assertNotNull(credential.getExpirationDate());
        assertTrue(credential.getType().contains("ExampleCredential"));
    }

    @Test
    public void testParseSdJwtCredential() throws Exception {
        String sdJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUuY29tIiwic3ViIjoiZGlkOmtleTp6NkxreFdyN3NLUXlTdWJzR005clAxdzVRTXpBOU" +
                "JUVG5rZ1VqSFF6UzZqTmdzWSIsImV4cCI6MTkyMjMxMjQwMH0.sig" +
                "~WyJzYWx0MSIsImZhbWlseU5hbWUiLCJEb2UiXQ" +
                "~WyJzYWx0MiIsImdpdmVuTmFtZSIsIkpvaG4iXQ";

        VerifiableCredential credential = vcVerificationService.parseCredential(sdJwt, "application/vc+sd-jwt");

        assertNotNull(credential);
        assertEquals(credential.getFormat(), VerifiableCredential.Format.SD_JWT);
        assertEquals(credential.getDisclosures().size(), 2);
        assertNotNull(credential.getCredentialSubject());
        assertEquals(credential.getCredentialSubject().get("givenName"), "John");
        assertEquals(credential.getCredentialSubject().get("familyName"), "Doe");
    }

    @Test
    public void testParseJsonLdCredential() throws Exception {
        String jsonLd = "{\n" +
                "  \"@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\",\n" +
                "    \"https://www.w3.org/2018/credentials/examples/v1\"\n" +
                "  ],\n" +
                "  \"id\": \"http://example.edu/credentials/1872\",\n" +
                "  \"type\": [\"VerifiableCredential\", \"AlumniCredential\"],\n" +
                "  \"issuer\": \"https://example.edu/issuers/5650\",\n" +
                "  \"issuanceDate\": \"2010-01-01T19:23:24Z\",\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"did:example:ebfeb1f712ebc6f1c276e12ec21\",\n" +
                "    \"alumniOf\": {\n" +
                "      \"id\": \"did:example:c276e12ec21ebfeb1f712ebc6f1\",\n" +
                "      \"name\": \"Example University\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"proof\": {\n" +
                "    \"type\": \"Ed25519Signature2018\",\n" +
                "    \"created\": \"2017-06-18T21:19:10Z\",\n" +
                "    \"proofPurpose\": \"assertionMethod\",\n" +
                "    \"verificationMethod\": \"https://example.edu/issuers/5650#key-1\",\n" +
                "    \"jws\": \"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature\"\n" +
                "  }\n" +
                "}";

        VerifiableCredential credential = vcVerificationService.parseCredential(jsonLd, "application/vc+ld+json");

        assertNotNull(credential.getFormat());
        assertEquals(credential.getFormat(), VerifiableCredential.Format.JSON_LD);
        assertEquals(credential.getIssuerId(), "https://example.edu/issuers/5650");
        assertTrue(credential.getType().contains("AlumniCredential"));
        assertNotNull(credential.getProof());
        assertEquals(credential.getProof().getType(), "Ed25519Signature2018");
    }

    @Test
    public void testVerifyExpiredCredential() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjEwMDAwMDAwMDB9.sig"; // Expired in year 2001
        
        VCVerificationResultDTO result = vcVerificationService.verify(jwt, "application/jwt");
        assertEquals(result.getVerificationStatusEnum(), VCVerificationStatus.EXPIRED);
    }

    @Test
    public void testIsExpired() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setExpirationDate(new Date(System.currentTimeMillis() - 10000));
        assertTrue(vcVerificationService.isExpired(credential));
    }
}
