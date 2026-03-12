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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import com.google.gson.JsonObject;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class VPResponseHandlerTest {

    private VPResponseHandler vpResponseHandler;
    private VPRequest vpRequest;

    @BeforeMethod
    public void setUp() {
        vpResponseHandler = new VPResponseHandler();
        vpRequest = new VPRequest.Builder()
                .requestId("test-request-id")
                .nonce("test-nonce")
                .clientId("test-client-id")
                .build();
    }

    @Test
    public void testProcessSubmissionNull() {
        assertThrows(VPSubmissionValidationException.class, () -> 
            vpResponseHandler.processSubmission(null, vpRequest));
    }

    @Test
    public void testProcessSubmissionWithError() throws VPException {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setError("access_denied");
        submission.setErrorDescription("User rejected the request");

        VPResponseHandler.ValidationResult result = vpResponseHandler.processSubmission(submission, vpRequest);

        assertNotNull(result);
        assertEquals(result.getStatus(), VCVerificationStatus.INVALID);
        assertEquals(result.getErrorCode(), "access_denied");
        assertEquals(result.getErrorDescription(), "User rejected the request");
        assertFalse(result.isValid());
    }

    @Test
    public void testProcessSubmissionStateMismatch() throws VPException {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("wrong-state");

        VPResponseHandler.ValidationResult result = vpResponseHandler.processSubmission(submission, vpRequest);

        assertNotNull(result);
        assertEquals(result.getStatus(), VCVerificationStatus.INVALID);
        assertEquals(result.getErrorCode(), "invalid_request");
        assertTrue(result.getErrorDescription().contains("State parameter mismatch"));
    }

    @Test
    public void testProcessSubmissionMissingToken() {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("test-request-id");

        assertThrows(VPSubmissionValidationException.class, () -> 
            vpResponseHandler.processSubmission(submission, vpRequest));
    }

    @Test
    public void testProcessJwtVPTokenSuccess() throws VPException {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("test-request-id");
        
        // Build a mock JWT
        JsonObject header = new JsonObject();
        header.addProperty("alg", "RS256");
        header.addProperty("typ", "JWT");

        JsonObject payload = new JsonObject();
        payload.addProperty("iss", "https://self-issued.me/v2");
        payload.addProperty("aud", "test-client-id");
        payload.addProperty("nonce", "test-nonce");
        payload.addProperty("exp", (System.currentTimeMillis() / 1000) + 3600);
        payload.addProperty("jti", "test-vp-id");

        JsonObject vp = new JsonObject();
        vp.addProperty("id", "test-presentation-id");
        payload.add("vp", vp);

        String jwt = encode(header) + "." + encode(payload) + ".signature";
        submission.setVpToken(jwt);

        VPResponseHandler.ValidationResult result = vpResponseHandler.processSubmission(submission, vpRequest);

        assertNotNull(result);
        assertEquals(result.getStatus(), VCVerificationStatus.SUCCESS);
        assertEquals(result.getPresentationId(), "test-presentation-id");
        assertTrue(result.isValid());
    }

    @Test
    public void testProcessJsonVPTokenSuccess() throws VPException {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("test-request-id");
        
        JsonObject vp = new JsonObject();
        vp.addProperty("type", "VerifiablePresentation");
        vp.addProperty("id", "test-presentation-id");
        
        JsonObject proof = new JsonObject();
        proof.addProperty("challenge", "test-nonce");
        proof.addProperty("domain", "test-client-id");
        vp.add("proof", proof);

        submission.setVpToken(vp.toString());

        VPResponseHandler.ValidationResult result = vpResponseHandler.processSubmission(submission, vpRequest);

        assertNotNull(result);
        assertEquals(result.getStatus(), VCVerificationStatus.SUCCESS);
        assertEquals(result.getPresentationId(), "test-presentation-id");
        assertTrue(result.isValid());
    }

    @Test
    public void testProcessJwtVPTokenExpired() throws VPException {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("test-request-id");
        
        JsonObject payload = new JsonObject();
        payload.addProperty("nonce", "test-nonce");
        payload.addProperty("aud", "test-client-id");
        payload.addProperty("exp", (System.currentTimeMillis() / 1000) - 100); // Expired

        String jwt = encode(new JsonObject()) + "." + encode(payload) + ".sig";
        submission.setVpToken(jwt);

        VPResponseHandler.ValidationResult result = vpResponseHandler.processSubmission(submission, vpRequest);
        assertEquals(result.getStatus(), VCVerificationStatus.EXPIRED);
    }

    private String encode(JsonObject json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.toString().getBytes(StandardCharsets.UTF_8));
    }
}
