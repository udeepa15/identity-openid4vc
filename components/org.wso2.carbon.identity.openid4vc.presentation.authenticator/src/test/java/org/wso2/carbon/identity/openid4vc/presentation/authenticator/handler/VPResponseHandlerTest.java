package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VPResponseHandlerTest {

    private VPResponseHandler handler;

    @BeforeMethod
    public void setUp() {
        handler = new VPResponseHandler();
    }

    @Test
    public void testProcessSubmissionError() throws Exception {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setError("invalid_request");
        submission.setErrorDescription("test error");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, null);
        assertFalse(result.isValid());
        assertEquals(result.getErrorCode(), "invalid_request");
    }

    @Test
    public void testProcessSubmissionStateMismatch() throws Exception {
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("wrong-state");
        VPRequest vpRequest = new VPRequest.Builder().requestId("correct-state").build();
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertEquals(result.getStatus(), VCVerificationStatus.INVALID);
    }

    @Test
    public void testProcessJwtVPToken() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId("state123")
                .nonce("nonce123")
                .clientId("client123")
                .build();
        
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        // Construct a simple JWT
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().encodeToString(
                "{\"nonce\":\"nonce123\",\"aud\":\"client123\",\"jti\":\"id123\",\"vp\":{\"verifiableCredential\":[]}}"
                .getBytes(StandardCharsets.UTF_8));
        submission.setVpToken(header + "." + payload + ".signature");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
        assertEquals(result.getPresentationId(), "id123");
    }

    @Test
    public void testProcessJsonVPToken() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId("state123")
                .nonce("nonce123")
                .clientId("client123")
                .build();
        
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        String jsonToken = "{\"type\":\"VerifiablePresentation\",\"id\":\"id456\"," +
                "\"proof\":{\"challenge\":\"nonce123\",\"domain\":\"client123\"},\"verifiableCredential\":[]}";
        submission.setVpToken(jsonToken);
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
        assertEquals(result.getPresentationId(), "id456");
    }

    @Test
    public void testExtractClaims() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId("state123")
                .build();
        
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        // JWT with a credential containing claims
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String credPayload = Base64.getUrlEncoder().encodeToString(
            "{\"vc\":{\"credentialSubject\":{\"given_name\":\"John\",\"address\":{\"city\":\"New York\"}}}}"
            .getBytes(StandardCharsets.UTF_8));
        String credential = "header." + credPayload + ".sig";
        
        String payload = Base64.getUrlEncoder().encodeToString(
                ("{\"jti\":\"id123\",\"vp\":{\"verifiableCredential\":[\"" + credential + "\"]}}")
                .getBytes(StandardCharsets.UTF_8));
        submission.setVpToken(header + "." + payload + ".signature");

        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
        assertNotNull(result.getVerifiedClaims());
        assertEquals(result.getVerifiedClaims().get("given_name"), "John");
        assertEquals(result.getVerifiedClaims().get("address.city"), "New York");
    }

    @Test
    public void testProcessMalformedJwt() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").build();
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        submission.setVpToken("not-a-jwt");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertFalse(result.isValid());
        assertEquals(result.getErrorCode(), "invalid_request");
    }

    @Test
    public void testProcessJwtMissingVp() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").build();
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().encodeToString("{\"jti\":\"id123\"}".getBytes(StandardCharsets.UTF_8));
        submission.setVpToken(header + "." + payload + ".sig");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertFalse(result.isValid());
    }

    @Test
    public void testProcessJsonVPTokenInvalidJson() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").build();
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        submission.setVpToken("{invalid-json}");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertFalse(result.isValid());
    }

    @Test
    public void testExtractClaimsComplex() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").build();
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        // Single credential as JSON object (not array) if supported
        String jsonToken = "{\"type\":\"VerifiablePresentation\",\"jti\":\"id123\"," +
                "\"vp\":{\"verifiableCredential\":{\"vc\":{\"credentialSubject\":{\"nested\":{\"key\":\"val\"}}}}}}";
        // Actually the class expects verifiableCredential to be an array or string
        
        // Test with a credential that is just a JWT string in the array
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String credPayload = Base64.getUrlEncoder().encodeToString("{\"vc\":{\"credentialSubject\":{\"a\":\"b\"}}}"
                .getBytes(StandardCharsets.UTF_8));
        String credential = "h." + credPayload + ".s";
        
        String payload = Base64.getUrlEncoder().encodeToString(
                ("{\"jti\":\"id123\",\"vp\":{\"verifiableCredential\":[\"" + credential + "\"]}}")
                        .getBytes(StandardCharsets.UTF_8));
        submission.setVpToken(header + "." + payload + ".signature");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
        assertEquals(result.getVerifiedClaims().get("a"), "b");
    }

    @Test
    public void testProcessJsonCredential() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").nonce("n1").clientId("c1").build();
        VPSubmissionDTO submission = new VPSubmissionDTO();
        submission.setState("state123");
        
        String jsonToken = "{\"type\":\"VerifiablePresentation\",\"id\":\"id1\"," +
                "\"verifiableCredential\":[{\"id\":\"c1\",\"type\":[\"VerifiableCredential\"]," +
                "\"credentialSubject\":{\"name\":\"John\"}}]," +
                "\"proof\":{\"challenge\":\"n1\",\"domain\":\"c1\"}}";
        submission.setVpToken(jsonToken);
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
        assertEquals(result.getVerifiedClaims().get("name"), "John");
    }
}
