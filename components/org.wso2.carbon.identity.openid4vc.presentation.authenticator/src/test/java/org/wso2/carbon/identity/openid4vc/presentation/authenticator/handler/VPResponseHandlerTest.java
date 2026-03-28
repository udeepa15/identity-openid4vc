package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class VPResponseHandlerTest {

    private VPResponseHandler handler;

    @BeforeMethod
    public void setUp() {
        handler = new VPResponseHandler();
    }

    @Test
    public void testProcessSubmissionError() throws Exception {
        Map<String, String> submission = new HashMap<>();
        submission.put(OpenID4VPConstants.ResponseParams.ERROR, "invalid_request");
        submission.put(OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION, "test error");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, null);
        assertFalse(result.isValid());
        assertEquals(result.getErrorCode(), "invalid_request");
    }

    @Test
    public void testProcessSubmissionStateMismatch() throws Exception {
        Map<String, String> submission = new HashMap<>();
        submission.put(OpenID4VPConstants.ResponseParams.STATE, "wrong-state");
        VPRequest vpRequest = new VPRequest.Builder().requestId("correct-state").build();
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertEquals(result.getStatus(), VerificationResult.VerificationStatus.FAILED);
    }

    @Test
    public void testProcessValidSubmission() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId("state123")
                .nonce("nonce123")
                .clientId("client123")
                .build();
        
        Map<String, String> submission = new HashMap<>();
        submission.put(OpenID4VPConstants.ResponseParams.STATE, "state123");
        submission.put(OpenID4VPConstants.ResponseParams.VP_TOKEN, "some-token");
        
        VPResponseHandler.ValidationResult result = handler.processSubmission(submission, vpRequest);
        assertTrue(result.isValid());
    }

    @Test
    public void testProcessMissingVpToken() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("state123").build();
        Map<String, String> submission = new HashMap<>();
        submission.put(OpenID4VPConstants.ResponseParams.STATE, "state123");
        
        try {
            handler.processSubmission(submission, vpRequest);
            assertTrue(false, "Should have thrown exception for missing vp_token");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("VP token is missing"));
        }
    }
}
