package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class ModelTest {

    @Test
    public void testVPRequest() {
        VPRequest request = new VPRequest.Builder()
                .requestId("id1")
                .nonce("nonce1")
                .clientId("client1")
                .tenantId(-1234)
                .status(VPRequestStatus.ACTIVE)
                .build();
        
        assertEquals(request.getRequestId(), "id1");
        assertEquals(request.getNonce(), "nonce1");
        assertEquals(request.getStatus(), VPRequestStatus.ACTIVE);
    }

    @Test
    public void testVPSubmission() {
        VPSubmission submission = new VPSubmission();
        submission.setRequestId("req1");
        submission.setVpToken("token1");
        
        assertEquals(submission.getRequestId(), "req1");
        assertEquals(submission.getVpToken(), "token1");
    }
}
