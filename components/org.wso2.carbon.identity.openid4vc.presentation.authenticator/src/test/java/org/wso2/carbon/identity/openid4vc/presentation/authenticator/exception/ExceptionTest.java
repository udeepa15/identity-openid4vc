package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class ExceptionTest {

    @Test
    public void testExceptions() {
        VPTokenExpiredException ex = new VPTokenExpiredException("expired");
        assertEquals(ex.getMessage(), "expired");
    }
}
