package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for presentation authenticator exceptions.
 */
public class ExceptionTest {

    @DataProvider(name = "exceptionDataProvider")
    public Object[][] exceptionDataProvider() {
        return new Object[][]{
                {new VPAuthenticatorException("generic error")},
                {new VPAuthenticatorClientException("client error")},
                {new VPAuthenticatorServerException("server error")},
                {new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST, "invalid request")},
                {new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR, "internal error")}
        };
    }

    @Test(dataProvider = "exceptionDataProvider")
    public void testExceptionMessage(VPAuthenticatorException exception) {
        assertNotNull(exception.getMessage());
    }

    @Test
    public void testExceptionWithErrorCode() {
        VPAuthenticatorClientException ex = new VPAuthenticatorClientException(
                VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND, "not found");
        assertEquals(ex.getCode(), VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode());
        assertEquals(ex.getMessage(), "not found");
    }
}
