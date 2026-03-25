package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class ServletUtilTest {

    @Mock
    private HttpServletRequest request;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        identityTenantUtilMockedStatic = Mockito.mockStatic(IdentityTenantUtil.class);
    }

    @AfterMethod
    public void tearDown() {
        identityTenantUtilMockedStatic.close();
    }

    @Test
    public void testGetTenantIdFromContext() {
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);

        int tenantId = ServletUtil.getTenantId(request);
        assertEquals(tenantId, -1234);
    }

    @Test
    public void testGetTenantIdFromAttribute() {
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(null);
        when(request.getAttribute("tenantDomain")).thenReturn("test.com");
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId("test.com")).thenReturn(1);

        int tenantId = ServletUtil.getTenantId(request);
        assertEquals(tenantId, 1);
    }

    @Test
    public void testGetTenantIdDefault() {
        identityTenantUtilMockedStatic.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(null);
        when(request.getAttribute("tenantDomain")).thenReturn(null);

        int tenantId = ServletUtil.getTenantId(request);
        assertEquals(tenantId, -1234);
    }

    @Test
    public void testGetValidatedAlphaNumParameter() throws IOException {
        String body = "request_id=req123&timeout=10&long_poll=true";
        ServletInputStream inputStream = new MockServletInputStream(body.getBytes());
        when(request.getInputStream()).thenReturn(inputStream);

        assertEquals(ServletUtil.getValidatedAlphaNumParameter(request, "request_id"), "req123");
        // Cached value test
        when(request.getAttribute("openid4vp.parsedParams")).thenReturn(new java.util.HashMap<String, String>() {{
            put("request_id", "req123");
        }});
        assertEquals(ServletUtil.getValidatedAlphaNumParameter(request, "request_id"), "req123");
    }

    @Test
    public void testGetValidatedAlphaNumParameterInvalid() throws IOException {
        // Test sanitization and validation
        String body = "request_id=req\r\n123";
        ServletInputStream inputStream = new MockServletInputStream(body.getBytes());
        when(request.getInputStream()).thenReturn(inputStream);

        assertEquals(ServletUtil.getValidatedAlphaNumParameter(request, "request_id"), "req__123");
    }

    @Test
    public void testGetValidatedAlphaNumParameterLongPoll() throws IOException {
        String body = "long_poll=invalid";
        ServletInputStream inputStream = new MockServletInputStream(body.getBytes());
        when(request.getInputStream()).thenReturn(inputStream);

        assertNull(ServletUtil.getValidatedAlphaNumParameter(request, "long_poll"));
    }

    private static class MockServletInputStream extends ServletInputStream {
        private final java.io.InputStream inputStream;

        public MockServletInputStream(byte[] bytes) {
            this.inputStream = new ByteArrayInputStream(bytes);
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }

        public boolean isFinished() {
            return false;
        }

        public boolean isReady() {
            return true;
        }

        public void setReadListener(javax.servlet.ReadListener readListener) {
        }
    }
}
