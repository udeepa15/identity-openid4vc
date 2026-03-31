package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;

import java.io.IOException;
import java.lang.reflect.Field;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RequestUriServletTest {

    private RequestUriServlet servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private VPRequestService vpRequestService;

    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<VPServiceDataHolder> mockedVPServiceDataHolder;

    @BeforeMethod
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        servlet = new RequestUriServlet();
        
        mockedIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedVPServiceDataHolder = Mockito.mockStatic(VPServiceDataHolder.class);
        mockedVPServiceDataHolder.when(VPServiceDataHolder::getVPRequestService).thenReturn(vpRequestService);
        
        // Always mock output stream to avoid NPE in sendErrorResponse
        ServletOutputStream outputStream = new MockServletOutputStream();
        when(response.getOutputStream()).thenReturn(outputStream);
        
        // Inject mock service
        setPrivateField(servlet, "vpRequestService", vpRequestService);
    }

    @AfterMethod
    public void tearDown() {
        mockedIdentityTenantUtil.close();
        mockedVPServiceDataHolder.close();
    }

    @Test
    public void testDoGet() throws Exception {
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(request.getPathInfo()).thenReturn("/req123");
        
        when(vpRequestService.getRequestJwt("req123", -1234)).thenReturn("eyJdummy-jwt");
        
        servlet.doGet(request, response);
        
        verify(response).setContentType("application/oauth-authz-req+jwt");
        verify(response).setStatus(HttpServletResponse.SC_OK);
    }

    @Test
    public void testDoGetMissingId() throws Exception {
        when(request.getPathInfo()).thenReturn(null);
        
        servlet.doGet(request, response);
        
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    public void testDoGetNotFound() throws Exception {
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(request.getPathInfo()).thenReturn("/non-existent");
        
        when(vpRequestService.getRequestJwt("non-existent", -1234))
                .thenThrow(new VPRequestNotFoundException("not found"));
        
        servlet.doGet(request, response);
        
        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    private static class MockServletOutputStream extends ServletOutputStream {
        private final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        @Override
        public void write(int b) throws IOException {
            baos.write(b);
        }

        public boolean isReady() {
            return true;
        }

        public void setWriteListener(javax.servlet.WriteListener writeListener) {
        }
    }
    private void setPrivateField(Object obj, String fieldName, Object value) throws IOException {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IOException(e);
        }
    }
}
