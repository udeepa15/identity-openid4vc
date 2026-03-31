package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;

import java.io.IOException;
import java.lang.reflect.Field;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class WellKnownDIDServletTest {

    private WellKnownDIDServlet servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private DIDDocumentService didDocumentService;

    private MockedStatic<IdentityTenantUtil> mockedTenantUtil;
    private MockedStatic<OpenID4VPUtil> mockedOpenID4VPUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        servlet = new WellKnownDIDServlet();
        
        mockedTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedOpenID4VPUtil = Mockito.mockStatic(OpenID4VPUtil.class);
        
        // Mock output stream
        ServletOutputStream outputStream = new MockServletOutputStream();
        when(response.getOutputStream()).thenReturn(outputStream);
        
        // Inject mock service
        setPrivateField(servlet, "didDocumentService", didDocumentService);
    }

    @AfterMethod
    public void tearDown() {
        mockedTenantUtil.close();
        mockedOpenID4VPUtil.close();
    }

    @Test
    public void testDoGet() throws Exception {
        mockedTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        mockedTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedOpenID4VPUtil.when(() -> OpenID4VPUtil.getTenantAwareBaseUrl("carbon.super"))
                .thenReturn("https://localhost:9443/");
        
        when(didDocumentService.getDIDDocument("localhost:9443", -1234)).thenReturn("{\"did\":\"test\"}");
        
        servlet.doGet(request, response);
        
        verify(response).setContentType("application/did+json;charset=UTF-8");
        verify(response).setStatus(HttpServletResponse.SC_OK);
    }


    private void setPrivateField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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
}
