package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class VPRequestBuilderTest {

    private VPRequestBuilder builder;

    @Mock
    private HttpServletRequest request;

    private MockedStatic<ServletUtil> mockedServletUtil;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        builder = new VPRequestBuilder();
        mockedServletUtil = Mockito.mockStatic(ServletUtil.class);
        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
        mockedIdentityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn("http://localhost:9443");
    }

    @AfterMethod
    public void tearDown() {
        mockedServletUtil.close();
        mockedIdentityUtil.close();
    }

    @Test
    public void testBuildAuthorizationRequestJson() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .clientId("client123")
                .nonce("nonce123")
                .requestId("req123")
                .responseMode("direct_post")
                .build();
        
        String json = builder.buildAuthorizationRequestJson(vpRequest, null);
        
        assertNotNull(json);
        assertTrue(json.contains("client123"));
        assertTrue(json.contains("nonce123"));
        assertTrue(json.contains("req123"));
    }

    @Test
    public void testBuildAuthorizationDetails() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .clientId("client123")
                .nonce("nonce123")
                .requestId("req123")
                .responseMode("direct_post")
                .build();
        
        AuthorizationDetailsDTO dto = builder.buildAuthorizationDetails(vpRequest, null);
        
        assertNotNull(dto);
        assertEquals(dto.getClientId(), "client123");
        assertEquals(dto.getNonce(), "nonce123");
        assertEquals(dto.getState(), "req123");
    }

    private void assertTrue(boolean condition) {
        org.testng.Assert.assertTrue(condition);
    }
}
