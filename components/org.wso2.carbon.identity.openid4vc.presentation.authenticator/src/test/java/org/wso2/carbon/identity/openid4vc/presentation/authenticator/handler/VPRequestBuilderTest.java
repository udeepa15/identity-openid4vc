/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VPRequestBuilderTest {

    private VPRequestBuilder builder;

    @Mock
    private HttpServletRequest request;

    private MockedStatic<IdentityUtil> mockedIdentityUtil;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        builder = new VPRequestBuilder();
        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
        mockedIdentityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn("http://localhost:9443");
    }

    @AfterMethod
    public void tearDown() {
        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
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
}
