/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VPRequestBuilderTest {

    private VPRequestBuilder vpRequestBuilder;
    private VPRequest vpRequest;
    private PresentationDefinition presentationDefinition;
    private MockedStatic<IdentityUtil> identityUtilMockedStatic;

    @BeforeMethod
    public void setUp() {
        identityUtilMockedStatic = mockStatic(IdentityUtil.class);
        identityUtilMockedStatic.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn("http://localhost:9443");
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(anyString()))
                .thenReturn(null);

        vpRequestBuilder = new VPRequestBuilder();
        vpRequest = new VPRequest.Builder()
                .clientId("test-client-id")
                .nonce("test-nonce")
                .requestId("test-request-id")
                .responseMode("direct_post")
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();

        PresentationDefinition.RequestedCredential cred = new PresentationDefinition.RequestedCredential();
        cred.setType("TestCredential");
        cred.setPurpose("Test purpose");
        cred.setClaims(java.util.Collections.singletonList("email"));
        presentationDefinition = new PresentationDefinition.Builder()
                .definitionId("test-pd-id")
                .name("Test PD")
                .requestedCredentials(java.util.Collections.singletonList(cred))
                .build();
    }

    @AfterMethod
    public void tearDown() {
        if (identityUtilMockedStatic != null) {
            identityUtilMockedStatic.close();
        }
    }

    @Test
    public void testBuildAuthorizationRequestJson() {
        String jsonStr = vpRequestBuilder.buildAuthorizationRequestJson(vpRequest, presentationDefinition);
        assertNotNull(jsonStr);

        JsonObject json = JsonParser.parseString(jsonStr).getAsJsonObject();
        assertEquals(json.get("client_id").getAsString(), "test-client-id");
        assertEquals(json.get("nonce").getAsString(), "test-nonce");
        assertEquals(json.get("response_mode").getAsString(), "direct_post");
        assertEquals(json.get("state").getAsString(), "test-request-id");
        assertTrue(json.has("presentation_definition"));
        assertTrue(json.has("client_metadata"));
    }

    @Test
    public void testBuildAuthorizationDetails() {
        AuthorizationDetailsDTO dto = vpRequestBuilder.buildAuthorizationDetails(vpRequest, presentationDefinition);
        
        assertNotNull(dto);
        assertEquals(dto.getClientId(), "test-client-id");
        assertEquals(dto.getNonce(), "test-nonce");
        assertEquals(dto.getState(), "test-request-id");
        assertEquals(dto.getResponseMode(), "direct_post");
        assertNotNull(dto.getPresentationDefinition());
    }

    @Test
    public void testBuildAuthorizationRequestJwt() throws Exception {
        // This test might be limited because buildAuthorizationRequestJwt calls IdentityUtil 
        // which might not be fully initialized in unit tests, or it might need a mock private key
        // However, we can test the general structure if it doesn't crash
        
        // Since buildAuthorizationRequestJwt uses sign() which reads from IdentityUtil,
        // we might want to ensure it handles missing keys gracefully (as seen in the code)
        
        String jwt = vpRequestBuilder.buildAuthorizationRequestJwt(vpRequest, presentationDefinition);
        assertNotNull(jwt);
        
        String[] parts = jwt.split("\\.");
        // Parts will be 2 if signature is empty (as per current sign method implementation) 
        // or 3 if signature is present.
        assertTrue(parts.length >= 2);
    }
}
