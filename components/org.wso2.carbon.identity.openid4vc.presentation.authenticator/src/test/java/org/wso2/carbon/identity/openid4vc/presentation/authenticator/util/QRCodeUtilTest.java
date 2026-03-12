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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class QRCodeUtilTest {

    @Test
    public void testGenerateRequestUriQRContent() {
        String requestUri = "https://example.com/request/123";
        String clientId = "test-client";
        
        String content = QRCodeUtil.generateRequestUriQRContent(requestUri, clientId);
        
        assertNotNull(content);
        assertTrue(content.startsWith("openid4vp://"));
        assertTrue(content.contains("authorize?"));
        assertTrue(content.contains("client_id=test-client"));
        assertTrue(content.contains("request_uri=https%3A%2F%2Fexample.com%2Frequest%2F123"));
    }

    @Test
    public void testGenerateRequestUriQRContentBlankUri() {
        assertThrows(IllegalArgumentException.class, () -> 
            QRCodeUtil.generateRequestUriQRContent("", "client"));
    }

    @Test
    public void testGenerateByValueQRContent() {
        AuthorizationDetailsDTO details = new AuthorizationDetailsDTO();
        details.setClientId("test-client");
        details.setResponseMode("direct_post");
        details.setResponseUri("https://example.com/resp");
        details.setNonce("test-nonce");
        details.setState("test-state");
        
        String content = QRCodeUtil.generateByValueQRContent(details);
        
        assertNotNull(content);
        assertTrue(content.contains("client_id=test-client"));
        assertTrue(content.contains("response_type=vp_token"));
        assertTrue(content.contains("response_mode=direct_post"));
        assertTrue(content.contains("nonce=test-nonce"));
        assertTrue(content.contains("state=test-state"));
    }

}
