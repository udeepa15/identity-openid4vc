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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

public class VPRequestServletTest {

    private VPRequestServlet vpRequestServlet;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock
    private HttpServletResponse response;
    
    @Mock
    private VPRequestService vpRequestService;

    private StringWriter responseWriter;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        vpRequestServlet = new VPRequestServlet();
        
        // Inject mock service via reflection
        Field serviceField = VPRequestServlet.class.getDeclaredField("vpRequestService");
        serviceField.setAccessible(true);
        serviceField.set(vpRequestServlet, vpRequestService);

        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Test
    public void testDoPostSuccess() throws Exception {
        String json = "{\"clientId\":\"test-client\",\"presentationDefinitionId\":\"test-pd\"}";
        ServletInputStream inputStream = createMockInputStream(json);
        when(request.getInputStream()).thenReturn(inputStream);

        VPRequestResponseDTO responseDTO = new VPRequestResponseDTO();
        responseDTO.setRequestId("test-request-id");
        when(vpRequestService.createVPRequest(any(VPRequestCreateDTO.class), anyInt())).thenReturn(responseDTO);

        vpRequestServlet.doPost(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("test-request-id"));
    }

    @Test
    public void testDoPostEmptyBody() throws Exception {
        ServletInputStream inputStream = createMockInputStream("");
        when(request.getInputStream()).thenReturn(inputStream);

        vpRequestServlet.doPost(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("Request body is required"));
    }

    @Test
    public void testDoGetRequestIdJwt() throws Exception {
        when(request.getPathInfo()).thenReturn("/test-id");
        when(vpRequestService.getRequestJwt("test-id", -1234)).thenReturn("test-jwt");

        vpRequestServlet.doGet(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("test-jwt"));
    }

    private ServletInputStream createMockInputStream(String content) {
        final ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return byteArrayInputStream.read(b, off, len);
            }

            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            public boolean isReady() {
                return true;
            }

            public void setReadListener(ReadListener readListener) {
            }
        };
    }
}
