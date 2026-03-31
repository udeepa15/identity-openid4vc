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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
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

    @Mock
    private LongPollingManager pollingManager;

    private ByteArrayOutputStream responseOutputStream;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        vpRequestServlet = new VPRequestServlet();

        mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);

        // Inject mock service via reflection
        Field serviceField = VPRequestServlet.class.getDeclaredField("vpRequestService");
        serviceField.setAccessible(true);
        serviceField.set(vpRequestServlet, vpRequestService);

        responseOutputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(createMockOutputStream(responseOutputStream));
    }

    @AfterMethod
    public void tearDown() {
        if (mockedIdentityTenantUtil != null) {
            mockedIdentityTenantUtil.close();
        }
    }

    @Test
    public void testDoGetRequestIdJwt() throws Exception {
        when(request.getPathInfo()).thenReturn("/test-id");
        when(vpRequestService.getRequestJwt("test-id", -1234)).thenReturn("test-jwt");

        vpRequestServlet.doGet(request, response);

        String output = responseOutputStream.toString(StandardCharsets.UTF_8.name());
        assertTrue(output.contains("test-jwt"));
    }

    @Test
    public void testDoGetStatusSuccess() throws Exception {
        when(request.getPathInfo()).thenReturn("/test-request-id/status");

        try (MockedStatic<LongPollingManager> mockedManager = mockStatic(LongPollingManager.class)) {
            mockedManager.when(LongPollingManager::getInstance).thenReturn(pollingManager);

            PollingResult result = PollingResult.submitted("test-request-id", "VP_SUBMITTED");
            when(pollingManager.waitForStatusChange(eq("test-request-id"), anyLong(), eq(-1234))).thenReturn(result);

            vpRequestServlet.doGet(request, response);

            String output = responseOutputStream.toString(StandardCharsets.UTF_8.name());
            assertTrue(output.contains("VP_SUBMITTED"));
        }
    }

    private ServletOutputStream createMockOutputStream(ByteArrayOutputStream outputStream) {
        return new ServletOutputStream() {
            public boolean isReady() {
                return true;
            }

            public void setWriteListener(WriteListener writeListener) {
            }

            @Override
            public void write(int b) {
                outputStream.write(b);
            }
        };
    }
}
