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
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;

import java.io.IOException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.when;

public class VPSubmissionServletTest {

    private VPSubmissionServlet servlet;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private VPRequestService vpRequestService;

    @Mock
    private WalletDataCache walletDataCache;

    private MockedStatic<VPServiceDataHolder> mockedDataHolder;
    private MockedStatic<WalletDataCache> mockedWalletCache;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        servlet = new VPSubmissionServlet();

        mockedIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);

        mockedDataHolder = Mockito.mockStatic(VPServiceDataHolder.class);
        mockedDataHolder.when(VPServiceDataHolder::getVPRequestService).thenReturn(vpRequestService);

        mockedWalletCache = Mockito.mockStatic(WalletDataCache.class);
        mockedWalletCache.when(WalletDataCache::getInstance).thenReturn(walletDataCache);

        // Mock input stream and output stream
        byte[] payload = "{\"vp_token\":\"test\",\"state\":\"req1\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        when(request.getInputStream()).thenReturn(new MockServletInputStream(payload));
        when(response.getOutputStream()).thenReturn(new MockServletOutputStream());
    }

    private static class MockServletInputStream extends javax.servlet.ServletInputStream {
        private final java.io.ByteArrayInputStream buffer;

        public MockServletInputStream(byte[] payload) {
            this.buffer = new java.io.ByteArrayInputStream(payload);
        }

        @Override
        public int read() throws IOException {
            return buffer.read();
        }

        public boolean isFinished() {
            return buffer.available() == 0;
        }

        public boolean isReady() {
            return true;
        }

        public void setReadListener(javax.servlet.ReadListener readListener) {
        }
    }

    @AfterMethod
    public void tearDown() {
        mockedDataHolder.close();
        mockedWalletCache.close();
        mockedIdentityTenantUtil.close();
    }

    @Test
    public void testDoPostSuccess() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId("req1").tenantId(-1234).build();
        when(vpRequestService.getVPRequestById("req1", -1234)).thenReturn(vpRequest);

        // This will trigger internal logic to process submission
        servlet.doPost(request, response);
    }

    private static class MockServletOutputStream extends ServletOutputStream {
        @Override
        public void write(int b) throws IOException {
        }

        public boolean isReady() {
            return true;
        }

        public void setWriteListener(javax.servlet.WriteListener writeListener) {
        }
    }
}
