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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VPSubmissionValidator;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

public class VPSubmissionServletTest {

    private VPSubmissionServlet vpSubmissionServlet;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock
    private HttpServletResponse response;
    
    @Mock
    private VPServiceDataHolder dataHolder;
    
    @Mock
    private VCVerificationService verificationService;

    private StringWriter responseWriter;
    private MockedStatic<VPServiceDataHolder> dataHolderMockedStatic;
    private MockedStatic<VPSubmissionValidator> validatorMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        vpSubmissionServlet = new VPSubmissionServlet();
        
        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        dataHolderMockedStatic = mockStatic(VPServiceDataHolder.class);
        dataHolderMockedStatic.when(VPServiceDataHolder::getInstance).thenReturn(dataHolder);
        when(dataHolder.getVCVerificationService()).thenReturn(verificationService);

        validatorMockedStatic = mockStatic(VPSubmissionValidator.class);
    }

    @AfterMethod
    public void tearDown() {
        dataHolderMockedStatic.close();
        validatorMockedStatic.close();
    }

    @Test
    public void testDoPostSuccess() throws Exception {
        when(request.getContentType()).thenReturn(OpenID4VPConstants.HTTP.CONTENT_TYPE_FORM);
        when(request.getParameter("state")).thenReturn("test-id");
        
        // Mock a simple JWT VP token for issuer verification
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"RS256\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString("{\"vp\":{\"verifiableCredential\":[]}}".getBytes());
        String vpToken = header + "." + payload + ".sig";
        when(request.getParameter("vp_token")).thenReturn(vpToken);

        vpSubmissionServlet.doPost(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("received"));
    }

    @Test
    public void testDoPostInvalidSubmission() throws Exception {
        when(request.getContentType()).thenReturn(OpenID4VPConstants.HTTP.CONTENT_TYPE_FORM);
        
        // Let validator throw exception
        validatorMockedStatic.when(() -> VPSubmissionValidator.validateSubmission(any()))
                .thenThrow(new VPSubmissionValidationException("Invalid"));

        vpSubmissionServlet.doPost(request, response);

        String output = responseWriter.toString();
        assertTrue(output.contains("Invalid"));
    }

    private <T> T any() {
        return Mockito.any();
    }
}
