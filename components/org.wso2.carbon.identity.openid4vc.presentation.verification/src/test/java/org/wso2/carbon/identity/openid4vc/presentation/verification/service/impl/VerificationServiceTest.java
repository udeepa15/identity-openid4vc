/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.Verifier;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class VerificationServiceTest {

    private VerificationServiceImpl verificationService;

    @Mock
    private PresentationDefinitionService presentationDefinitionService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        verificationService = new VerificationServiceImpl();
    }

    @Test
    public void testVerifyWithMissingServiceThrows() throws Exception {

        // Use a stubbed verifier so handle(..) succeeds, allowing the logic to reach the service null check.
        Verifier stubVerifier = mock(Verifier.class);
        when(stubVerifier.canHandle(Constants.JWT_VC_FORMAT)).thenReturn(true);
        when(stubVerifier.handle(any(PresentationSubmission.class), anyInt(), anyString()))
                .thenReturn(Collections.singletonMap("iss", "test-issuer"));

        Field verifiersField = VerificationServiceImpl.class.getDeclaredField("verifiers");
        verifiersField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Verifier> verifierList = (List<Verifier>) verifiersField.get(verificationService);
        verifierList.clear();
        verifierList.add(stubVerifier);

        PresentationSubmission submission = new PresentationSubmission();
        submission.setDefinitionId("def-1");

        PresentationSubmission.DescriptorMap descriptor = new PresentationSubmission.DescriptorMap();
        descriptor.setFormat(Constants.JWT_VC_FORMAT);
        submission.setDescriptorMap(Collections.singletonList(descriptor));

        // This will throw VerificationServerException because presentationDefinitionService is null
        try {
            verificationService.verify(submission, 1, "any-token");
            fail("Expected VerificationServerException due to missing presentationDefinitionService");
        } catch (VerificationServerException e) {
            assertEquals(e.getErrorCode(), VerificationErrorCode.INTERNAL_SERVER_ERROR);
            assertEquals(e.getMessage(), "Presentation definition service is not available");
        }
    }
}
