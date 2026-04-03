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
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;

import static org.testng.Assert.assertThrows;

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
        PresentationSubmission submission = new PresentationSubmission();
        submission.setDefinitionId("def-1");

        PresentationSubmission.DescriptorMap descriptor = new PresentationSubmission.DescriptorMap();
        descriptor.setFormat(VerificationConstants.FORMAT_JWT);
        submission.setDescriptorMap(java.util.Collections.singletonList(descriptor));

        // This will throw VerificationServerException because presentationDefinitionService is null
        assertThrows(VerificationException.class,
            () -> verificationService.verify(submission, 1, "jwt"));
    }
}
