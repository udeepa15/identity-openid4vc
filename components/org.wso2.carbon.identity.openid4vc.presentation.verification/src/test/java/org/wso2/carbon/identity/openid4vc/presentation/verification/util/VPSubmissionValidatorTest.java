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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.definition.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;

import static org.testng.Assert.assertThrows;

public class VPSubmissionValidatorTest {

    @Test
    public void testValidateSubmissionNull() {
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateSubmission(null));
    }

    @Test
    public void testValidateSubmissionMissingState() {
        VPSubmissionDTO dto = new VPSubmissionDTO();
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateSubmission(dto));
    }

    @Test
    public void testValidateSubmissionSuccessfulMissingToken() {
        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateSubmission(dto));
    }

    @Test
    public void testValidateVPTokenEmpty() {
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateVPToken(""));
    }

    @Test
    public void testValidateJwtVpInvalid() {
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateVPToken("header.payload")); // Missing signature part or not 3 dots
    }

    @Test
    public void testValidateJsonLdVPNoType() {
        String json = "{\"id\": \"vp1\"}";
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateVPToken(json));
    }

    @Test
    public void testValidateSubmissionMatchesDefinitionMismatch() {
        org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmissionDTO submission = 
            new org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmissionDTO();
        submission.setDefinitionId("def1");
        
        PresentationDefinition definition = new PresentationDefinition();
        definition.setDefinitionId("def2");
        
        assertThrows(VPSubmissionValidationException.class, () -> 
            VPSubmissionValidator.validateSubmissionMatchesDefinition(submission, definition));
    }
}
