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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;

import static org.testng.Assert.assertThrows;
import static org.testng.Assert.fail;

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
        public void testValidateSubmissionSuccessfulMissingPresentationSubmission() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        dto.setVpToken("vp-token");
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validateSubmission(dto));
        }

        @Test
        public void testValidateSubmissionErrorResponseAllowedKnownErrorCode() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        dto.setError("invalid_request");

        try {
            VPSubmissionValidator.validateSubmission(dto);
        } catch (VPSubmissionValidationException e) {
            fail("Expected validation to pass for known error code", e);
        }
        }

        @Test
        public void testValidateSubmissionErrorResponseAllowedCustomErrorCode() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        dto.setError("custom_wallet_error");

        try {
            VPSubmissionValidator.validateSubmission(dto);
        } catch (VPSubmissionValidationException e) {
            fail("Expected validation to pass for custom lowercase error code", e);
        }
        }

        @Test
        public void testValidateSubmissionErrorResponseRejectsInvalidErrorCode() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        dto.setError("Invalid-Mixed-Error");

        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validateSubmission(dto));
        }

        @Test
        public void testValidateSubmissionSuccessPath() {

        VPSubmissionDTO dto = new VPSubmissionDTO();
        dto.setState("state123");
        dto.setVpToken("vp-token");
        dto.setPresentationSubmission(
            JsonParser.parseString(validSubmissionJsonString()).getAsJsonObject());

        try {
            VPSubmissionValidator.validateSubmission(dto);
        } catch (VPSubmissionValidationException e) {
            fail("Expected successful submission validation to pass", e);
        }
        }

        @Test
        public void testValidatePresentationSubmissionJsonNull() {

        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(null));
        }

        @Test
        public void testValidatePresentationSubmissionJsonMissingId() {

        JsonObject json = JsonParser.parseString("{\"definition_id\":\"def1\",\"descriptor_map\":[{}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonMissingDefinitionId() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"descriptor_map\":[{}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMapNotArray() {

        JsonObject json = JsonParser.parseString(
            "{\"id\":\"sub1\",\"definition_id\":\"def1\",\"descriptor_map\":{}}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMapEmpty() {

        JsonObject json = JsonParser.parseString(
            "{\"id\":\"sub1\",\"definition_id\":\"def1\",\"descriptor_map\":[]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMapEntryNotObject() {

        JsonObject json = JsonParser.parseString(
            "{\"id\":\"sub1\",\"definition_id\":\"def1\",\"descriptor_map\":[\"x\"]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMissingId() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"format\":\"jwt_vp\",\"path\":\"$\"}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMissingFormat() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"id\":\"in1\",\"path\":\"$\"}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorMissingPath() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"id\":\"in1\",\"format\":\"jwt_vp\"}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonDescriptorInvalidPath() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"id\":\"in1\",\"format\":\"jwt_vp\",\"path\":\"abc\"}]}")
            .getAsJsonObject();
        assertThrows(VPSubmissionValidationException.class,
            () -> VPSubmissionValidator.validatePresentationSubmissionJson(json));
        }

        @Test
        public void testValidatePresentationSubmissionJsonValidPathAt() {

        JsonObject json = JsonParser.parseString("{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"id\":\"in1\",\"format\":\"jwt_vp\",\"path\":\"@\"}]}")
            .getAsJsonObject();

        try {
            VPSubmissionValidator.validatePresentationSubmissionJson(json);
        } catch (VPSubmissionValidationException e) {
            fail("Expected presentation_submission with @ path to pass validation", e);
        }
        }

        private static String validSubmissionJsonString() {

        return "{\"id\":\"sub1\",\"definition_id\":\"def1\","
            + "\"descriptor_map\":[{\"id\":\"in1\",\"format\":\"jwt_vp\",\"path\":\"$\"}]"
            + "}";
        }
}
