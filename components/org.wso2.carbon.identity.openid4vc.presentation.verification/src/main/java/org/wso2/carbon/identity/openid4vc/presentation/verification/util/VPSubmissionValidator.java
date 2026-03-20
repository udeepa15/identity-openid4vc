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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DescriptorMapDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;


/**
 * Utility class for validating VP submissions.
 * Performs various validation checks on VP tokens and presentation submissions.
 */
public final class VPSubmissionValidator {

    private static final Gson GSON = new Gson();

    private VPSubmissionValidator() {
        // Prevent instantiation
    }

    /**
     * Validate a VP submission DTO.
     *
     * @param dto The submission DTO to validate
     * @throws VPSubmissionValidationException If validation fails
     */
    public static void validateSubmission(final VPSubmissionDTO dto)
            throws VPSubmissionValidationException {

        if (dto == null) {
            throw new VPSubmissionValidationException("Submission cannot be null");
        }

        // State is always required
        if (StringUtils.isBlank(dto.getState())) {
            throw new VPSubmissionValidationException(
                    "state parameter is required");
        }

        // Check if it's an error response
        if (StringUtils.isNotBlank(dto.getError())) {
            // Error response is valid if error code is provided
            validateErrorResponse(dto);
            return;
        }

        // For successful submission, vp_token is required
        if (StringUtils.isBlank(dto.getVpToken())) {
            throw new VPSubmissionValidationException(
                    "vp_token is required");
        }

        // presentation_submission is now required
        if (dto.getPresentationSubmission() == null || dto.getPresentationSubmission().entrySet().isEmpty()) {
            throw new VPSubmissionValidationException(
                    "presentation_submission is required");
        }

        // Validate presentation_submission if provided
        validatePresentationSubmissionJson(dto.getPresentationSubmission());
    }

    /**
     * Validate error response from wallet.
     *
     * @param dto The submission DTO with error
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateErrorResponse(final VPSubmissionDTO dto)
            throws VPSubmissionValidationException {

        String error = dto.getError();

        // Validate error code format
        if (!isValidErrorCode(error)) {
            throw new VPSubmissionValidationException(
                    "Invalid error code format: " + error);
        }

    }

    /**
     * Check if error code is valid.
     *
     * @param errorCode Error code to check
     * @return true if valid
     */
    private static boolean isValidErrorCode(final String errorCode) {

        // Known error codes from OpenID4VP spec
        return OpenID4VPConstants.ErrorCodes.INVALID_REQUEST.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.UNAUTHORIZED_CLIENT.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.ACCESS_DENIED.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.SERVER_ERROR.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.USER_CANCELLED.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.CREDENTIAL_NOT_AVAILABLE.equals(errorCode)
                || OpenID4VPConstants.ErrorCodes.VP_FORMATS_NOT_SUPPORTED.equals(errorCode)
                // Allow other error codes (extensible)
                || errorCode.matches("^[a-z_]+$");
    }

    /**
     * Validate presentation submission JSON.
     *
     * @param submissionJson Presentation submission as JsonObject
     * @throws VPSubmissionValidationException If validation fails
     */
    public static void validatePresentationSubmissionJson(
            final JsonObject submissionJson) throws VPSubmissionValidationException {

        try {
            validatePresentationSubmissionJsonStructure(submissionJson);
            PresentationSubmissionDTO submission = GSON.fromJson(
                    submissionJson, PresentationSubmissionDTO.class);
        } catch (JsonSyntaxException e) {
            throw new VPSubmissionValidationException(
                    "Invalid presentation_submission JSON: " + e.getMessage());
        }
    }

    /**
     * Validate strict JSON structure for DIF Presentation Exchange MUST fields.
     *
     * @param submissionJson Presentation submission as JsonObject.
     * @throws VPSubmissionValidationException If validation fails.
     */
    private static void validatePresentationSubmissionJsonStructure(final JsonObject submissionJson)
            throws VPSubmissionValidationException {

        if (submissionJson == null) {
            throw new VPSubmissionValidationException(
                    "presentation_submission cannot be null");
        }

        if (!isNonBlankStringField(submissionJson, "id")) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.id is required and must be a string");
        }

        if (!isNonBlankStringField(submissionJson, "definition_id")) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.definition_id is required and must be a string");
        }

        if (!submissionJson.has("descriptor_map") || !submissionJson.get("descriptor_map").isJsonArray()) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.descriptor_map is required and must be an array");
        }

        JsonArray descriptorMap = submissionJson.getAsJsonArray("descriptor_map");
        if (descriptorMap.size() == 0) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.descriptor_map is required");
        }

        for (int i = 0; i < descriptorMap.size(); i++) {
            JsonElement descriptorElement = descriptorMap.get(i);
            if (!descriptorElement.isJsonObject()) {
                throw new VPSubmissionValidationException(
                        "descriptor_map[" + i + "] must be an object");
            }

            JsonObject descriptorObject = descriptorElement.getAsJsonObject();
            if (!isNonBlankStringField(descriptorObject, "id")) {
                throw new VPSubmissionValidationException(
                        "descriptor_map[" + i + "].id is required and must be a string");
            }

            if (!isNonBlankStringField(descriptorObject, "format")) {
                throw new VPSubmissionValidationException(
                        "descriptor_map[" + i + "].format is required and must be a string");
            }

            if (!isNonBlankStringField(descriptorObject, "path")) {
                throw new VPSubmissionValidationException(
                        "descriptor_map[" + i + "].path is required and must be a string");
            }

            if (!isValidJsonPath(descriptorObject.get("path").getAsString())) {
                throw new VPSubmissionValidationException(
                        "descriptor_map[" + i + "].path is not valid JSONPath");
            }
        }
    }

    /**
     * Check whether a field exists as a non-empty string.
     *
     * @param object JSON object.
     * @param fieldName Field name.
     * @return true if valid.
     */
    private static boolean isNonBlankStringField(final JsonObject object,
            final String fieldName) {

        if (object == null || StringUtils.isBlank(fieldName)
                || !object.has(fieldName) || object.get(fieldName).isJsonNull()) {
            return false;
        }

        JsonElement field = object.get(fieldName);
        return field.isJsonPrimitive() && field.getAsJsonPrimitive().isString()
                && StringUtils.isNotBlank(field.getAsString());
    }

    /**
     * Validate descriptor map entry.
     *
     * @param descriptor Descriptor map entry
     * @param index      Index in array
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateDescriptorMap(final DescriptorMapDTO descriptor,
            final int index)
            throws VPSubmissionValidationException {

        if (descriptor == null) {
            throw new VPSubmissionValidationException(
                    "descriptor_map[" + index + "] cannot be null");
        }

        if (StringUtils.isBlank(descriptor.getId())) {
            throw new VPSubmissionValidationException(
                    "descriptor_map[" + index + "].id is required");
        }

        if (StringUtils.isBlank(descriptor.getFormat())) {
            throw new VPSubmissionValidationException(
                    "descriptor_map[" + index + "].format is required");
        }

        if (StringUtils.isBlank(descriptor.getPath())) {
            throw new VPSubmissionValidationException(
                    "descriptor_map[" + index + "].path is required");
        }

        // Validate path is valid JSONPath
        if (!isValidJsonPath(descriptor.getPath())) {
            throw new VPSubmissionValidationException(
                    "descriptor_map[" + index + "].path is not valid JSONPath");
        }
    }

    /**
     * Check if string is valid JSONPath.
     *
     * @param path Path to check
     * @return true if valid JSONPath
     */
    private static boolean isValidJsonPath(final String path) {

        if (StringUtils.isBlank(path)) {
            return false;
        }
        // Basic JSONPath validation - must start with $ or @
        return path.startsWith("$") || path.startsWith("@");
    }
}
