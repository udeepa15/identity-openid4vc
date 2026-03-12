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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.definition.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DescriptorMapDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility class for validating VP submissions.
 * Performs various validation checks on VP tokens and presentation submissions.
 */
public final class VPSubmissionValidator {

    private static final Gson GSON = new Gson();

    /**
     * Supported VP token formats.
     */
    private static final Set<String> SUPPORTED_FORMATS = new HashSet<>();

    static {
        SUPPORTED_FORMATS.add(OpenID4VPConstants.VCFormats.JWT_VP);
        SUPPORTED_FORMATS.add(OpenID4VPConstants.VCFormats.JWT_VP_JSON);
        SUPPORTED_FORMATS.add(OpenID4VPConstants.VCFormats.LDP_VP);
        SUPPORTED_FORMATS.add(OpenID4VPConstants.VCFormats.VC_SD_JWT);
        SUPPORTED_FORMATS.add(OpenID4VPConstants.VCFormats.MSO_MDOC);
    }

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
                    "vp_token is required for successful submission");
        }

        // Validate VP token format
        validateVPToken(dto.getVpToken());

        // Validate presentation_submission if provided
        if (dto.getPresentationSubmission() != null) {
            validatePresentationSubmissionJson(dto.getPresentationSubmission());
        }
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
     * Validate VP token format.
     *
     * @param vpToken VP token to validate
     * @throws VPSubmissionValidationException If validation fails
     */
    public static void validateVPToken(final String vpToken)
            throws VPSubmissionValidationException {

        if (StringUtils.isBlank(vpToken)) {
            throw new VPSubmissionValidationException("VP token cannot be empty");
        }

        // VP token could be:
        // 1. JWT format (3 parts separated by dots)
        // 2. SD-JWT format (multiple parts with ~)
        // 3. JSON-LD format (JSON object)
        // 4. Array of any of the above

        String trimmed = vpToken.trim();

        // Check if it's a JSON array
        if (trimmed.startsWith("[")) {
            validateVPTokenArray(trimmed);
            return;
        }

        String format = VerificationUtil.detectFormat(trimmed);
        if (VerificationUtil.CONTENT_TYPE_SD_JWT.equals(format)) {
            validateSdJwtVP(trimmed);
            return;
        } else if (VerificationUtil.CONTENT_TYPE_JWT.equals(format)) {
            validateJwtVP(trimmed);
            return;
        } else if (VerificationUtil.CONTENT_TYPE_VC_LD_JSON.equals(format) && trimmed.startsWith("{")) {
            validateJsonLdVP(trimmed);
            return;
        }

        throw new VPSubmissionValidationException(
                "VP token format is not recognized");
    }

    /**
     * Validate VP token array.
     *
     * @param vpTokenArray JSON array of VP tokens
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateVPTokenArray(final String vpTokenArray)
            throws VPSubmissionValidationException {

        try {
            com.google.gson.JsonArray array = com.google.gson.JsonParser.parseString(vpTokenArray)
                    .getAsJsonArray();

            if (array.size() == 0) {
                throw new VPSubmissionValidationException(
                        "VP token array cannot be empty");
            }

            // Validate each element
            for (int i = 0; i < array.size(); i++) {
                com.google.gson.JsonElement element = array.get(i);
                if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
                    String token = element.getAsString();
                    validateVPToken(token);
                } else if (element.isJsonObject()) {
                    validateJsonLdVP(element.toString());
                } else {
                    throw new VPSubmissionValidationException(
                            "Invalid VP token element at index " + i);
                }
            }
        } catch (JsonSyntaxException e) {
            throw new VPSubmissionValidationException(
                    "Invalid VP token array JSON: " + e.getMessage());
        }
    }

    /**
     * Validate JSON-LD VP.
     *
     * @param vpJson JSON-LD VP
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateJsonLdVP(final String vpJson)
            throws VPSubmissionValidationException {

        try {
            JsonObject vp = com.google.gson.JsonParser.parseString(vpJson)
                    .getAsJsonObject();

            // Check for required fields
            if (!vp.has("type")) {
                throw new VPSubmissionValidationException(
                        "JSON-LD VP missing 'type' field");
            }

            // Verify it contains VerifiablePresentation type
            com.google.gson.JsonElement typeElement = vp.get("type");
            boolean hasVPType = false;

            if (typeElement.isJsonArray()) {
                for (com.google.gson.JsonElement t : typeElement.getAsJsonArray()) {
                    if ("VerifiablePresentation".equals(t.getAsString())) {
                        hasVPType = true;
                        break;
                    }
                }
            } else if (typeElement.isJsonPrimitive()) {
                hasVPType = "VerifiablePresentation".equals(
                        typeElement.getAsString());
            }

            if (!hasVPType) {
                throw new VPSubmissionValidationException(
                        "VP must have type 'VerifiablePresentation'");
            }

        } catch (JsonSyntaxException e) {
            throw new VPSubmissionValidationException(
                    "Invalid JSON-LD VP: " + e.getMessage());
        }
    }

    /**
     * Validate SD-JWT VP.
     *
     * @param sdJwt SD-JWT VP token
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateSdJwtVP(final String sdJwt)
            throws VPSubmissionValidationException {

        // SD-JWT format: <Issuer-signed JWT>~<Disclosure 1>~...~<KB-JWT>
        String[] parts = sdJwt.split("~");
        if (parts.length < 1) {
            throw new VPSubmissionValidationException(
                    "Invalid SD-JWT format");
        }

        // First part should be a valid JWT
        if (StringUtils.isBlank(parts[0]) || parts[0].split("\\.").length != 3) {
            throw new VPSubmissionValidationException(
                    "SD-JWT issuer-signed part is not valid JWT");
        }
    }

    /**
     * Validate JWT VP.
     *
     * @param jwt JWT VP token
     * @throws VPSubmissionValidationException If validation fails
     */
    private static void validateJwtVP(final String jwt)
            throws VPSubmissionValidationException {

        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new VPSubmissionValidationException(
                    "Invalid JWT format - expected 3 parts");
        }

        // Validate Base64URL encoding of each part
        for (int i = 0; i < parts.length; i++) {
            if (!isValidBase64Url(parts[i])) {
                throw new VPSubmissionValidationException(
                        "Invalid Base64URL encoding in JWT part " + (i + 1));
            }
        }
    }



    /**
     * Check if string is valid Base64URL.
     *
     * @param str String to check
     * @return true if valid Base64URL
     */
    private static boolean isValidBase64Url(final String str) {

        if (str == null) {
            return false;
        }
        // Base64URL uses: A-Z, a-z, 0-9, -, _
        return str.matches("^[A-Za-z0-9_-]*$");
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
            PresentationSubmissionDTO submission = GSON.fromJson(
                    submissionJson, PresentationSubmissionDTO.class);
            validatePresentationSubmission(submission);
        } catch (JsonSyntaxException e) {
            throw new VPSubmissionValidationException(
                    "Invalid presentation_submission JSON: " + e.getMessage());
        }
    }

    /**
     * Validate presentation submission DTO.
     *
     * @param submission Presentation submission DTO
     * @throws VPSubmissionValidationException If validation fails
     */
    public static void validatePresentationSubmission(
            final PresentationSubmissionDTO submission)
            throws VPSubmissionValidationException {

        if (submission == null) {
            throw new VPSubmissionValidationException(
                    "presentation_submission cannot be null");
        }

        if (StringUtils.isBlank(submission.getId())) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.id is required");
        }

        if (StringUtils.isBlank(submission.getDefinitionId())) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.definition_id is required");
        }

        List<DescriptorMapDTO> descriptorMap = submission.getDescriptorMap();
        if (descriptorMap == null || descriptorMap.isEmpty()) {
            throw new VPSubmissionValidationException(
                    "presentation_submission.descriptor_map is required");
        }

        // Validate each descriptor map entry
        for (int i = 0; i < descriptorMap.size(); i++) {
            validateDescriptorMap(descriptorMap.get(i), i);
        }
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

    /**
     * Validate that submission matches presentation definition.
     *
     * @param submission Presentation submission
     * @param definition Presentation definition
     * @throws VPSubmissionValidationException If validation fails
     */
    public static void validateSubmissionMatchesDefinition(
            final PresentationSubmissionDTO submission,
            final PresentationDefinition definition)
            throws VPSubmissionValidationException {

        if (submission == null || definition == null) {
            throw new VPSubmissionValidationException(
                    "Submission and definition cannot be null");
        }

        String defId = definition.getDefinitionId();
        String submissionDefId = submission.getDefinitionId();

        if (!defId.equals(submissionDefId)) {
            throw new VPSubmissionValidationException(
                    "Submission definition_id '" + submissionDefId
                            + "' does not match request definition_id '" + defId + "'");
        }

        // Additional validation can be added here to verify that
        // all required input descriptors are satisfied
    }

}
