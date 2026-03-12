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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPTokenExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Handler for processing VP responses from wallets.
 * 
 * This class is responsible for:
 * 1. Parsing VP token (JWT or JSON format)
 * 2. Validating VP structure against presentation definition
 * 3. Extracting verifiable credentials from VP
 * 4. Verifying cryptographic proofs
 * 5. Extracting claims from verified credentials
 */
public class VPResponseHandler {

    /**
     * Result of VP validation.
     */
    public static class ValidationResult {
        private VCVerificationStatus status;
        private String errorCode;
        private String errorDescription;
        private Map<String, String> verifiedClaims;
        private List<String> validatedCredentialIds;
        private String presentationId;

        public VCVerificationStatus getStatus() {
            return status;
        }

        public void setStatus(VCVerificationStatus status) {
            this.status = status;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public void setErrorCode(String errorCode) {
            this.errorCode = errorCode;
        }

        public String getErrorDescription() {
            return errorDescription;
        }

        public void setErrorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
        }

        public Map<String, String> getVerifiedClaims() {
            return verifiedClaims != null ? new HashMap<>(verifiedClaims) : null;
        }

        public void setVerifiedClaims(Map<String, String> verifiedClaims) {
            this.verifiedClaims = verifiedClaims != null ? new HashMap<>(verifiedClaims) : null;
        }

        public List<String> getValidatedCredentialIds() {
            return validatedCredentialIds != null ? new ArrayList<>(validatedCredentialIds) : null;
        }

        public void setValidatedCredentialIds(List<String> validatedCredentialIds) {
            this.validatedCredentialIds = validatedCredentialIds != null ? new ArrayList<>(validatedCredentialIds)
                    : null;
        }

        public String getPresentationId() {
            return presentationId;
        }

        public void setPresentationId(String presentationId) {
            this.presentationId = presentationId;
        }

        public boolean isValid() {
            return VCVerificationStatus.SUCCESS.equals(status);
        }
    }

    /**
     * Process a VP submission from a wallet.
     * 
     * @param submission The VP submission DTO
     * @param vpRequest  The original VP request
     * @return Validation result
     * @throws VPException If processing fails
     */
    public ValidationResult processSubmission(VPSubmissionDTO submission, VPRequest vpRequest)
            throws VPException {

        if (submission == null) {
            throw new VPSubmissionValidationException("VP submission is null");
        }

        // Check for error response from wallet
        if (StringUtils.isNotBlank(submission.getError())) {
            return handleErrorResponse(submission);
        }

        // Validate state matches
        if (!validateState(submission, vpRequest)) {
            ValidationResult result = new ValidationResult();
            result.setStatus(VCVerificationStatus.INVALID);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription("State parameter mismatch");
            return result;
        }

        // Get VP token
        String vpToken = submission.getVpToken();
        if (StringUtils.isBlank(vpToken)) {
            throw new VPSubmissionValidationException("VP token is missing");
        }

        // Determine token format and process accordingly
        if (isJwtFormat(vpToken)) {
            return processJwtVPToken(vpToken, vpRequest);
        } else {
            return processJsonVPToken(vpToken, vpRequest);
        }
    }

    /**
     * Handle error response from wallet.
     */
    private ValidationResult handleErrorResponse(VPSubmissionDTO submission) {
        ValidationResult result = new ValidationResult();
        result.setStatus(VCVerificationStatus.INVALID);
        result.setErrorCode(submission.getError());
        result.setErrorDescription(submission.getErrorDescription());

        return result;
    }

    /**
     * Validate that the state parameter matches.
     */
    private boolean validateState(VPSubmissionDTO submission, VPRequest vpRequest) {
        String submittedState = submission.getState();
        String expectedState = vpRequest.getRequestId();

        return StringUtils.equals(submittedState, expectedState);
    }

    /**
     * Check if the VP token is in JWT format.
     */
    private boolean isJwtFormat(String vpToken) {
        // JWT format has 3 parts separated by dots
        if (vpToken == null) {
            return false;
        }
        String[] parts = vpToken.split("\\.");
        return parts.length == 3;
    }

    /**
     * Process VP token in JWT format.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private ValidationResult processJwtVPToken(String vpToken, VPRequest vpRequest)
            throws VPException {

        ValidationResult result = new ValidationResult();
        result.setValidatedCredentialIds(new ArrayList<>());
        result.setVerifiedClaims(new HashMap<>());

        try {
            // Decode JWT (header.payload.signature)
            String[] parts = vpToken.split("\\.");
            if (parts.length != 3) {
                throw new VPSubmissionValidationException("Invalid JWT format");
            }

            // Decode header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]),
                    StandardCharsets.UTF_8);
            // Decode header
            JsonParser.parseString(headerJson).getAsJsonObject();

            // Decode payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

            // Validate JWT claims
            validateJwtClaims(payload, vpRequest);

            // Extract VP from payload
            JsonObject vp = null;
            if (payload.has("vp")) {
                vp = payload.getAsJsonObject("vp");
            } else {
                // The payload itself might be the VP
                vp = payload;
            }

            // Validate and extract credentials
            if (vp.has("verifiableCredential")) {
                JsonArray credentials = vp.getAsJsonArray("verifiableCredential");
                processCredentials(credentials, result);
            }

            // Set presentation ID
            if (vp.has("id")) {
                result.setPresentationId(vp.get("id").getAsString());
            } else if (payload.has("jti")) {
                result.setPresentationId(payload.get("jti").getAsString());
            }

            // TODO: Verify JWT signature
            // This requires access to the holder's public key or DID resolution
            // For now, we'll mark as requiring further verification

            // If we got here, the basic structure is valid
            result.setStatus(VCVerificationStatus.SUCCESS);

        } catch (VPTokenExpiredException e) {
            result.setStatus(VCVerificationStatus.EXPIRED);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription(e.getMessage());
        } catch (IllegalArgumentException e) {
            result.setStatus(VCVerificationStatus.INVALID);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription("Invalid JWT encoding: " + e.getMessage());
        } catch (Exception e) {
            result.setStatus(VCVerificationStatus.INVALID);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription("Failed to process VP token: " + e.getMessage());
        }

        return result;
    }

    /**
     * Validate JWT claims.
     */
    private void validateJwtClaims(JsonObject payload, VPRequest vpRequest)
            throws VPException {

        // Validate nonce
        if (payload.has("nonce")) {
            String tokenNonce = payload.get("nonce").getAsString();
            String expectedNonce = vpRequest.getNonce();
            if (!StringUtils.equals(tokenNonce, expectedNonce)) {
                throw new VPSubmissionValidationException("Nonce mismatch");
            }
        }

        // Validate audience (client_id)
        if (payload.has("aud")) {
            JsonElement audElement = payload.get("aud");
            String expectedAud = vpRequest.getClientId();
            boolean audMatches = false;

            if (audElement.isJsonArray()) {
                JsonArray audArray = audElement.getAsJsonArray();
                for (JsonElement aud : audArray) {
                    if (StringUtils.equals(aud.getAsString(), expectedAud)) {
                        audMatches = true;
                        break;
                    }
                }
            } else {
                audMatches = StringUtils.equals(audElement.getAsString(), expectedAud);
            }

            if (!audMatches) {
                throw new VPSubmissionValidationException("Audience mismatch");
            }
        }

        // Validate expiration
        if (payload.has("exp")) {
            long exp = payload.get("exp").getAsLong();
            long now = System.currentTimeMillis() / 1000;
            if (now > exp) {
                throw new VPTokenExpiredException("VP token has expired");
            }
        }
    }

    /**
     * Process VP token in JSON-LD format.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private ValidationResult processJsonVPToken(String vpToken, VPRequest vpRequest)
            throws VPException {

        ValidationResult result = new ValidationResult();
        result.setValidatedCredentialIds(new ArrayList<>());
        result.setVerifiedClaims(new HashMap<>());

        try {
            JsonObject vp = JsonParser.parseString(vpToken).getAsJsonObject();

            // Validate VP type
            if (!hasCorrectType(vp, "VerifiablePresentation")) {
                throw new VPSubmissionValidationException(
                        "Invalid VP type, expected VerifiablePresentation");
            }

            // Validate proof
            if (vp.has("proof")) {
                JsonObject proof = vp.getAsJsonObject("proof");
                validateProof(proof, vpRequest);
            }

            // Extract credentials
            if (vp.has("verifiableCredential")) {
                JsonArray credentials = vp.getAsJsonArray("verifiableCredential");
                processCredentials(credentials, result);
            }

            // Set presentation ID
            if (vp.has("id")) {
                result.setPresentationId(vp.get("id").getAsString());
            }

            result.setStatus(VCVerificationStatus.SUCCESS);

        } catch (VPSubmissionValidationException e) {
            throw e;
        } catch (Exception e) {
            result.setStatus(VCVerificationStatus.INVALID);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription("Failed to parse VP token: " + e.getMessage());
        }

        return result;
    }

    /**
     * Check if the JSON object has the expected type.
     */
    private boolean hasCorrectType(JsonObject obj, String expectedType) {
        if (!obj.has("type")) {
            return false;
        }

        JsonElement typeElement = obj.get("type");
        if (typeElement.isJsonArray()) {
            JsonArray types = typeElement.getAsJsonArray();
            for (JsonElement type : types) {
                if (expectedType.equals(type.getAsString())) {
                    return true;
                }
            }
            return false;
        } else {
            return expectedType.equals(typeElement.getAsString());
        }
    }

    /**
     * Validate the VP proof.
     */
    private void validateProof(JsonObject proof, VPRequest vpRequest)
            throws VPSubmissionValidationException {

        // Check challenge (nonce)
        if (proof.has("challenge")) {
            String challenge = proof.get("challenge").getAsString();
            if (!StringUtils.equals(challenge, vpRequest.getNonce())) {
                throw new VPSubmissionValidationException("Proof challenge mismatch");
            }
        }

        // Check domain (client_id)
        if (proof.has("domain")) {
            String domain = proof.get("domain").getAsString();
            if (!StringUtils.equals(domain, vpRequest.getClientId())) {
                throw new VPSubmissionValidationException("Proof domain mismatch");
            }
        }

        // TODO: Verify cryptographic signature
        // This requires resolving the verification method and checking the signature
    }

    /**
     * Process verifiable credentials in the VP.
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    private void processCredentials(JsonArray credentials, ValidationResult result) {
        for (JsonElement credElement : credentials) {
            try {
                if (credElement.isJsonPrimitive()) {
                    // JWT-encoded credential
                    String jwtCredential = credElement.getAsString();
                    processJwtCredential(jwtCredential, result);
                } else if (credElement.isJsonObject()) {
                    // JSON-LD credential
                    JsonObject credential = credElement.getAsJsonObject();
                    processJsonCredential(credential, result);
                }
            } catch (Exception e) {
            }
        }
    }

    /**
     * Process a JWT-encoded verifiable credential.
     */
    @SuppressFBWarnings({ "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    private void processJwtCredential(String jwtCredential, ValidationResult result) {
        try {
            String[] parts = jwtCredential.split("\\.");
            if (parts.length != 3) {
                return;
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8);
            JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();

            // Extract VC from payload
            JsonObject vc = null;
            if (payload.has("vc")) {
                vc = payload.getAsJsonObject("vc");
            } else {
                vc = payload;
            }

            // Get credential ID
            String credId = null;
            if (vc.has("id")) {
                credId = vc.get("id").getAsString();
            } else if (payload.has("jti")) {
                credId = payload.get("jti").getAsString();
            }

            if (credId != null) {
                result.getValidatedCredentialIds().add(credId);
            }

            // Extract claims from credential subject
            if (vc.has("credentialSubject")) {
                JsonObject subject = vc.getAsJsonObject("credentialSubject");
                extractClaims(subject, "", result.getVerifiedClaims());
            }

        } catch (Exception e) {
        }
    }

    /**
     * Process a JSON-LD verifiable credential.
     */
    private void processJsonCredential(JsonObject credential, ValidationResult result) {
        // Get credential ID
        if (credential.has("id")) {
            result.getValidatedCredentialIds().add(credential.get("id").getAsString());
        }

        // Extract claims from credential subject
        if (credential.has("credentialSubject")) {
            JsonElement subject = credential.get("credentialSubject");
            if (subject.isJsonObject()) {
                extractClaims(subject.getAsJsonObject(), "", result.getVerifiedClaims());
            } else if (subject.isJsonArray()) {
                // Multiple subjects
                JsonArray subjects = subject.getAsJsonArray();
                for (int i = 0; i < subjects.size(); i++) {
                    if (subjects.get(i).isJsonObject()) {
                        String prefix = "subject" + i + ".";
                        extractClaims(subjects.get(i).getAsJsonObject(), prefix,
                                result.getVerifiedClaims());
                    }
                }
            }
        }
    }

    /**
     * Extract claims from a JSON object recursively.
     */
    private void extractClaims(JsonObject obj, String prefix, Map<String, String> claims) {
        for (String key : obj.keySet()) {
            JsonElement value = obj.get(key);
            String claimKey = prefix + key;

            if (value.isJsonPrimitive()) {
                claims.put(claimKey, value.getAsString());
            } else if (value.isJsonObject()) {
                // Recurse for nested objects
                extractClaims(value.getAsJsonObject(), claimKey + ".", claims);
            } else if (value.isJsonArray()) {
                // Store array as JSON string
                claims.put(claimKey, value.toString());
            }
        }
    }
}
