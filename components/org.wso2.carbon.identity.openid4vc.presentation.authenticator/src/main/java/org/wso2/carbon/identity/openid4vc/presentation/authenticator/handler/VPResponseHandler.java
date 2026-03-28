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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Handler for OpenID4VP responses.
 * This class handles basic state and error checks for incoming submissions.
 */
public class VPResponseHandler {

    /**
     * Inner class to represent validation results.
     */
    public static class ValidationResult implements Serializable {
        private static final long serialVersionUID = 1L;
        private VerificationResult.VerificationStatus status;
        private String errorCode;
        private String errorDescription;
        private String presentationId;
        private Map<String, String> verifiedClaims = new HashMap<>();

        public VerificationResult.VerificationStatus getStatus() {
            return status;
        }

        public void setStatus(VerificationResult.VerificationStatus status) {
            this.status = status;
        }

        public boolean isValid() {
            return VerificationResult.VerificationStatus.VERIFIED.equals(status);
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

        public String getPresentationId() {
            return presentationId;
        }

        public void setPresentationId(String presentationId) {
            this.presentationId = presentationId;
        }

        public Map<String, String> getVerifiedClaims() {
            return verifiedClaims;
        }

        public void setVerifiedClaims(Map<String, String> verifiedClaims) {
            this.verifiedClaims = verifiedClaims;
        }
    }

    /**
     * Process a VP submission from a wallet.
     * 
     * @param submission The VP submission parameters
     * @param vpRequest  The original VP request
     * @return Validation result
     * @throws VPException If processing fails
     */
    public ValidationResult processSubmission(Map<String, String> submission, VPRequest vpRequest)
            throws VPException {

        if (submission == null) {
            throw new VPSubmissionValidationException("VP submission is null");
        }

        // Check for error response from wallet
        String error = submission.get(OpenID4VPConstants.ResponseParams.ERROR);
        if (StringUtils.isNotBlank(error)) {
            return handleErrorResponse(submission);
        }

        // Validate state matches
        if (!validateState(submission, vpRequest)) {
            ValidationResult result = new ValidationResult();
            result.setStatus(VerificationResult.VerificationStatus.FAILED);
            result.setErrorCode(OpenID4VPConstants.ErrorCodes.INVALID_REQUEST);
            result.setErrorDescription("State parameter mismatch");
            return result;
        }

        // Get VP token
        String vpToken = submission.get(OpenID4VPConstants.ResponseParams.VP_TOKEN);
        if (StringUtils.isBlank(vpToken)) {
            throw new VPSubmissionValidationException("VP token is missing");
        }

        // Basic validation passed.
        // Complex verification will be performed by VerificationService later.
        ValidationResult result = new ValidationResult();
        result.setStatus(VerificationResult.VerificationStatus.VERIFIED);
        return result;
    }

    /**
     * Handle error response from wallet.
     */
    private ValidationResult handleErrorResponse(Map<String, String> submission) {
        ValidationResult result = new ValidationResult();
        result.setStatus(VerificationResult.VerificationStatus.FAILED);
        result.setErrorCode(submission.get(OpenID4VPConstants.ResponseParams.ERROR));
        result.setErrorDescription(submission.get(OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
        return result;
    }

    /**
     * Validate that the state parameter matches.
     */
    private boolean validateState(Map<String, String> submission, VPRequest vpRequest) {
        if (vpRequest == null) {
            return true;
        }
        String submittedState = submission.get(OpenID4VPConstants.ResponseParams.STATE);
        String expectedState = vpRequest.getRequestId();
        return StringUtils.equals(submittedState, expectedState);
    }
}
