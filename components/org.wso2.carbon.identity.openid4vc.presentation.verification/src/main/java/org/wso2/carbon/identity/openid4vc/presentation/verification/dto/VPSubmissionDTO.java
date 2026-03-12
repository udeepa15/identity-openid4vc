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

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for VP token submission from wallet.
 */
public class VPSubmissionDTO {

    @SerializedName("vp_token")
    private String vpToken;

    @SerializedName("presentation_submission")
    private JsonObject presentationSubmission;

    @SerializedName("state")
    private String state;

    @SerializedName("error")
    private String error;

    @SerializedName("error_description")
    private String errorDescription;

    /**
     * Default constructor.
     */
    public VPSubmissionDTO() {
    }

    // Getters and Setters

    public String getVpToken() {
        return vpToken;
    }

    public void setVpToken(String vpToken) {
        this.vpToken = vpToken;
    }

    public JsonObject getPresentationSubmission() {
        return presentationSubmission != null ? presentationSubmission.deepCopy() : null;
    }

    public void setPresentationSubmission(JsonObject presentationSubmission) {
        this.presentationSubmission = presentationSubmission != null ? presentationSubmission.deepCopy() : null;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    /**
     * Check if this submission contains an error.
     *
     * @return true if error is present
     */
    public boolean hasError() {
        return error != null && !error.trim().isEmpty();
    }

    /**
     * Check if this submission contains a VP token.
     *
     * @return true if VP token is present
     */
    public boolean hasVpToken() {
        return vpToken != null && !vpToken.trim().isEmpty();
    }

    /**
     * Validate the submission is valid per OpenID4VP spec.
     * Either (vp_token + presentation_submission) OR error must be present.
     *
     * @return true if valid
     */
    public boolean isValid() {
        boolean hasValidVpBlock = hasVpToken() && presentationSubmission != null;
        boolean hasValidErrorBlock = hasError() && !hasVpToken() && presentationSubmission == null;
        return hasValidVpBlock || hasValidErrorBlock;
    }

    @Override
    public String toString() {
        return "VPSubmissionDTO{" +
                "hasVpToken=" + hasVpToken() +
                ", hasPresentationSubmission=" + (presentationSubmission != null) +
                ", state='" + state + '\'' +
                ", hasError=" + hasError() +
                '}';
    }
}
