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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto;

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.io.Serializable;

/**
 * Unified Data Transfer Object for VP (Verifiable Presentation) request lifecycle.
 * Used for request initiation, response delivery, and status tracking.
 */
public class VPRequestDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    // Shared Identifiers
    @SerializedName("transactionId")
    private String transactionId;

    @SerializedName("requestId")
    private String requestId;

    // --- Initiation / Create Fields ---
    @SerializedName("clientId")
    private String clientId;

    @SerializedName("presentationDefinitionId")
    private String presentationDefinitionId;

    @SerializedName("presentationDefinition")
    private JsonObject presentationDefinition;

    @SerializedName("nonce")
    private String nonce;

    @SerializedName("responseMode")
    private String responseMode;

    @SerializedName("didMethod")
    private String didMethod;

    @SerializedName("signingAlgorithm")
    private String signingAlgorithm;

    // --- Response / Delivery Fields ---
    @SerializedName("authorizationDetails")
    private AuthorizationDetailsDTO authorizationDetails;

    @SerializedName("requestUri")
    private String requestUri;

    @SerializedName("expiresAt")
    private Long expiresAt;

    // --- Status / Polling Fields ---
    @SerializedName("status")
    private String status;

    /**
     * Default constructor.
     */
    public VPRequestDTO() {
    }

    // Getters and Setters

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPresentationDefinitionId() {
        return presentationDefinitionId;
    }

    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public JsonObject getPresentationDefinition() {
        return presentationDefinition != null ? presentationDefinition.deepCopy() : null;
    }

    public void setPresentationDefinition(JsonObject presentationDefinition) {
        this.presentationDefinition = presentationDefinition != null ? presentationDefinition.deepCopy() : null;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public String getDidMethod() {
        return didMethod;
    }

    public void setDidMethod(String didMethod) {
        this.didMethod = didMethod;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    public AuthorizationDetailsDTO getAuthorizationDetails() {
        return authorizationDetails != null ? new AuthorizationDetailsDTO(authorizationDetails) : null;
    }

    public void setAuthorizationDetails(AuthorizationDetailsDTO authorizationDetails) {
        this.authorizationDetails = authorizationDetails != null ? new AuthorizationDetailsDTO(authorizationDetails)
                : null;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setStatus(VPRequestStatus status) {
        this.status = status != null ? status.getValue() : null;
    }

    // Helper Methods

    /**
     * Validate the DTO has required fields for creation.
     *
     * @return true if valid for creation, false otherwise
     */
    public boolean isValidForCreation() {
        if (clientId == null || clientId.trim().isEmpty()) {
            return false;
        }
        boolean hasPdId = presentationDefinitionId != null && !presentationDefinitionId.trim().isEmpty();
        boolean hasPd = presentationDefinition != null;
        return hasPdId || hasPd;
    }

    /**
     * Check if this is a request-by-reference response.
     *
     * @return true if requestUri is present
     */
    public boolean isByReference() {
        return requestUri != null && !requestUri.trim().isEmpty();
    }

    @Override
    public String toString() {
        return "VPRequestDTO{" +
                "transactionId='" + transactionId + '\'' +
                ", requestId='" + requestId + '\'' +
                ", status='" + status + '\'' +
                ", isByReference=" + isByReference() +
                ", expiresAt=" + expiresAt +
                '}';
    }
}
