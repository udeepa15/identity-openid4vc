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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto;

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for creating a VP (Verifiable Presentation) request.
 */
public class VPRequestCreateDTO {

    @SerializedName("clientId")
    private String clientId;

    @SerializedName("transactionId")
    private String transactionId;

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

    /**
     * Default constructor.
     */
    public VPRequestCreateDTO() {
    }

    /**
     * Constructor with required fields.
     *
     * @param clientId The client ID (verifier's identifier)
     */
    public VPRequestCreateDTO(String clientId) {
        this.clientId = clientId;
    }

    // Getters and Setters

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
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

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
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

    /**
     * Validate the DTO has required fields.
     *
     * @return true if valid, false otherwise
     */
    public boolean isValid() {
        if (clientId == null || clientId.trim().isEmpty()) {
            return false;
        }
        // Either presentationDefinitionId OR presentationDefinition must be provided
        boolean hasPdId = presentationDefinitionId != null && !presentationDefinitionId.trim().isEmpty();
        boolean hasPd = presentationDefinition != null;
        return hasPdId || hasPd;
    }

    @Override
    public String toString() {
        return "VPRequestCreateDTO{" +
                "clientId='" + clientId + '\'' +
                ", transactionId='" + transactionId + '\'' +
                ", presentationDefinitionId='" + presentationDefinitionId + '\'' +
                ", hasPresentationDefinition=" + (presentationDefinition != null) +
                ", responseMode='" + responseMode + '\'' +
                '}';
    }
}
