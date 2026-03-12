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
 * Data Transfer Object containing authorization request details.
 * Used for request-by-value responses.
 */
public class AuthorizationDetailsDTO {

    @SerializedName("clientId")
    private String clientId;

    @SerializedName("responseType")
    private String responseType;

    @SerializedName("responseMode")
    private String responseMode;

    @SerializedName("responseUri")
    private String responseUri;

    @SerializedName("nonce")
    private String nonce;

    @SerializedName("state")
    private String state;

    @SerializedName("presentationDefinition")
    private JsonObject presentationDefinition;

    /**
     * Default constructor.
     */
    public AuthorizationDetailsDTO() {
        this.responseType = "vp_token";
        this.responseMode = "direct_post";
    }

    /**
     * Copy constructor.
     *
     * @param authorizationDetails AuthorizationDetailsDTO to copy
     */
    public AuthorizationDetailsDTO(AuthorizationDetailsDTO authorizationDetails) {
        this.clientId = authorizationDetails.clientId;
        this.responseType = authorizationDetails.responseType;
        this.responseMode = authorizationDetails.responseMode;
        this.responseUri = authorizationDetails.responseUri;
        this.nonce = authorizationDetails.nonce;
        this.state = authorizationDetails.state;
        this.presentationDefinition = authorizationDetails.presentationDefinition != null
                ? authorizationDetails.presentationDefinition.deepCopy()
                : null;
    }

    // Getters and Setters

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getResponseMode() {
        return responseMode;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public String getResponseUri() {
        return responseUri;
    }

    public void setResponseUri(String responseUri) {
        this.responseUri = responseUri;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public JsonObject getPresentationDefinition() {
        return presentationDefinition != null ? presentationDefinition.deepCopy() : null;
    }

    public void setPresentationDefinition(JsonObject presentationDefinition) {
        this.presentationDefinition = presentationDefinition != null ? presentationDefinition.deepCopy() : null;
    }

    @Override
    public String toString() {
        return "AuthorizationDetailsDTO{" +
                "clientId='" + clientId + '\'' +
                ", responseType='" + responseType + '\'' +
                ", responseMode='" + responseMode + '\'' +
                ", responseUri='" + responseUri + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
}
