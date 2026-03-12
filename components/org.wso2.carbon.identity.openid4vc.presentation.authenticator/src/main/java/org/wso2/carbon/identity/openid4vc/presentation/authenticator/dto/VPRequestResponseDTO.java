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

import com.google.gson.annotations.SerializedName;

/**
 * Data Transfer Object for VP request response.
 * This is returned after creating an authorization request.
 */
public class VPRequestResponseDTO {

    @SerializedName("transactionId")
    private String transactionId;

    @SerializedName("requestId")
    private String requestId;

    @SerializedName("authorizationDetails")
    private AuthorizationDetailsDTO authorizationDetails;

    @SerializedName("requestUri")
    private String requestUri;

    @SerializedName("expiresAt")
    private Long expiresAt;

    /**
     * Default constructor.
     */
    public VPRequestResponseDTO() {
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

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }

    /**
     * Check if this is a request-by-reference response.
     *
     * @return true if request_uri is present
     */
    public boolean isByReference() {
        return requestUri != null && !requestUri.trim().isEmpty();
    }

    @Override
    public String toString() {
        return "VPRequestResponseDTO{" +
                "transactionId='" + transactionId + '\'' +
                ", requestId='" + requestId + '\'' +
                ", isByReference=" + isByReference() +
                ", expiresAt=" + expiresAt +
                '}';
    }
}
