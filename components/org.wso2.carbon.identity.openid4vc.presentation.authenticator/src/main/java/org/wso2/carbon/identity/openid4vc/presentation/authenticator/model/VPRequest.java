/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;


/**
 * Model class representing a Verifiable Presentation Request.
 * This corresponds to an OpenID4VP authorization request.
 */
public class VPRequest {


    /**
     * Unique identifier for the VP request.
     */
    private String requestId;


    /**
     * Client ID of the relying party making the request.
     */
    private String clientId;

    /**
     * Nonce value to prevent replay attacks.
     */
    private String nonce;

    /**
     * Identifier for the presentation definition.
     */
    private String presentationDefinitionId;

    /**
     * The presentation definition JSON string.
     */
    private String presentationDefinition;

    /**
     * URI where the response should be sent.
     */
    private String responseUri;

    /**
     * Mode of the response (e.g., direct_post).
     */
    private String responseMode;

    /**
     * The signed request JWT sent to the wallet.
     */
    private String requestJwt;

    /**
     * Current status of the VP request.
     */
    private VPRequestStatus status;

    /**
     * Timestamp when the request expires.
     */
    private long expiresAt;

    /**
     * Tenant ID associated with the request.
     */
    private int tenantId;

    /**
     * DID method used for signing.
     */
    private String didMethod;

    /**
     * Algorithm used for signing the request.
     */
    private String signingAlgorithm;

    /**
     * URI for the request if sent as request_uri.
     */
    private String requestUri;

    /**
     * Private constructor for VPRequest using the Builder.
     *
     * @param builder The VPRequest builder.
     */
    private VPRequest(Builder builder) {

        this.requestId = builder.requestId;
        this.clientId = builder.clientId;
        this.nonce = builder.nonce;
        this.presentationDefinitionId = builder.presentationDefinitionId;
        this.presentationDefinition = builder.presentationDefinition;
        this.responseUri = builder.responseUri;
        this.responseMode = builder.responseMode;
        this.requestJwt = builder.requestJwt;
        this.status = builder.status;
        this.expiresAt = builder.expiresAt;
        this.tenantId = builder.tenantId;
        this.didMethod = builder.didMethod;
        this.signingAlgorithm = builder.signingAlgorithm;
        this.requestUri = builder.requestUri;
    }

    /**
     * Get the unique request identifier.
     *
     * @return The request ID string.
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Set the unique request identifier.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param requestId The request identifier string.
     */
    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }


    /**
     * Get the client identifier.
     *
     * @return The client ID string.
     */
    public String getClientId() {

        return clientId;
    }

    /**
     * Set the client identifier.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param clientId The client identifier string.
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    /**
     * Get the nonce value.
     *
     * @return The nonce string.
     */
    public String getNonce() {

        return nonce;
    }

    /**
     * Set the nonce value.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param nonce The nonce string.
     */
    public void setNonce(String nonce) {

        this.nonce = nonce;
    }

    /**
     * Get the presentation definition ID.
     *
     * @return The presentation definition ID string.
     */
    public String getPresentationDefinitionId() {

        return presentationDefinitionId;
    }

    /**
     * Set the presentation definition ID.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param presentationDefinitionId The presentation definition identifier string.
     */
    public void setPresentationDefinitionId(String presentationDefinitionId) {

        this.presentationDefinitionId = presentationDefinitionId;
    }

    /**
     * Get the presentation definition JSON string.
     *
     * @return The presentation definition JSON string.
     */
    public String getPresentationDefinition() {

        return presentationDefinition;
    }

    /**
     * Set the presentation definition JSON string.
     *
     * <p>Note: This setter exists for lazy-loading. New instances should use Builder.</p>
     *
     * @param presentationDefinition The presentation definition JSON string.
     */
    public void setPresentationDefinition(String presentationDefinition) {

        this.presentationDefinition = presentationDefinition;
    }

    /**
     * Get the response URI.
     *
     * @return The response URI string.
     */
    public String getResponseUri() {

        return responseUri;
    }

    /**
     * Set the response URI.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param responseUri The response URI string.
     */
    public void setResponseUri(String responseUri) {

        this.responseUri = responseUri;
    }

    /**
     * Get the response mode.
     *
     * @return The response mode string.
     */
    public String getResponseMode() {

        return responseMode;
    }

    /**
     * Set the response mode.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param responseMode The response mode string.
     */
    public void setResponseMode(String responseMode) {

        this.responseMode = responseMode;
    }

    /**
     * Get the request JWT.
     *
     * @return The request JWT string.
     */
    public String getRequestJwt() {

        return requestJwt;
    }

    /**
     * Set the request JWT string.
     *
     * <p>Note: This setter is used to update the JWT after initial creation. New instances should use Builder.</p>
     *
     * @param requestJwt The request JWT string.
     */
    public void setRequestJwt(String requestJwt) {

        this.requestJwt = requestJwt;
    }

    /**
     * Get the current status of the VP request.
     *
     * @return The VPRequestStatus enum value.
     */
    public VPRequestStatus getStatus() {

        return status;
    }

    /**
     * Set the current status of the VP request.
     *
     * <p>Note: This setter is used for status updates (e.g., ACTIVE to COMPLETED).
     * New instances should use Builder.</p>
     *
     * @param status The VP request status to set.
     */
    public void setStatus(VPRequestStatus status) {

        this.status = status;
    }

    /**
     * Get the expiration timestamp of the request.
     *
     * @return The expiration timestamp in milliseconds.
     */
    public long getExpiresAt() {

        return expiresAt;
    }

    /**
     * Set the expiration timestamp of the request.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param expiresAt The expiration timestamp in milliseconds.
     */
    public void setExpiresAt(long expiresAt) {

        this.expiresAt = expiresAt;
    }

    /**
     * Get the tenant ID associated with the request.
     *
     * @return The tenant ID integer.
     */
    public int getTenantId() {

        return tenantId;
    }

    /**
     * Set the tenant ID associated with the request.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param tenantId The tenant ID integer.
     */
    public void setTenantId(int tenantId) {

        this.tenantId = tenantId;
    }

    /**
     * Get the DID method used for the request.
     *
     * @return The DID method string.
     */
    public String getDidMethod() {

        return didMethod;
    }

    /**
     * Set the DID method used for the request.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param didMethod The DID method string.
     */
    public void setDidMethod(String didMethod) {

        this.didMethod = didMethod;
    }

    /**
     * Get the signing algorithm used for the request.
     *
     * @return The signing algorithm string.
     */
    public String getSigningAlgorithm() {

        return signingAlgorithm;
    }

    /**
     * Set the signing algorithm used for the request.
     *
     * <p>Note: This setter exists for DAO/cache updates. New instances should use Builder.</p>
     *
     * @param signingAlgorithm The signing algorithm string.
     */
    public void setSigningAlgorithm(String signingAlgorithm) {

        this.signingAlgorithm = signingAlgorithm;
    }

    /**
     * Get the request URI.
     *
     * @return The request URI string.
     */
    public String getRequestUri() {

        return requestUri;
    }

    /**
     * Set the request URI.
     *
     * @param requestUri The request URI string.
     */
    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }

    /**
     * Returns a string representation of the VPRequest.
     *
     * @return String representing the request.
     */
    @Override
    public String toString() {

        return "VPRequest{" +
                "requestId='" + requestId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", status=" + status +
                ", expiresAt=" + expiresAt +
                ", tenantId=" + tenantId +
                ", didMethod='" + didMethod + '\'' +
                ", signingAlgorithm='" + signingAlgorithm + '\'' +
                '}';
    }

    /**
     * Builder class for generating VPRequest instances.
     */
    public static class Builder {

        private String requestId;
        private String clientId;
        private String nonce;
        private String presentationDefinitionId;
        private String presentationDefinition;
        private String responseUri;
        private String responseMode;
        private String requestJwt;
        private VPRequestStatus status;
        private long expiresAt;
        private int tenantId;
        private String didMethod;
        private String signingAlgorithm;
        private String requestUri;

        /**
         * Set the request ID.
         *
         * @param requestId The request identifier.
         * @return The builder instance.
         */
        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }


        /**
         * Set the client ID.
         *
         * @param clientId The client identifier.
         * @return The builder instance.
         */
        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        /**
         * Set the nonce.
         *
         * @param nonce The nonce string.
         * @return The builder instance.
         */
        public Builder nonce(String nonce) {

            this.nonce = nonce;
            return this;
        }

        /**
         * Set the presentation definition ID.
         *
         * @param presentationDefinitionId The presentation definition identifier.
         * @return The builder instance.
         */
        public Builder presentationDefinitionId(String presentationDefinitionId) {

            this.presentationDefinitionId = presentationDefinitionId;
            return this;
        }

        /**
         * Set the presentation definition JSON.
         *
         * @param presentationDefinition The presentation definition string.
         * @return The builder instance.
         */
        public Builder presentationDefinition(String presentationDefinition) {

            this.presentationDefinition = presentationDefinition;
            return this;
        }

        /**
         * Set the response URI.
         *
         * @param responseUri The response URI string.
         * @return The builder instance.
         */
        public Builder responseUri(String responseUri) {

            this.responseUri = responseUri;
            return this;
        }

        /**
         * Set the response mode.
         *
         * @param responseMode The response mode string.
         * @return The builder instance.
         */
        public Builder responseMode(String responseMode) {

            this.responseMode = responseMode;
            return this;
        }

        /**
         * Set the request JWT.
         *
         * @param requestJwt The request JWT string.
         * @return The builder instance.
         */
        public Builder requestJwt(String requestJwt) {

            this.requestJwt = requestJwt;
            return this;
        }

        /**
         * Set the request status.
         *
         * @param status The VP request status.
         * @return The builder instance.
         */
        public Builder status(VPRequestStatus status) {

            this.status = status;
            return this;
        }

        /**
         * Set the expiration timestamp.
         *
         * @param expiresAt The timestamp in milliseconds.
         * @return The builder instance.
         */
        public Builder expiresAt(long expiresAt) {

            this.expiresAt = expiresAt;
            return this;
        }

        /**
         * Set the tenant ID.
         *
         * @param tenantId The tenant identifier.
         * @return The builder instance.
         */
        public Builder tenantId(int tenantId) {

            this.tenantId = tenantId;
            return this;
        }

        /**
         * Set the DID method.
         *
         * @param didMethod The DID method string.
         * @return The builder instance.
         */
        public Builder didMethod(String didMethod) {

            this.didMethod = didMethod;
            return this;
        }

        /**
         * Set the signing algorithm.
         *
         * @param signingAlgorithm The signing algorithm string.
         * @return The builder instance.
         */
        public Builder signingAlgorithm(String signingAlgorithm) {

            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        /**
         * Set the request URI.
         *
         * @param requestUri The request URI string.
         * @return The builder instance.
         */
        public Builder requestUri(String requestUri) {

            this.requestUri = requestUri;
            return this;
        }

        /**
         * Create the VPRequest instance.
         *
         * @return A new VPRequest object.
         */
        public VPRequest build() {

            return new VPRequest(this);
        }
    }
}
