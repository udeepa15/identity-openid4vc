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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import java.io.Serializable;

/**
 * Model class representing a Verifiable Presentation Request.
 * This corresponds to an OpenID4VP authorization request.
 */
public class VPRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String requestId;
    private String transactionId;
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

    private VPRequest(Builder builder) {
        this.requestId = builder.requestId;
        this.transactionId = builder.transactionId;
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
    }

    public String getRequestId() {
        return requestId;
    }

    /**
     * Set request ID.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param requestId Request ID
     */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    /**
     * Set transaction ID.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param transactionId Transaction ID
     */
    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getClientId() {
        return clientId;
    }

    /**
     * Set client ID.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param clientId Client ID
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param nonce Nonce
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getPresentationDefinitionId() {
        return presentationDefinitionId;
    }

    /**
     * Set presentation definition ID.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param presentationDefinitionId Presentation definition ID
     */
    public void setPresentationDefinitionId(String presentationDefinitionId) {
        this.presentationDefinitionId = presentationDefinitionId;
    }

    public String getPresentationDefinition() {
        return presentationDefinition;
    }

    /**
     * Set presentation definition.
     * Note: This setter exists for lazy-loading PD. New instances should use Builder.
     *
     * @param presentationDefinition Presentation definition JSON
     */
    public void setPresentationDefinition(String presentationDefinition) {
        this.presentationDefinition = presentationDefinition;
    }

    public String getResponseUri() {
        return responseUri;
    }

    /**
     * Set response URI.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param responseUri Response URI
     */
    public void setResponseUri(String responseUri) {
        this.responseUri = responseUri;
    }

    public String getResponseMode() {
        return responseMode;
    }

    /**
     * Set response mode.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param responseMode Response mode
     */
    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public String getRequestJwt() {
        return requestJwt;
    }

    /**
     * Set request JWT.
     * Note: This setter is used to update the JWT after initial creation. New instances should use Builder.
     *
     * @param requestJwt Request JWT
     */
    public void setRequestJwt(String requestJwt) {
        this.requestJwt = requestJwt;
    }

    public VPRequestStatus getStatus() {
        return status;
    }

    /**
     * Set status.
     * Note: This setter is used for status updates (ACTIVE → SUBMITTED → COMPLETED). New instances should use Builder.
     *
     * @param status VP request status
     */
    public void setStatus(VPRequestStatus status) {
        this.status = status;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    /**
     * Set expiration timestamp.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param expiresAt Expiration timestamp
     */
    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public int getTenantId() {
        return tenantId;
    }

    /**
     * Set tenant ID.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param tenantId Tenant ID
     */
    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public String getDidMethod() {
        return didMethod;
    }

    /**
     * Set DID method.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param didMethod DID method
     */
    public void setDidMethod(String didMethod) {
        this.didMethod = didMethod;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * Set signing algorithm.
     * Note: This setter exists for DAO/cache updates. New instances should use Builder.
     *
     * @param signingAlgorithm Signing algorithm
     */
    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    public String toString() {
        return "VPRequest{" +
                "requestId='" + requestId + '\'' +
                ", transactionId='" + transactionId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", status=" + status +
                ", expiresAt=" + expiresAt +
                ", tenantId=" + tenantId +
                ", didMethod='" + didMethod + '\'' +
                ", signingAlgorithm='" + signingAlgorithm + '\'' +
                '}';
    }

    /**
     * Builder class for VPRequest.
     */
    public static class Builder {
        private String requestId;
        private String transactionId;
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

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder transactionId(String transactionId) {
            this.transactionId = transactionId;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder presentationDefinitionId(String presentationDefinitionId) {
            this.presentationDefinitionId = presentationDefinitionId;
            return this;
        }

        public Builder presentationDefinition(String presentationDefinition) {
            this.presentationDefinition = presentationDefinition;
            return this;
        }

        public Builder responseUri(String responseUri) {
            this.responseUri = responseUri;
            return this;
        }

        public Builder responseMode(String responseMode) {
            this.responseMode = responseMode;
            return this;
        }

        public Builder requestJwt(String requestJwt) {
            this.requestJwt = requestJwt;
            return this;
        }

        public Builder status(VPRequestStatus status) {
            this.status = status;
            return this;
        }

        public Builder expiresAt(long expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder didMethod(String didMethod) {
            this.didMethod = didMethod;
            return this;
        }

        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        public VPRequest build() {
            return new VPRequest(this);
        }
    }
}
