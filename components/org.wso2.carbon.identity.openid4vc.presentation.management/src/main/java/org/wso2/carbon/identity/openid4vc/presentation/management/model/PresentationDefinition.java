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

package org.wso2.carbon.identity.openid4vc.presentation.management.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing a Presentation Definition.
 * This defines the credential requirements for a Verifiable Presentation request.
 */
public class PresentationDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String definitionId;
    private String name;
    private String description;
    private int tenantId;
    private List<RequestedCredential> requestedCredentials;

    /**
     * Default constructor.
     */
    public PresentationDefinition() {
    }

    /**
     * Builder pattern constructor.
     */
    private PresentationDefinition(Builder builder) {
        this.definitionId = builder.definitionId;
        this.name = builder.name;
        this.description = builder.description;
        this.tenantId = builder.tenantId;
        this.requestedCredentials = builder.requestedCredentials;
    }

    // Getters and Setters

    public String getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public List<RequestedCredential> getRequestedCredentials() {
        return requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
    }

    public void setRequestedCredentials(List<RequestedCredential> requestedCredentials) {
        this.requestedCredentials = requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
    }

    /**
     * Builder class for PresentationDefinition.
     */
    public static class Builder {
        private String definitionId;
        private String name;
        private String description;
        private int tenantId;
        private List<RequestedCredential> requestedCredentials;

        public Builder definitionId(String definitionId) {
            this.definitionId = definitionId;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder tenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder requestedCredentials(List<RequestedCredential> requestedCredentials) {
            this.requestedCredentials = requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
            return this;
        }

        public PresentationDefinition build() {
            return new PresentationDefinition(this);
        }
    }

    /**
     * Inner model class representing a single requested credential within a Presentation Definition.
     */
    public static class RequestedCredential implements Serializable {

        private static final long serialVersionUID = 1L;

        private String type;
        private String purpose;
        private String issuer;
        private List<String> claims;

        public RequestedCredential() {
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getPurpose() {
            return purpose;
        }

        public void setPurpose(String purpose) {
            this.purpose = purpose;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public List<String> getClaims() {
            return claims != null ? new ArrayList<>(claims) : null;
        }

        public void setClaims(List<String> claims) {
            this.claims = claims != null ? new ArrayList<>(claims) : null;
        }
    }

    @Override
    public String toString() {
        return "PresentationDefinition{" +
                "definitionId='" + definitionId + '\'' +
                ", name='" + name + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
