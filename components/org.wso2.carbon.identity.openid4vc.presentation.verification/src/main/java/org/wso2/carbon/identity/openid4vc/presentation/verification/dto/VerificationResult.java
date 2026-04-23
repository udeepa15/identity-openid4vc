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

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DTO class for verification result.
 */
public class VerificationResult {

    private boolean isVerified;
    private String statusMessage;
    private List<String> errors;
    private Map<String, Object> verifiedClaims;
    private PresentationMetadata metadata;

    public VerificationResult() {
        this.errors = new ArrayList<>();
        this.verifiedClaims = new HashMap<>();
    }

    private VerificationResult(Builder builder) {
        this.isVerified = builder.isVerified;
        this.statusMessage = builder.statusMessage;
        this.errors = builder.errors != null ? builder.errors : new ArrayList<>();
        this.verifiedClaims = builder.verifiedClaims != null ? builder.verifiedClaims : new HashMap<>();
        this.metadata = builder.metadata;
    }

    public boolean isVerified() {
        return isVerified;
    }

    public void setVerified(boolean verified) {
        isVerified = verified;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public Map<String, Object> getVerifiedClaims() {
        return verifiedClaims;
    }

    public void setVerifiedClaims(Map<String, Object> verifiedClaims) {
        this.verifiedClaims = verifiedClaims;
    }

    public PresentationMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(PresentationMetadata metadata) {
        this.metadata = metadata;
    }

    /**
     * Builder class for VerificationResult.
     */
    public static class Builder {
        private boolean isVerified;
        private String statusMessage;
        private List<String> errors = new ArrayList<>();
        private Map<String, Object> verifiedClaims = new HashMap<>();
        private PresentationMetadata metadata;

        public Builder isVerified(boolean isVerified) {
            this.isVerified = isVerified;
            return this;
        }

        public Builder statusMessage(String statusMessage) {
            this.statusMessage = statusMessage;
            return this;
        }

        public Builder errors(List<String> errors) {
            this.errors = errors;
            return this;
        }

        public Builder addError(String error) {
            this.errors.add(error);
            return this;
        }

        public Builder verifiedClaims(Map<String, Object> verifiedClaims) {
            this.verifiedClaims = verifiedClaims;
            return this;
        }

        public Builder metadata(PresentationMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        public VerificationResult build() {
            return new VerificationResult(this);
        }
    }
}
