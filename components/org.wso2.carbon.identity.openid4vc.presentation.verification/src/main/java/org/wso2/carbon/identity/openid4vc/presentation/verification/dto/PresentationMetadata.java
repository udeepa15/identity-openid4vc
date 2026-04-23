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

/**
 * DTO class for Presentation Metadata.
 */
public class PresentationMetadata {

    private String vpFormat;
    private String algorithm;
    private String issuerDid;
    private String holderDid;
    private String nonce;
    private long presentationTime;

    private PresentationMetadata(Builder builder) {
        this.vpFormat = builder.vpFormat;
        this.algorithm = builder.algorithm;
        this.issuerDid = builder.issuerDid;
        this.holderDid = builder.holderDid;
        this.nonce = builder.nonce;
        this.presentationTime = builder.presentationTime;
    }

    public String getVpFormat() {
        return vpFormat;
    }

    public void setVpFormat(String vpFormat) {
        this.vpFormat = vpFormat;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getIssuerDid() {
        return issuerDid;
    }

    public void setIssuerDid(String issuerDid) {
        this.issuerDid = issuerDid;
    }

    public String getHolderDid() {
        return holderDid;
    }

    public void setHolderDid(String holderDid) {
        this.holderDid = holderDid;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public long getPresentationTime() {
        return presentationTime;
    }

    public void setPresentationTime(long presentationTime) {
        this.presentationTime = presentationTime;
    }

    /**
     * Builder class for PresentationMetadata.
     */
    public static class Builder {
        private String vpFormat;
        private String algorithm;
        private String issuerDid;
        private String holderDid;
        private String nonce;
        private long presentationTime;

        public Builder vpFormat(String vpFormat) {
            this.vpFormat = vpFormat;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder issuerDid(String issuerDid) {
            this.issuerDid = issuerDid;
            return this;
        }

        public Builder holderDid(String holderDid) {
            this.holderDid = holderDid;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder presentationTime(long presentationTime) {
            this.presentationTime = presentationTime;
            return this;
        }

        public PresentationMetadata build() {
            return new PresentationMetadata(this);
        }
    }
}
