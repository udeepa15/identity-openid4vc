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

import java.io.Serializable;
import java.util.Map;

/**
 * DTO class for verification result.
 */
public class VerificationResult implements Serializable {

    private static final long serialVersionUID = 159357486201L;

    private Map<String, Object> verifiedClaims;
    private VerificationStatus status;

    public Map<String, Object> getVerifiedClaims() {
        return verifiedClaims;
    }

    public void setVerifiedClaims(Map<String, Object> verifiedClaims) {
        this.verifiedClaims = verifiedClaims;
    }

    public VerificationStatus getStatus() {
        return status;
    }

    public void setStatus(VerificationStatus status) {
        this.status = status;
    }

    /**
     * Enum for verification status.
     */
    public enum VerificationStatus {
        SUBMITTED,
        PENDING,
        VERIFIED,
        FAILED
    }
}
