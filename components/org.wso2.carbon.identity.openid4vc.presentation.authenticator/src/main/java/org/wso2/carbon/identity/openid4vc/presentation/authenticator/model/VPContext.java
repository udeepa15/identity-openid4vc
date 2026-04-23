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



import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.Serializable;

/**
 * Context model that stores VP request status and other session-bound data in a single cacheable object.
 */
public class VPContext implements Serializable {

    private static final long serialVersionUID = 1L;

    private VPRequestStatus requestStatus;
    private VerificationResult verificationResult;

    /**
     * Create a VP context.
     *
     * @param requestStatus Current VP request status.
     */
    public VPContext(VPRequestStatus requestStatus) {

        this.requestStatus = requestStatus;
    }

    /**
     * Returns the request status.
     *
     * @return Request status.
     */
    public VPRequestStatus getRequestStatus() {

        return requestStatus;
    }

    /**
     * Sets the request status.
     *
     * @param requestStatus Request status.
     */
    public void setRequestStatus(VPRequestStatus requestStatus) {

        this.requestStatus = requestStatus;
    }

    /**
     * Returns the verification result.
     *
     * @return Verification result.
     */
    public VerificationResult getVerificationResult() {

        return verificationResult;
    }

    /**
     * Sets the verification result.
     *
     * @param verificationResult Verification result.
     */
    public void setVerificationResult(VerificationResult verificationResult) {

        this.verificationResult = verificationResult;
    }
}
