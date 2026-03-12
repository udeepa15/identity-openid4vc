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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Exception thrown when a VP request is not found.
 */
public class VPRequestNotFoundException extends VPException {

    /**
     * Default error code.
     */
    private static final String DEFAULT_ERROR_CODE = "VP_REQUEST_NOT_FOUND";

    /**
     * The request ID that was not found.
     */
    private String requestId;

    /**
     * Constructor with request ID.
     *
     * @param reqId The request ID that was not found
     */
    public VPRequestNotFoundException(final String reqId) {

        super(DEFAULT_ERROR_CODE, "VP request not found: " + reqId);
        this.requestId = reqId;
    }

    /**
     * Get the request ID that was not found.
     *
     * @return Request ID
     */
    public String getRequestId() {
        return requestId;
    }
}
