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
 * Exception thrown when VP request has expired.
 */
public class VPRequestExpiredException extends VPException {

    /**
     * Default error code.
     */
    private static final String DEFAULT_ERROR_CODE = "VP_REQUEST_EXPIRED";

    /**
     * The request ID that has expired.
     */
    private String requestId;

    /**
     * The expiry timestamp.
     */
    private long expiredAt;

    /**
     * Constructor with request ID.
     *
     * @param request The request ID that has expired
     */
    public VPRequestExpiredException(final String request) {
        super(DEFAULT_ERROR_CODE, "VP request has expired: " + request);
        this.requestId = request;
    }

    /**
     * Constructor with request ID and expiry time.
     *
     * @param request  Request ID
     * @param expiryTs Expiry timestamp
     */
    public VPRequestExpiredException(final String request,
            final long expiryTs) {
        super(DEFAULT_ERROR_CODE,
                "VP request has expired: " + request + " at " + expiryTs);
        this.requestId = request;
        this.expiredAt = expiryTs;
    }

    /**
     * Get the request ID that has expired.
     *
     * @return Request ID
     */
    public String getRequestId() {
        return requestId;
    }
}
