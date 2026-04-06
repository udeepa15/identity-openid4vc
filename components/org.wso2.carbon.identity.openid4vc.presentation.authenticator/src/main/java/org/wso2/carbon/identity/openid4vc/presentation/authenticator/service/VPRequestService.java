/*
 * Copyright (c) 20262 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;

/**
 * Base service contract for managing VP requests.
 */
public abstract class VPRequestService {

    /**
     * Create a new VP authorization request for the authentication session.
     *
     * @param context Authentication context.
     * @return Created VP request.
     * @throws VPAuthenticatorException If an error occurs.
     */
    public abstract VPRequest createVPRequest(AuthenticationContext context)
            throws VPAuthenticatorException;

    /**
     * Get request JWT.
     *
     * @param requestId Request ID.
     * @param tenantId Tenant ID.
     * @return Request JWT.
     * @throws VPAuthenticatorClientException If the request is not found or has expired.
     * @throws VPAuthenticatorException If an error occurs.
     */
    public abstract String getRequestJwt(String requestId, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException;
}
