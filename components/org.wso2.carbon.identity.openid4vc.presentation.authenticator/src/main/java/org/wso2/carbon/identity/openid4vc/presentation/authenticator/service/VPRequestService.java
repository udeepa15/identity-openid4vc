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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Service interface for managing VP requests.
 * Handles creation, retrieval, and status management of authorization requests.
 */
public interface VPRequestService {

    /**
     * Create a new VP authorization request for the authentication session.
     *
     * @param context The authentication context
     * @return VPRequest containing the created request details
     * @throws VPException If an error occurs during request creation
     */
    VPRequest createVPRequest(AuthenticationContext context) throws VPException;

    /**
     * Create a new VP authorization request.
     *
     * @param request    The request model containing creation parameters
     * @param tenantId   The tenant ID
     * @return VPRequest containing the created request details
     * @throws VPException If an error occurs during request creation
     */
    VPRequest createVPRequest(VPRequest request, int tenantId)
            throws VPException;

    /**
     * Get a VP request by its request ID.
     *
     * @param requestId The unique request identifier
     * @param tenantId  The tenant ID
     * @return The VP request
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    VPRequest getVPRequestById(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException;

    /**
     * Get a VP request by its transaction ID.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return The VP request
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    VPRequest getVPRequestByTransactionId(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException;

    /**
     * Get the current status of a VP request.
     *
     * @param transactionId The transaction identifier
     * @param tenantId      The tenant ID
     * @return VPRequest containing the status
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    VPRequest getVPRequestStatus(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException;

    /**
     * Update the status of a VP request.
     *
     * @param requestId The request identifier
     * @param status    The new status
     * @param tenantId  The tenant ID
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPRequestExpiredException  If the request has expired
     * @throws VPException                If an error occurs
     */
    void updateVPRequestStatus(String requestId, VPRequestStatus status,
                               int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException,
            VPException;

    /**
     * Get the request URI for a VP request (for request_uri flow).
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return The request URI
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    String getRequestUri(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException;

    /**
     * Get the signed JWT for a VP request.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return The signed request JWT
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPRequestExpiredException  If the request has expired
     * @throws VPException                If an error occurs
     */
    String getRequestJwt(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException,
            VPException;

}
