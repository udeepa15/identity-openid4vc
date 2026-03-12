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

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Service interface for managing VP (Verifiable Presentation) requests.
 * Handles the creation, retrieval, and status management of authorization requests
 * for verifiable presentations as per OpenID4VP specification.
 */
public interface VPRequestService {

    /**
     * Create a new VP authorization request.
     *
     * @param requestCreateDTO The DTO containing request creation parameters
     * @param tenantId         The tenant ID
     * @return VPRequestResponseDTO containing the created request details
     * @throws VPException If an error occurs during request creation
     */
    VPRequestResponseDTO createVPRequest(VPRequestCreateDTO requestCreateDTO, int tenantId) 
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
     * @return VPRequestStatusDTO containing the status
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    VPRequestStatusDTO getVPRequestStatus(String transactionId, int tenantId) 
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
    void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId) 
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException;

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
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException;

    /**
     * Delete a VP request.
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    void deleteVPRequest(String requestId, int tenantId) 
            throws VPRequestNotFoundException, VPException;

    /**
     * Process and mark expired requests.
     *
     * @param tenantId The tenant ID
     * @return The number of requests marked as expired
     * @throws VPException If an error occurs
     */
    int processExpiredRequests(int tenantId) throws VPException;

    /**
     * Validate if a VP request is still active (not expired).
     *
     * @param requestId The request identifier
     * @param tenantId  The tenant ID
     * @return true if the request is active
     * @throws VPRequestNotFoundException If the request is not found
     * @throws VPException                If an error occurs
     */
    boolean isRequestActive(String requestId, int tenantId) 
            throws VPRequestNotFoundException, VPException;
}
