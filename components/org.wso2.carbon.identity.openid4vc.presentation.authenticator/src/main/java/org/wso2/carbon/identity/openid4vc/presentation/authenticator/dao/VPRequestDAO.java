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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.util.List;

/**
 * Data Access Object interface for VP Request operations.
 */
public interface VPRequestDAO {

    /**
     * Create a new VP request.
     *
     * @param vpRequest VP request to create
     * @throws VPException if creation fails
     */
    void createVPRequest(VPRequest vpRequest) throws VPException;

    /**
     * Get VP request by request ID.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @return VP request or null if not found
     * @throws VPException if retrieval fails
     */
    VPRequest getVPRequestById(String requestId, int tenantId) throws VPException;

    /**
     * Get VP request by transaction ID.
     *
     * @param transactionId Transaction ID
     * @param tenantId      Tenant ID
     * @return VP request or null if not found
     * @throws VPException if retrieval fails
     */
    VPRequest getVPRequestByTransactionId(String transactionId, int tenantId) throws VPException;

    /**
     * Get all request IDs for a transaction.
     *
     * @param transactionId Transaction ID
     * @param tenantId      Tenant ID
     * @return List of request IDs
     * @throws VPException if retrieval fails
     */
    List<String> getRequestIdsByTransactionId(String transactionId, int tenantId) throws VPException;

    /**
     * Update VP request status.
     *
     * @param requestId Request ID
     * @param status    New status
     * @param tenantId  Tenant ID
     * @throws VPException if update fails
     */
    void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId) 
            throws VPException;

    /**
     * Update VP request with JWT.
     *
     * @param requestId  Request ID
     * @param requestJwt JWT string
     * @param tenantId   Tenant ID
     * @throws VPException if update fails
     */
    void updateVPRequestJwt(String requestId, String requestJwt, int tenantId) throws VPException;

    /**
     * Delete VP request.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @throws VPException if deletion fails
     */
    void deleteVPRequest(String requestId, int tenantId) throws VPException;

    /**
     * Get expired VP requests.
     *
     * @param tenantId Tenant ID
     * @return List of expired VP requests
     * @throws VPException if retrieval fails
     */
    List<VPRequest> getExpiredVPRequests(int tenantId) throws VPException;

    /**
     * Update status of expired requests to EXPIRED.
     *
     * @param tenantId Tenant ID
     * @return Number of requests updated
     * @throws VPException if update fails
     */
    int markExpiredRequests(int tenantId) throws VPException;

    /**
     * Get VP requests by status.
     *
     * @param status   Status to filter by
     * @param tenantId Tenant ID
     * @return List of VP requests with the given status
     * @throws VPException if retrieval fails
     */
    List<VPRequest> getVPRequestsByStatus(VPRequestStatus status, int tenantId) throws VPException;
}
