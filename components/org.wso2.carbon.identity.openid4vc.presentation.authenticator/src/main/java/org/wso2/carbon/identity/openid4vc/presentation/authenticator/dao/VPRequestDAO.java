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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheById;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheByTransactionId;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestTransactionIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for VP request operations.
 */
public class VPRequestDAO {

    private static final Log log = LogFactory.getLog(VPRequestDAO.class);
    private final VPRequestCacheById vpRequestCacheById;
    private final VPRequestCacheByTransactionId vpRequestCacheByTransactionId;

    /**
     * Create DAO instance.
     */
    public VPRequestDAO() {

        this.vpRequestCacheById = VPRequestCacheById.getInstance();
        this.vpRequestCacheByTransactionId = VPRequestCacheByTransactionId.getInstance();
    }

    /**
     * Create a new VP request.
     *
     * @param vpRequest VP request to create.
     * @throws VPAuthenticatorException If creation fails.
     */
    public void createVPRequest(VPRequest vpRequest) throws VPAuthenticatorException {

        addToAllCaches(vpRequest);
    }

    /**
     * Get VP request by request ID.
     *
     * @param requestId Request ID.
     * @param tenantId  Tenant ID.
     * @return VP request or null if not found.
     * @throws VPAuthenticatorException If retrieval fails.
     */
    public VPRequest getVPRequestById(String requestId, int tenantId) throws VPAuthenticatorException {

        VPRequestIdCacheKey cacheKey = new VPRequestIdCacheKey(requestId);
        VPRequestCacheEntry entry = vpRequestCacheById.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            VPRequest request = entry.getVPRequest();
            if (request != null && request.getTenantId() != tenantId) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Cross-tenant access detected. Requested tenant: %d, " +
                                    "Actual tenant: %d for request ID: %s",
                            tenantId, request.getTenantId(), sanitizeForLog(requestId)));
                }
                return null;
            }
            return request;
        }
        return null;
    }

    /**
     * Get VP request by transaction ID.
     *
     * @param transactionId Transaction ID.
     * @param tenantId      Tenant ID.
     * @return VP request or null if not found.
     * @throws VPAuthenticatorException If retrieval fails.
     */
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId) throws VPAuthenticatorException {

        VPRequestTransactionIdCacheKey cacheKey = new VPRequestTransactionIdCacheKey(transactionId);
        VPRequestCacheEntry entry = vpRequestCacheByTransactionId.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            VPRequest request = entry.getVPRequest();
            if (request != null && request.getTenantId() != tenantId) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Cross-tenant access detected. Requested tenant: %d, " +
                                    "Actual tenant: %d for transaction ID: %s",
                            tenantId, request.getTenantId(), sanitizeForLog(transactionId)));
                }
                return null;
            }
            return request;
        }
        return null;
    }

    /**
     * Get all request IDs for a transaction.
     *
     * @param transactionId Transaction ID.
     * @param tenantId      Tenant ID.
     * @return List of request IDs.
     * @throws VPAuthenticatorException If retrieval fails.
     */
    public List<String> getRequestIdsByTransactionId(String transactionId, int tenantId)
            throws VPAuthenticatorException {

        List<String> requestIds = new ArrayList<>();
        VPRequest request = getVPRequestByTransactionId(transactionId, tenantId);
        if (request != null) {
            requestIds.add(request.getRequestId());
        }
        return requestIds;
    }

    /**
     * Update VP request status.
     *
     * @param requestId Request ID.
     * @param status    New status.
     * @param tenantId  Tenant ID.
     * @throws VPAuthenticatorException If update fails.
     */
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPAuthenticatorException {

        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            request.setStatus(status);
            addToAllCaches(request);
        }
    }

    /**
     * Update VP request with JWT.
     *
     * @param requestId  Request ID.
     * @param requestJwt JWT string.
     * @param tenantId   Tenant ID.
     * @throws VPAuthenticatorException If update fails.
     */
    public void updateVPRequestJwt(String requestId, String requestJwt, int tenantId)
            throws VPAuthenticatorException {

        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            request.setRequestJwt(requestJwt);
            addToAllCaches(request);
        }
    }

    /**
     * Delete VP request.
     *
     * @param requestId Request ID.
     * @param tenantId  Tenant ID.
     * @throws VPAuthenticatorException If deletion fails.
     */
    public void deleteVPRequest(String requestId, int tenantId) throws VPAuthenticatorException {

        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            if (request.getRequestId() != null) {
                vpRequestCacheById.clearCacheEntry(new VPRequestIdCacheKey(request.getRequestId()), tenantId);
            }
            if (request.getTransactionId() != null) {
                vpRequestCacheByTransactionId.clearCacheEntry(
                        new VPRequestTransactionIdCacheKey(request.getTransactionId()), tenantId);
            }
        }
    }

    /**
     * Get expired VP requests.
     *
     * @param tenantId Tenant ID.
     * @return List of expired VP requests.
     * @throws VPAuthenticatorException If retrieval fails.
     */
    public List<VPRequest> getExpiredVPRequests(int tenantId) throws VPAuthenticatorException {

        return new ArrayList<>();
    }

    /**
     * Update status of expired requests to EXPIRED.
     *
     * @param tenantId Tenant ID.
     * @return Number of requests updated.
     * @throws VPAuthenticatorException If update fails.
     */
    public int markExpiredRequests(int tenantId) throws VPAuthenticatorException {

        return 0;
    }

    /**
     * Get VP requests by status.
     *
     * @param status   Status to filter by.
     * @param tenantId Tenant ID.
     * @return List of VP requests with the given status.
     * @throws VPAuthenticatorException If retrieval fails.
     */
    public List<VPRequest> getVPRequestsByStatus(VPRequestStatus status, int tenantId)
            throws VPAuthenticatorException {

        return new ArrayList<>();
    }

    /**
     * Add a VP request to all caches.
     *
     * @param vpRequest VP request.
     */
    private void addToAllCaches(VPRequest vpRequest) {

        VPRequestCacheEntry cacheEntry = new VPRequestCacheEntry(vpRequest);

        if (vpRequest.getRequestId() != null) {
            vpRequestCacheById.addToCache(new VPRequestIdCacheKey(vpRequest.getRequestId()), cacheEntry,
                    vpRequest.getTenantId());
        }
        if (vpRequest.getTransactionId() != null) {
            vpRequestCacheByTransactionId.addToCache(
                    new VPRequestTransactionIdCacheKey(vpRequest.getTransactionId()), cacheEntry,
                    vpRequest.getTenantId());
        }
    }

    /**
     * Sanitize values for logging to prevent CRLF injection.
     *
     * @param value Value to sanitize.
     * @return Sanitized string.
     */
    private String sanitizeForLog(Object value) {

        if (value == null) {
            return "null";
        }
        return value.toString().replaceAll("[\r\n]", "_");
    }
}
