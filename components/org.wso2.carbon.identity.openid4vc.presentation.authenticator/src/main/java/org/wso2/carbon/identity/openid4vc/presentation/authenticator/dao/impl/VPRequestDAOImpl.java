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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of VPRequestDAO using VPRequestCache (Distributed Cache).
 * Replaces DB storage with Cache-based storage as per new architecture.
 */
public class VPRequestDAOImpl implements VPRequestDAO {

    private static final Log log = LogFactory.getLog(VPRequestDAOImpl.class);
    private final VPRequestCache vpRequestCache;

    public VPRequestDAOImpl() {
        this.vpRequestCache = VPRequestCache.getInstance();
    }

    @Override
    public void createVPRequest(VPRequest vpRequest) throws VPException {
        // Store in cache
        vpRequestCache.put(vpRequest);
    }

    @Override
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public VPRequest getVPRequestById(String requestId, int tenantId) throws VPException {
        // Retrieve from cache
        VPRequest request = vpRequestCache.getByRequestId(requestId);
        if (request != null && request.getTenantId() != tenantId) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cross-tenant access detected. Requested tenant: %d, " +
                                "Actual tenant: %d for request ID: %s",
                        tenantId, request.getTenantId(), requestId));
            }
            return null;
        }
        return request;
    }

    @Override
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId) throws VPException {
        // Retrieve from cache
        VPRequest request = vpRequestCache.getByTransactionId(transactionId);
        if (request != null && request.getTenantId() != tenantId) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Cross-tenant access detected. Requested tenant: %d, " +
                                "Actual tenant: %d for transaction ID: %s",
                        tenantId, request.getTenantId(), transactionId));
            }
            return null;
        }
        return request;
    }

    @Override
    public List<String> getRequestIdsByTransactionId(String transactionId, int tenantId) throws VPException {
        List<String> requestIds = new ArrayList<>();
        VPRequest request = getVPRequestByTransactionId(transactionId, tenantId);
        if (request != null) {
            requestIds.add(request.getRequestId());
        }
        return requestIds;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId) throws VPException {
        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            request.setStatus(status);
            // Updating the object reference in cache is usually sufficient for local map,
            // but for distributed caches, a put() is often required to trigger replication.
            vpRequestCache.put(request);
        }
    }

    @Override
    public void updateVPRequestJwt(String requestId, String requestJwt, int tenantId) throws VPException {
        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            request.setRequestJwt(requestJwt);
            // Re-put to trigger replication if distributed
            vpRequestCache.put(request);
        }
    }

    @Override
    public void deleteVPRequest(String requestId, int tenantId) throws VPException {
        VPRequest request = getVPRequestById(requestId, tenantId);
        if (request != null) {
            vpRequestCache.remove(requestId);
        }
    }

    @Override
    public List<VPRequest> getExpiredVPRequests(int tenantId) throws VPException {
        // Not efficiently supported by cache. Returning empty list as cache handles its own expiry.
        // This method was for the DB cleanup task.
        return new ArrayList<>();
    }

    @Override
    public int markExpiredRequests(int tenantId) throws VPException {
        // Not needed for cache. Cache expiry handles it.
        return 0;
    }

    @Override
    public List<VPRequest> getVPRequestsByStatus(VPRequestStatus status, int tenantId) throws VPException {
        // Iterating cache is expensive and not standard pattern, but supported if needed for admin APIs.
        // For now, returning empty list as this is rarely used in core flow.
        return new ArrayList<>();
    }
}
