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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCacheByRequestId;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionRequestIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

/**
 * Manager for retrieving current VP request status.
 */
public class PollingManager {

    /**
     * Singleton instance of PollingManager.
     */
    private static volatile PollingManager instance;

    /**
     * Cache for VP submissions by request ID.
     */
    private VPSubmissionCacheByRequestId vpSubmissionCache;

    /**
     * DAO for accessing VP request store.
     */
    private VPRequestDAO vpRequestDAO;

    /**
     * Private constructor for singleton initialization.
     *
     * <p>Initializes the internal submission cache and the request DAO.</p>
     */
    private PollingManager() {

        this.vpSubmissionCache = VPSubmissionCacheByRequestId.getInstance();
        this.vpRequestDAO = new VPRequestDAO();
    }

    /**
     * Get the singleton instance of the PollingManager.
     *
     * @return PollingManager instance.
     */
    public static PollingManager getInstance() {

        if (instance == null) {
            synchronized (PollingManager.class) {
                if (instance == null) {
                    instance = new PollingManager();
                }
            }
        }
        return instance;
    }

    /**
     * Check the current status of a VP request without waiting.
     *
     * @param requestId Request ID to check.
     * @param tenantId  Tenant ID.
     * @return PollingResult with the current status of the request.
     */
    public PollingResult checkCurrentStatus(final String requestId, final int tenantId) {

        if (vpSubmissionCache.getValueFromCache(new VPSubmissionRequestIdCacheKey(requestId), tenantId) != null) {
            return PollingResult.submitted(requestId, VPRequestStatus.VP_SUBMITTED.name());
        }

        try {
            VPRequest vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);

            if (vpRequest == null) {
                return PollingResult.notFound(requestId);
            }

            VPRequestStatus status = vpRequest.getStatus();

            switch (status) {
                case VP_SUBMITTED:
                case COMPLETED:
                    return PollingResult.submitted(requestId, VPRequestStatus.VP_SUBMITTED.name());
                case EXPIRED:
                    return PollingResult.expired(requestId);
                case ACTIVE:
                default:
                    if (isRequestExpired(vpRequest)) {
                        return PollingResult.expired(requestId);
                    }
                    return PollingResult.waiting(requestId);
            }
        } catch (VPAuthenticatorException e) {
            return PollingResult.error(requestId, e.getMessage());
        }
    }

    /**
     * Check if a VP request has expired based on its timestamp.
     *
     * @param vpRequest VP request to check.
     * @return True if the request has expired, false otherwise.
     */
    private boolean isRequestExpired(final VPRequest vpRequest) {

        return vpRequest.getExpiresAt() > 0
                && System.currentTimeMillis() > vpRequest.getExpiresAt();
    }
}
