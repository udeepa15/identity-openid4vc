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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;

/**
 * Utility class for VP Authenticator related operations.
 */
public final class VPAuthenticatorUtil {

    /**
     * Private constructor to prevent instantiation.
     */
    private VPAuthenticatorUtil() {

    }

    /**
     * Resolve tenant-aware base URL from framework utilities.
     *
     * @return Tenant-aware base URL.
     * @throws VPAuthenticatorException If URL resolution fails.
     */
    public static String resolveTenantAwareBaseUrl() throws VPAuthenticatorException {

        try {
            String baseUrl = ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();

            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            if (tenantDomain != null && !Constraints.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
                return baseUrl + Constraints.TENANT_PATH_PREFIX + tenantDomain;
            }

            return baseUrl;

        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving tenant-aware base URL.", e);
        }
    }

    /**
     * Resolve base URL from framework utilities.
     *
     * @return Base URL without tenant prefix.
     * @throws VPAuthenticatorException If URL resolution fails.
     */
    public static String resolveBaseUrl() throws VPAuthenticatorException {

        try {
            return ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();
        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving base URL.", e);
        }
    }

    /**
     * Get the client ID for the given base URL.
     *
     * @param baseUrl Base URL.
     * @return Client ID.
     * @throws VPAuthenticatorClientException If base URL is blank.
     */
    public static String getClientId(String baseUrl)
            throws VPAuthenticatorClientException {

        if (StringUtils.isBlank(baseUrl)) {
            throw new VPAuthenticatorClientException(
                    VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Base URL cannot be null or empty.");
        }

        return Constraints.DID_WEB_PREFIX + baseUrl
                .replaceFirst(Constraints.URL_SCHEME_REGEX, "")
                .replaceAll(Constraints.TRAILING_SLASH_REGEX, "");
    }
}
