/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for Servlets to handle common HTTP request parameters.
 */
public class ServletUtil {

    private static final String PARAM_LONG_POLL = "long_poll";
    private static final String PARAM_TIMEOUT = "timeout";
    private static final long MAX_TIMEOUT_SECONDS = 120L;
    private static final long DEFAULT_TIMEOUT_SECONDS = 5L;
    private static final int DEFAULT_TENANT_ID = -1234;
    private static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    private ServletUtil() {
    }

    /**
     * Check if long polling is enabled for this request.
     *
     * @param request HTTP request
     * @return true if long polling is enabled
     */
    public static boolean isLongPollingEnabled(final HttpServletRequest request) {

        String longPollParam = getFirstParameter(request, PARAM_LONG_POLL);
        longPollParam = sanitizeParam(longPollParam);
        if (longPollParam != null) {
            return "true".equalsIgnoreCase(longPollParam)
                    || "1".equals(longPollParam);
        }

        // If timeout parameter is provided, assume long polling
        String timeoutParam = getFirstParameter(request, PARAM_TIMEOUT);
        timeoutParam = sanitizeParam(timeoutParam);
        return StringUtils.isNotBlank(timeoutParam);
    }

    /**
     * Get timeout seconds from request.
     *
     * @param request HTTP request
     * @return timeout seconds
     */
    public static long getTimeoutSeconds(final HttpServletRequest request) {

        String timeoutParam = getFirstParameter(request, PARAM_TIMEOUT);
        timeoutParam = sanitizeParam(timeoutParam);
        if (StringUtils.isNotBlank(timeoutParam)) {
            try {
                long timeout = Long.parseLong(timeoutParam);
                if (timeout > 0 && timeout <= MAX_TIMEOUT_SECONDS) {
                    return timeout;
                }
                if (timeout > MAX_TIMEOUT_SECONDS) {
                    return MAX_TIMEOUT_SECONDS;
                }
            } catch (NumberFormatException e) {
            }
        }
        return DEFAULT_TIMEOUT_SECONDS;
    }

    /**
     * Get tenant ID from request.
     *
     * @param request HTTP request
     * @return tenant ID
     */
    public static int getTenantId(final HttpServletRequest request) {

        String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
        if (StringUtils.isBlank(tenantDomain)) {
            Object tenantDomainAttribute = request.getAttribute("tenantDomain");
            tenantDomain = tenantDomainAttribute instanceof String ? (String) tenantDomainAttribute : null;
        }

        if (StringUtils.isNotBlank(tenantDomain)
                && tenantDomain.matches(TENANT_DOMAIN_PATTERN)) {
            try {
                return org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignore.
            }
        }

        return DEFAULT_TENANT_ID;
    }

    /**
     * Strip CRLF/control characters from request parameter input.
     *
     * @param value Request parameter value.
     * @return Sanitized parameter value.
     */
    private static String sanitizeParam(final String value) {

        if (value == null) {
            return null;
        }
        return value.replace('\r', '_').replace('\n', '_').replaceAll("[\\p{Cntrl}]", "");
    }

    /**
     * Read the first value for a request parameter from the parameter map.
     *
     * @param request HTTP request.
     * @param name Parameter name.
     * @return First value, or null.
     */
    private static String getFirstParameter(final HttpServletRequest request, final String name) {

        if (request == null || StringUtils.isBlank(name) || request.getParameterMap() == null) {
            return null;
        }

        String[] values = (String[]) request.getParameterMap().get(name);
        if (values == null || values.length == 0) {
            return null;
        }
        return values[0];
    }
}
