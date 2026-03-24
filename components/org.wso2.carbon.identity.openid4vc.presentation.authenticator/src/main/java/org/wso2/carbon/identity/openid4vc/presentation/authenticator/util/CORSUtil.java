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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Utility class for handling CORS (Cross-Origin Resource Sharing) headers.
 */
public final class CORSUtil {

    private static final String HEADER_ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
    private static final String HEADER_ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
    private static final String HEADER_ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
    private static final String HEADER_ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";

    private static final String DEFAULT_ALLOWED_METHODS = "GET, POST, PUT, DELETE, OPTIONS";
    private static final String DEFAULT_ALLOWED_HEADERS = "Content-Type, Authorization, X-Requested-With, Accept, " +
            "Origin, X-Tenant-Id, X-CSRF-Token";
    private static final String DEFAULT_EXPOSED_HEADERS = "Content-Type, X-Request-Id, X-Transaction-Id";
    private static final String DEFAULT_MAX_AGE = "86400"; // 24 hours

    /**
     * Add CORS headers to the response.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void addCORSHeaders(HttpServletRequest request, HttpServletResponse response) {
        String allowedOrigins = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.CORS_ALLOWED_ORIGINS);
        if (StringUtils.isBlank(allowedOrigins)) {
            // Default to server's own origin if not configured, to avoid permissive policy
            try {
                allowedOrigins = OpenID4VPUtil.getBaseUrl();
            } catch (Exception e) {
                allowedOrigins = "*"; // Last resort, but should be avoided in production
            }
        }

        if ("*".equals(allowedOrigins)) {
            response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        } else {
            // If specific origins are allowed, we might need to match against request origin
            // but for now we set the configured value strictly to resolve SERVLET_HEADER
            response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, allowedOrigins);
        }

        response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_METHODS, DEFAULT_ALLOWED_METHODS);
        response.setHeader(HEADER_ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_ALLOWED_HEADERS);
        response.setHeader(HEADER_ACCESS_CONTROL_MAX_AGE, DEFAULT_MAX_AGE);
        response.setHeader(HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, DEFAULT_EXPOSED_HEADERS);
    }


    /**
     * Add CORS headers for preflight requests.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void handlePreflight(HttpServletRequest request, HttpServletResponse response) {
        addCORSHeaders(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
