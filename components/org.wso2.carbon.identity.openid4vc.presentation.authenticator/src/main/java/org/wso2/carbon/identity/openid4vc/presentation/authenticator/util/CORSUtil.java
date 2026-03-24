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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Utility class for handling CORS (Cross-Origin Resource Sharing) headers.
 */
public final class CORSUtil {

    /**
     * Add CORS headers to the response.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void addCORSHeaders(HttpServletRequest request, HttpServletResponse response) {
        // Deny by default: do not add CORS allow headers unless an explicit, reviewed
        // endpoint-specific policy is implemented by the caller.
    }


    /**
     * Add CORS headers for preflight requests.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     */
    public static void handlePreflight(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
