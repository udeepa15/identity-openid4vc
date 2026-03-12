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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for generating QR codes for OpenID4VP authorization requests.
 * 
 * QR codes can encode:
 * 1. A full authorization request URL (by-value)
 * 2. A request_uri reference (by-reference)
 * 3. An OpenID4VP deep link for mobile wallets
 */
public class QRCodeUtil {

    private QRCodeUtil() {
        // Prevent instantiation
    }

    /**
     * Generate QR code content for a VP request using request_uri flow.
     * 
     * @param requestUri The URI where the full request can be fetched
     * @param clientId   The client ID to include in the authorization request
     * @return QR code content string (OpenID4VP deep link)
     */
    public static String generateRequestUriQRContent(String requestUri, String clientId) {
        if (StringUtils.isBlank(requestUri)) {
            throw new IllegalArgumentException("Request URI cannot be blank");
        }

        // OpenID4VP scheme with request_uri
        StringBuilder content = new StringBuilder();
        content.append(OpenID4VPConstants.Protocol.OPENID4VP_SCHEME);
        content.append("authorize"); // Add authorize path as requested
        content.append("?");

        // Add client_id if present (as requested by user)
        if (StringUtils.isNotBlank(clientId)) {
            content.append(OpenID4VPConstants.RequestParams.CLIENT_ID);
            content.append("=");
            content.append(urlEncode(clientId));
            content.append("&");
        }

        content.append(OpenID4VPConstants.RequestParams.REQUEST_URI);
        content.append("=");
        content.append(urlEncode(requestUri));

        return content.toString();
    }

    /**
     * Generate QR code content for a VP request using by-value flow.
     * 
     * @param authorizationDetails The full authorization details
     * @return QR code content string (OpenID4VP deep link with full request)
     */
    public static String generateByValueQRContent(AuthorizationDetailsDTO authorizationDetails) {
        if (authorizationDetails == null) {
            throw new IllegalArgumentException("Authorization details cannot be null");
        }

        StringBuilder content = new StringBuilder();
        content.append(OpenID4VPConstants.Protocol.OPENID4VP_SCHEME);
        content.append("?");

        // Client ID
        content.append(OpenID4VPConstants.RequestParams.CLIENT_ID);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getClientId()));

        // Response type
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_TYPE);
        content.append("=");
        content.append(OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);

        // Response mode
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_MODE);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getResponseMode()));

        // Response URI
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.RESPONSE_URI);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getResponseUri()));

        // Nonce
        content.append("&");
        content.append(OpenID4VPConstants.RequestParams.NONCE);
        content.append("=");
        content.append(urlEncode(authorizationDetails.getNonce()));

        // State (request ID)
        if (StringUtils.isNotBlank(authorizationDetails.getState())) {
            content.append("&");
            content.append(OpenID4VPConstants.RequestParams.STATE);
            content.append("=");
            content.append(urlEncode(authorizationDetails.getState()));
        }

        // Presentation definition
        if (authorizationDetails.getPresentationDefinition() != null) {
            content.append("&");
            content.append(OpenID4VPConstants.Protocol.PRESENTATION_DEFINITION);
            content.append("=");
            content.append(urlEncode(authorizationDetails.getPresentationDefinition().toString()));
        }

        return content.toString();
    }

    private static String urlEncode(String value) {
        if (value == null) {
            return "";
        }
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is always supported
            return value;
        }
    }
}
