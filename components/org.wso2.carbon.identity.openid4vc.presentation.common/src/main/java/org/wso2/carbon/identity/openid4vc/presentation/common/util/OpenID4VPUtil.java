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

package org.wso2.carbon.identity.openid4vc.presentation.common.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Utility class for OpenID4VP operations.
 */
public class OpenID4VPUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generate a unique request ID.
     *
     * @return A unique request ID
     */
    public static String generateRequestId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique transaction ID.
     *
     * @return A unique transaction ID
     */
    public static String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique submission ID.
     *
     * @return A unique submission ID
     */
    public static String generateSubmissionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a cryptographically secure nonce.
     *
     * @return A secure nonce string
     */
    public static String generateNonce() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }

    /**
     * Get the VP request expiry time in seconds.
     *
     * @return Expiry time in seconds
     */
    public static int getVPRequestExpirySeconds() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.VP_REQUEST_EXPIRY_SECONDS);
        if (StringUtils.isNotBlank(configValue)) {
            try {
                return Integer.parseInt(configValue);
            } catch (NumberFormatException e) {
                            }
        }
        return OpenID4VPConstants.Defaults.VP_REQUEST_EXPIRY_SECONDS;
    }

    /**
     * Calculate the expiry timestamp for a VP request.
     *
     * @param createdAt The creation timestamp
     * @return The expiry timestamp
     */
    public static long calculateExpiryTime(long createdAt) {
        return createdAt + (getVPRequestExpirySeconds() * 1000L);
    }

    /**
     * Check if a timestamp is expired.
     *
     * @param expiresAt The expiry timestamp
     * @return true if the timestamp is in the past
     */
    public static boolean isExpired(long expiresAt) {
        return System.currentTimeMillis() > expiresAt;
    }

    /**
     * Check if the request_uri mode is enabled.
     *
     * @return true if request_uri mode is enabled
     */
    public static boolean isRequestUriEnabled() {
        String configValue = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.ENABLE_REQUEST_URI);
        return StringUtils.isBlank(configValue) || Boolean.parseBoolean(configValue);
    }

    /**
     * Build the request URI for a VP request.
     *
     * @param baseUrl   The base URL of the authorization server
     * @param requestId The request ID
     * @return The request URI
     */
    public static String buildRequestUri(String baseUrl, String requestId) {
        StringBuilder uri = new StringBuilder(baseUrl);
        if (!baseUrl.endsWith("/")) {
            uri.append("/");
        }
        uri.append("openid4vp/v1");
        uri.append(OpenID4VPConstants.Endpoints.REQUEST_URI);
        uri.append("/").append(requestId);
        return uri.toString();
    }

    /**
     * Build the response URI for a VP request.
     *
     * @param baseUrl The base URL of the authorization server
     * @return The response URI
     */
    public static String buildResponseUri(String baseUrl) {
        StringBuilder uri = new StringBuilder(baseUrl);
        if (!baseUrl.endsWith("/")) {
            uri.append("/");
        }
        uri.append("openid4vp/v1");
        uri.append(OpenID4VPConstants.Endpoints.VP_RESPONSE);
        return uri.toString();
    }

    /**
     * Validate a client ID.
     *
     * @param clientId The client ID to validate
     * @return true if the client ID is valid
     */
    public static boolean isValidClientId(String clientId) {
        return StringUtils.isNotBlank(clientId);
    }

    /**
     * Validate a nonce.
     *
     * @param nonce The nonce to validate
     * @return true if the nonce is valid
     */
    public static boolean isValidNonce(String nonce) {
        return StringUtils.isNotBlank(nonce) && nonce.length() >= 16;
    }

    /**
     * Get the configured base URL.
     * Falls back to the Identity Server's configured hostname from deployment.toml
     * if OpenID4VP.BaseUrl is not explicitly configured in identity.xml.
     *
     * @return The base URL
     */
    public static String getBaseUrl() {
        // First try the explicit OpenID4VP configuration
        String baseUrl = IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.BASE_URL);
        if (StringUtils.isNotBlank(baseUrl)) {
            return baseUrl;
        }

        // Fall back to the server's configured hostname (from deployment.toml [server] section)
        String serverUrl = IdentityUtil.getServerURL("", true, true);
        if (StringUtils.isNotBlank(serverUrl)) {
            return serverUrl;
        }

        throw new IllegalStateException("Unable to determine server base URL. " +
                "Configure [server].hostname in deployment.toml or add OpenID4VP.BaseUrl to identity.xml.");
    }

    /**
     * Get the tenant-aware base URL.
     * Appends /t/{tenantDomain} to the base URL if the tenant is not carbon.super.
     *
     * @param tenantDomain The tenant domain
     * @return The tenant-aware base URL
     */
    public static String getTenantAwareBaseUrl(String tenantDomain) {
        String baseUrl = getBaseUrl();
        if (StringUtils.isNotBlank(tenantDomain) &&
                !org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(
                        tenantDomain)) {
            if (baseUrl.endsWith("/")) {
                baseUrl = baseUrl + "t/" + tenantDomain;
            } else {
                baseUrl = baseUrl + "/t/" + tenantDomain;
            }
        }
        return baseUrl;
    }
}
