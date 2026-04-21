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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Utility class for fetching HTTP contents, removing duplicated HttpURLConnection logic.
 */
public final class HttpClientUtil {

    private static final int HTTP_CONNECT_TIMEOUT = 5000;
    private static final int HTTP_READ_TIMEOUT = 5000;
    private static final int HTTP_OK = 200;
    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    /**
     * Creates a utility class instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only static utility methods.</p>
     */
    private HttpClientUtil() {
    }

    /**
     * Opens a URL connection for the provided URI string.
     *
     * @param uriString The URI string to open
     * @return The opened {@link java.net.URLConnection}
     * @throws IOException If the connection cannot be opened
     */
    @SuppressFBWarnings("URLCONNECTION_SSRF_FD")
    @SuppressWarnings("squid:S836")
    private static java.net.URLConnection openSafeConnection(String uriString) throws IOException {

        return new java.net.URL(uriString).openConnection();
    }

    /**
         * Fetches a URL response body as a UTF-8 string.
         *
         * <p>Security checks include protocol validation, host validation, SSRF IP
         * filtering, redirect disabling, and response-size bounds enforcement.</p>
         *
         * @param urlString The URL to fetch
         * @param headers Optional request headers, or {@code null}
         * @return The response body when HTTP status is {@code 200}; otherwise {@code null}
         * @throws VerificationException If URL validation or network processing fails
     */
    public static String fetchContent(final String urlString, Map<String, String> headers) 
            throws VerificationException {

        URI uri;
        try {
            uri = new java.net.URL(urlString).toURI();
        } catch (java.net.MalformedURLException | URISyntaxException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Invalid URL syntax or unhandled protocol: " + urlString, e);
        }

        if (!VerificationConstants.HTTP_PREFIX.equalsIgnoreCase(uri.getScheme()) &&
                !VerificationConstants.HTTPS_PREFIX.equalsIgnoreCase(uri.getScheme())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL, 
                    "Unsupported protocol: " + uri.getScheme());
        }

        if (uri.getHost() == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL, 
                    "Invalid host in URL: " + urlString);
        }

        // SSRF Protection: Validate the IP address
        validateIpAddress(uri.getHost());

        HttpURLConnection con;
        try {
            con = (HttpURLConnection) openSafeConnection(uri.toString());
            
            // SSRF Protection: Disable automatic redirects to prevent bypassing IP validation
            con.setInstanceFollowRedirects(false);

            con.setRequestMethod("GET");
            con.setConnectTimeout(HTTP_CONNECT_TIMEOUT);
            con.setReadTimeout(HTTP_READ_TIMEOUT);

            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    con.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }

            int status = con.getResponseCode();
            if (status != HTTP_OK) {
                return null;
            }

            try (InputStream is = con.getInputStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                    if (baos.size() > MAX_RESPONSE_SIZE) {
                        throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                                "Response body exceeds maximum allowed size of " + MAX_RESPONSE_SIZE + " bytes");
                    }
                }
                return baos.toString(StandardCharsets.UTF_8.name());
            } finally {
                con.disconnect();
            }
        } catch (IOException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error fetching content from URL: " + urlString, e);
        }
    }

    /**
        * Fetches and parses JSON content from a URL.
        *
        * @param urlString The URL to fetch
        * @return The parsed {@link JsonObject}, or {@code null} for non-{@code 200} responses
        * @throws VerificationException If retrieval fails or the payload is not valid JSON
     */
    public static JsonObject fetchJson(final String urlString) throws VerificationException {

        String content = fetchContent(urlString, null);
        if (content == null) {
            return null;
        }
        try {
            return JsonParser.parseString(content).getAsJsonObject();
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to parse JSON content from URL: " + urlString, e);
        }
    }

    /**
        * Validates that the resolved host IP addresses are public and not internal.
        *
        * @param host The host name to resolve and validate
        * @throws VerificationException If host resolution fails or an internal/restricted
        *                               address is detected
     */
    private static void validateIpAddress(String host) throws VerificationException {

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isRestrictedAddress(address)) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "SSRF Validation Failed: Target resolves to an internal or restricted IP address.");
                }
            }
        } catch (UnknownHostException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "SSRF Validation Failed: Unknown host.", e);
        }
    }

    /**
     * Checks if the given address is a restricted (non-global) address.
     *
     * @param addr The address to check
     * @return {@code true} if the address is restricted, {@code false} otherwise
     */
    private static boolean isRestrictedAddress(InetAddress addr) {

        if (addr == null) {
            return true;
        }

        if (addr.isLoopbackAddress() ||
                addr.isAnyLocalAddress() ||
                addr.isLinkLocalAddress() ||
                addr.isSiteLocalAddress() ||
                addr.isMulticastAddress()) {
            return true;
        }

        // Check for IPv6 unique-local addresses (fc00::/7)
        byte[] raw = addr.getAddress();
        if (raw.length == 16) { // IPv6
            return (raw[0] & 0xFE) == 0xFC;
        }

        return false;
    }
}
