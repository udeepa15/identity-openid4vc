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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCacheByRequestId;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionRequestIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.status.StatusNotificationService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling VP (Verifiable Presentation) submissions from wallets.
 * Implements the OpenID4VP direct_post response mode.
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/oid4vp/v1/response",
        "osgi.http.whiteboard.servlet.name=OpenID4VPSubmission",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPSubmissionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(VPSubmissionServlet.class);
    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    /**
     * Maximum allowed length for any request parameter value.
     */
    private static final int MAX_PARAM_LENGTH = 65536;

    private transient StatusNotificationService statusNotificationService;
    private transient VPSubmissionCacheByRequestId vpSubmissionCache;

    @Override
    public void init() throws ServletException {
        super.init();
        this.statusNotificationService =
                StatusNotificationService.getInstance();
        this.vpSubmissionCache = VPSubmissionCacheByRequestId.getInstance();
    }

    @Override
    protected void doPost(final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Parse submission directly into a builder
            VPSubmission.Builder submissionBuilder = parseSubmission(request);
            
            // Get tenant ID and other context
            int tenantId = getTenantId(request);
            submissionBuilder.submissionId(OpenID4VPUtil.generateSubmissionId())
                    .submittedAt(System.currentTimeMillis())
                    .tenantId(tenantId);
            
            VPSubmission submission = submissionBuilder.build();

            // Basic validation
            if (StringUtils.isBlank(submission.getRequestId())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Missing state parameter."));
                return;
            }

            if (StringUtils.isBlank(submission.getVpToken()) && StringUtils.isBlank(submission.getError())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Missing vp_token or error."));
                return;
            }

            // Notify listeners
            notifyStatusListeners(submission.getRequestId(), submission);

            // Send success response
            sendSuccessResponse(response, submission);

        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error", e));
        }
    }

    /**
     * Parse submission from request body into a VPSubmission builder.
     */
    private VPSubmission.Builder parseSubmission(final HttpServletRequest request)
            throws IOException {

        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        VPSubmission.Builder builder = new VPSubmission.Builder();

        if (StringUtils.isNotBlank(body) && body.trim().startsWith("{")) {
            // Handle JSON body
            try {
                return GSON.fromJson(body, VPSubmission.Builder.class);
            } catch (JsonSyntaxException e) {
                LOG.warn("Failed to parse JSON submission body.");
            }
        } else {
            // Handle form-encoded body
            parseFormEncodedSubmission(body, builder);
        }

        return builder;
    }

    /**
     * Parse form-encoded submission into the builder.
     */
    private void parseFormEncodedSubmission(final String formBody,
                                             final VPSubmission.Builder builder) {

        builder.vpToken(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.VP_TOKEN))
               .presentationSubmission(getDecodedFormParameter(formBody, 
                       OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION))
               .requestId(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.STATE))
               .error(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.ERROR))
               .errorDescription(getDecodedFormParameter(formBody, 
                       OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
    }

    /**
     * Get URL-decoded parameter value.
     *
     * @param request   HTTP request
     * @param paramName Parameter name
     * @return Decoded value or original if decoding fails
     */
    private String getDecodedFormParameter(final String formBody,
            final String paramName) {

        // Validating parameter name against a whitelist to build trust for SpotBugs
        if (!OpenID4VPConstants.ResponseParams.VP_TOKEN.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.STATE.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.ERROR.equals(paramName)
                && !OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION.equals(paramName)) {
            return null;
        }

        String value = null;
        if (StringUtils.isNotBlank(formBody)) {
            String[] pairs = formBody.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length == 0) {
                    continue;
                }
                String key = decodeFormToken(keyValue[0]);
                if (paramName.equals(key)) {
                    value = keyValue.length > 1 ? keyValue[1] : "";
                    break;
                }
            }
        }

        if (StringUtils.isNotBlank(value)) {
            // Enforce maximum length to prevent oversized input.
            if (value.length() > MAX_PARAM_LENGTH) {
                value = value.substring(0, MAX_PARAM_LENGTH);
            }
            try {
                String decodedValue = URLDecoder.decode(value, StandardCharsets.UTF_8.name());
                // Special handling for vp_token to remove extraneous quotes if present (inji)
                if (OpenID4VPConstants.ResponseParams.VP_TOKEN.equals(paramName)) {
                    String sanitizedValue = decodedValue.trim();

                    if (sanitizedValue.startsWith("\"") && sanitizedValue.endsWith("\"")) {
                        sanitizedValue = sanitizedValue.substring(1, sanitizedValue.length() - 1).trim();
                    }

                    sanitizedValue = StringUtils.strip(sanitizedValue, "\"");

                    if (!StringUtils.equals(decodedValue, sanitizedValue) && LOG.isDebugEnabled()) {
                        LOG.debug("Sanitized quoted vp_token in decoded request parameter.");
                    }

                    return sanitizedValue;
                }

                return decodedValue;
            } catch (IllegalArgumentException | java.io.UnsupportedEncodingException e) {
                return sanitize(value);
            }
        }
        return value;
    }

    private String decodeFormToken(final String value) {
        if (value == null) {
            return null;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (IllegalArgumentException | java.io.UnsupportedEncodingException e) {
            return sanitize(value);
        }
    }

    /**
     * Strip CRLF and HTML-significant characters from a string to prevent
     * log injection and reflected-XSS in error responses.
     *
     * @param input The raw string.
     * @return The sanitized string, or an empty string if {@code input} is null.
     */
    private String sanitize(final String input) {
        if (input == null) {
            return "";
        }
        // Remove carriage-return, newline and HTML tag characters.
        return input.replace('\r', '_').replace('\n', '_')
                .replaceAll("[<>\"']", "_");
    }

    /**
     * Notify status listeners.
     *
     * @param requestId  The request ID (state).
     * @param submission The VP submission.
     */
    private void notifyStatusListeners(final String requestId,
            final VPSubmission submission) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }

        // Store submission in wallet data cache for status checks
        if (vpSubmissionCache != null) {
            vpSubmissionCache.addToCache(new VPSubmissionRequestIdCacheKey(requestId), 
                    new VPSubmissionCacheEntry(submission), submission.getTenantId());
        } else {
            LOG.warn("VPSubmissionCache is null; submission will not be persisted.");
        }

        // Use the centralized notification service
        if (statusNotificationService != null) {
            if (StringUtils.isNotBlank(submission.getError())) {
                statusNotificationService.notifySubmissionError(
                        requestId,
                        submission.getError(),
                        submission.getErrorDescription());
            } else {
                statusNotificationService.notifyVPSubmitted(requestId);
            }
        }

    }

    /**
     * Send success response to wallet.
     *
     * @param response   HTTP response
     * @param submission The processed submission
     * @throws IOException If writing fails
     */
    private void sendSuccessResponse(final HttpServletResponse response,
            final VPSubmission submission)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + ";charset=UTF-8");
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Build response object per OpenID4VP spec
        // Values are server-generated (submission IDs), not reflected user input.
        JsonObject responseObj = new JsonObject();
        responseObj.addProperty("status", "received");
        responseObj.addProperty("submission_id", submission.getSubmissionId());

        // Add transaction ID if present for tracking
        if (submission.getTransactionId() != null) {
            responseObj.addProperty("transaction_id",
                    submission.getTransactionId());
        }

        String responseJson = GSON.toJson(responseObj);

        byte[] payload = responseJson.getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();

    }

    /**
     * Send error response per OAuth 2.0 spec.
     *
     * @param response   HTTP response
     * @param statusCode HTTP status code
     * @param exception  The exception to send as error
     * @throws IOException If writing fails
     */
    private void sendErrorResponse(final HttpServletResponse response,
                                    final int statusCode,
                                    final VPAuthenticatorException exception)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + ";charset=UTF-8");
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Use exception values for error response
        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", sanitize(exception.getOAuth2ErrorCode()));
        errorObj.addProperty("error_description",
                sanitize(exception.getMessage()));
        errorObj.addProperty("error_code", exception.getCode());

        byte[] payload = GSON.toJson(errorObj).getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    /**
     * Default tenant ID to use when tenant domain cannot be resolved.
     */
    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * Pattern to validate tenant domain names.
     */
    private static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    /**
     * Get tenant ID from request context.
     *
     * @param request HTTP request
     * @return Tenant ID
     */
    private int getTenantId(final HttpServletRequest request) {

        String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil
                .getTenantDomainFromContext();
        if (StringUtils.isBlank(tenantDomain)) {
            Object tenantDomainAttribute = request.getAttribute("tenantDomain");
            tenantDomain = tenantDomainAttribute instanceof String
                    ? (String) tenantDomainAttribute : null;
        }

        if (StringUtils.isNotBlank(tenantDomain)
                && tenantDomain.matches(TENANT_DOMAIN_PATTERN)) {
            try {
                return org.wso2.carbon.identity.core.util.IdentityTenantUtil
                        .getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignore.
            }
        }

        return DEFAULT_TENANT_ID;
    }

}

