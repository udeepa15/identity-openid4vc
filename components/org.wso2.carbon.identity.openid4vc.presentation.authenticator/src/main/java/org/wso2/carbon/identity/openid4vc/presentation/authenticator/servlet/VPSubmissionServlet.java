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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.status.StatusNotificationService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.CONTEXT_VP_REQUEST;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.CONTEXT_VP_SUBMISSION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DEFAULT_VP_REQUEST_EXPIRY_MS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS_SUCCESS;

/*/**
 * Servlet handling VP (Verifiable Presentation) submissions from wallets.
 *
 * <p>Implements the OpenID4VP direct_post response mode. This servlet processes
 * both JSON and application/x-www-form-urlencoded submissions, notifies
 * status listeners, and provides spec-compliant feedback to the wallet.</p>
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

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Logger for the VPSubmissionServlet class.
     */
    private static final Log LOG = LogFactory.getLog(VPSubmissionServlet.class);

    /**
     * Gson instance for JSON serialization/deserialization.
     */
    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    /**
     * Maximum allowed length for any request parameter value.
     */
    private static final int MAX_PARAM_LENGTH = 65536;

    /**
     * Service instance for status change notifications.
     */
    private transient StatusNotificationService statusNotificationService;


    /**
     * Initialize the servlet and its dependencies.
     *
     * @throws ServletException If an error occurs during initialization.
     */
    @Override
    public void init() throws ServletException {

        super.init();
        this.statusNotificationService =
                StatusNotificationService.getInstance();
    }

    /**
     * Handle POST requests containing VP submissions.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @throws ServletException If an error occurs in the servlet.
     * @throws IOException      If an I/O error occurs.
     */
    @Override
    protected void doPost(final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Parse submission directly into a builder.
            VPSubmission.Builder submissionBuilder = parseSubmission(request);

            // Get tenant ID and other context.
            VPSubmission submission = submissionBuilder.build();

            // Basic validation.
            if (StringUtils.isBlank(submission.getRequestId())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Missing state parameter."));
                return;
            }

            // Retrieve AuthenticationContext to check status.
            AuthenticationContext context =
                    FrameworkUtils.getAuthenticationContextFromCache(submission.getRequestId());
            if (context == null) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid state parameter."));
                return;
            }

            Object vpRequestContextObj = context.getProperty(CONTEXT_VP_REQUEST);
            if (!(vpRequestContextObj instanceof VPRequestContext)) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid request context."));
                return;
            }

            VPRequestContext vpRequestContext = (VPRequestContext) vpRequestContextObj;
            if (!VPRequestStatus.ACTIVE.equals(vpRequestContext.getRequestStatus())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Request is not in ACTIVE status."));
                return;
            }

            // Check if the request has expired.
            if (isRequestExpired(vpRequestContext)) {
                vpRequestContext.setRequestStatus(VPRequestStatus.EXPIRED);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Request has expired."));
                return;
            }

            if (StringUtils.isBlank(submission.getVpToken())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Missing vp_token."));
                return;
            }
            try {
                // Parse the presentation_submission string into the DTO.
                Gson gson = new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .create();
                PresentationSubmission presentationSubmission = gson
                        .fromJson(submission.getPresentationSubmission(), PresentationSubmission.class);

                VerificationResult verificationResult = VPServiceDataHolder
                        .getVerificationService()
                        .verify(
                                presentationSubmission,
                                getTenantId(request),
                                submission.getVpToken());

                if (!VerificationResult.VerificationStatus.VERIFIED.equals(verificationResult.getStatus())) {
                    vpRequestContext.setRequestStatus(VPRequestStatus.FAILED);
                    FrameworkUtils.addAuthenticationContextToCache(submission.getRequestId(), context);
                    sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                    "VP verification status is not VERIFIED."));
                    return;
                }

                // Store verified claims in the context for handoff to the authenticator.
                context.setProperty("VERIFIED_CLAIMS", verificationResult.getVerifiedClaims());
            } catch (VerificationException e) {
                vpRequestContext.setRequestStatus(VPRequestStatus.FAILED);
                FrameworkUtils.addAuthenticationContextToCache(submission.getRequestId(), context);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "VP verification failed: " + e.getMessage()));
                return;
            } catch (JsonSyntaxException e) {
                vpRequestContext.setRequestStatus(VPRequestStatus.FAILED);
                FrameworkUtils.addAuthenticationContextToCache(submission.getRequestId(), context);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid presentation_submission format."));
                return;
            }

            // Notify listeners.
            notifyStatusListeners(submission.getRequestId(), submission);

            // Send success response.
            sendSuccessResponse(response);

        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission.", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error.", e));
        }
    }

    /**
     * Check if the VP request has expired.
     *
     * @param vpRequestContext VP request context.
     * @return True if expired, false otherwise.
     */
    private boolean isRequestExpired(VPRequestContext vpRequestContext) {

        if (vpRequestContext == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        return (currentTime - vpRequestContext.getCreatedAt()) > DEFAULT_VP_REQUEST_EXPIRY_MS;
    }

    /**
     * Parse submission from request body into a VPSubmission builder.
     *
     * @param request HTTP request.
     * @return A VPSubmission.Builder populated with request data.
     * @throws IOException If an I/O error occurs.
     */
    private VPSubmission.Builder parseSubmission(final HttpServletRequest request)
            throws IOException {

        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        VPSubmission.Builder builder = new VPSubmission.Builder();

        if (StringUtils.isNotBlank(body) && body.trim().startsWith("{")) {
            // Handle JSON body.
            try {
                return GSON.fromJson(body, VPSubmission.Builder.class);
            } catch (JsonSyntaxException e) {
                LOG.warn("Failed to parse JSON submission body.");
            }
        } else {
            // Handle form-encoded body.
            parseFormEncodedSubmission(body, builder);
        }

        return builder;
    }

    /**
     * Parse form-encoded submission into the builder.
     *
     * @param formBody The raw form-encoded body string.
     * @param builder  The builder to populate.
     */
    private void parseFormEncodedSubmission(final String formBody,
                                             final VPSubmission.Builder builder) {

        builder.vpToken(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.VP_TOKEN))
               .presentationSubmission(getDecodedFormParameter(formBody,
                       OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION))
               .requestId(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.STATE));
    }

    /**
     * Get URL-decoded parameter value from a form-encoded body.
     *
     * @param formBody  The raw form-encoded body string.
     * @param paramName Parameter name to extract.
     * @return Decoded value, or null if not found or invalid.
     */
    private String getDecodedFormParameter(final String formBody,
            final String paramName) {

        // Validating parameter name against a whitelist to build trust for SpotBugs.
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
                // Special handling for vp_token to remove extraneous quotes if present (inji).
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

    /**
     * Decode a single form token.
     *
     * @param value The token to decode.
     * @return The decoded token.
     */
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
     * Notify status listeners and store the submission in the cache.
     *
     * @param requestId  The request ID (state).
     * @param submission The VP submission data.
     */
    private void notifyStatusListeners(final String requestId,
            final VPSubmission submission) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }

        // Store the submission in the context for handoff to the authenticator.
        AuthenticationContext context =
                FrameworkUtils.getAuthenticationContextFromCache(requestId);
        if (context != null) {
            context.setProperty(CONTEXT_VP_SUBMISSION, submission);

            Object vpRequestContextObj = context.getProperty(CONTEXT_VP_REQUEST);
            if (vpRequestContextObj instanceof VPRequestContext) {
                ((VPRequestContext) vpRequestContextObj).setRequestStatus(VPRequestStatus.VP_SUBMITTED);
            } else {
                context.setProperty(CONTEXT_VP_REQUEST,
                        new VPRequestContext(null, VPRequestStatus.VP_SUBMITTED));
            }

            FrameworkUtils.addAuthenticationContextToCache(requestId, context);

            // Update the context in the cache using the masked requestId (alias).
            String maskedId = (String) context.getProperty("VP_REQUEST_ID");
            if (StringUtils.isNotBlank(maskedId) && !maskedId.equals(requestId)) {
                FrameworkUtils.addAuthenticationContextToCache(maskedId, context);
            }
        } else {
            LOG.warn("AuthenticationContext not found for state ID; "
                    + "submission status and data will not be updated.");
        }

        // Use the centralized notification service.
        if (statusNotificationService != null) {
            statusNotificationService.notifyVPSubmitted(requestId);
        }
    }

    /**
     * Send success response to wallet.
     *
     * @param response   HTTP response.
     * @throws IOException If writing fails.
     */
    private void sendSuccessResponse(final HttpServletResponse response)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);

        // Build response object per OpenID4VP spec.
        JsonObject responseObj = new JsonObject();
        responseObj.addProperty(RESPONSE_STATUS, RESPONSE_STATUS_SUCCESS);

        String responseJson = GSON.toJson(responseObj);

        byte[] payload = responseJson.getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    /**
     * Send error response per OAuth 2.0 spec.
     *
     * @param response   HTTP response.
     * @param statusCode HTTP status code.
     * @param exception  The exception to send as error.
     * @throws IOException If writing fails.
     */
    private void sendErrorResponse(final HttpServletResponse response,
                                    final int statusCode,
                                    final VPAuthenticatorException exception)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);

        // Use exception values for error response.
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
     * Resolve the tenant ID from the request context or attributes.
     *
     * @param request HTTP request.
     * @return Tenant ID.
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

