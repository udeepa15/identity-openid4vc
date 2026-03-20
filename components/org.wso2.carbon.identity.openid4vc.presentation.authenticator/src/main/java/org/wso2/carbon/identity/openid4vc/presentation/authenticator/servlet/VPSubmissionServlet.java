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
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.status.StatusNotificationService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VPSubmissionValidationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VPSubmissionValidator;

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
 * 
 * Endpoint:
 * - POST /openid4vp/v1/response - Receive VP submission from wallet
 * 
 * The wallet submits via application/x-www-form-urlencoded with:
 * - vp_token: The VP token (JWT or JSON-LD)
 * - presentation_submission: JSON describing which credentials satisfy the
 * request
 * - state: The request ID (used as correlation)
 * - error: (Optional) Error code if wallet declined or failed
 * - error_description: (Optional) Error description
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/openid4vp/v1/response",
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
     * Prevents excessively large inputs from reaching downstream logic.
     */
    private static final int MAX_PARAM_LENGTH = 65536;

    /**
     * Status listener cache for long polling notifications.
     */
    private transient VPStatusListenerCache statusListenerCache;

    /**
     * Status notification service for coordinated notifications.
     */
    private transient StatusNotificationService statusNotificationService;

    /**
     * Wallet data cache for storing submissions.
     */
    private transient WalletDataCache walletDataCache;

    @Override
    public void init() throws ServletException {

        super.init();
        this.statusListenerCache = VPStatusListenerCache.getInstance();
        this.statusNotificationService = StatusNotificationService.getInstance();
        this.walletDataCache = WalletDataCache.getInstance();
    }

    /**
     * Handle POST requests - VP submission from wallet.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @throws ServletException If servlet error occurs
     * @throws IOException      If I/O error occurs
     */
    @Override
    protected void doPost(final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Parse submission parameters
            VPSubmissionDTO submissionDTO = parseSubmission(request);
            if (submissionDTO == null) {
                sendErrorResponse(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
                        OpenID4VPConstants.ErrorCodes.INVALID_REQUEST,
                        "Unsupported Content-Type.");
                return;
            }

            // Validate submission using enhanced validator
            try {
                VPSubmissionValidator.validateSubmission(submissionDTO);
            } catch (VPSubmissionValidationException e) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        OpenID4VPConstants.ErrorCodes.INVALID_REQUEST,
                        e.getMessage());
                return;
            }


            // Get tenant ID
            int tenantId = getTenantId(request);
            String requestId = submissionDTO.getState();

            // Build VPSubmission object in-memory
            String presentationSubmissionJson = submissionDTO.getPresentationSubmission() != null
                    ? submissionDTO.getPresentationSubmission().toString()
                    : null;

            VPSubmission submission = new VPSubmission.Builder()
                    .submissionId(OpenID4VPUtil.generateSubmissionId())
                    .requestId(requestId)
                    .vpToken(submissionDTO.getVpToken())
                    .presentationSubmission(presentationSubmissionJson)
                    .verificationStatus(VCVerificationStatus.PENDING)
                    .submittedAt(System.currentTimeMillis())
                    .tenantId(tenantId)
                    .build();

            // Single authoritative cache write happens inside notifyStatusListeners().
            notifyStatusListeners(requestId, submission);

            // Send success response
            sendSuccessResponse(response, submission);

        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    OpenID4VPConstants.ErrorCodes.SERVER_ERROR, "Internal server error");
        }
    }

    /**
     * Parse submission from request parameters.
     * Handles application/x-www-form-urlencoded and JSON content types.
     *
     * @param request HTTP request
     * @return Parsed VPSubmissionDTO
     * @throws IOException If parsing fails
     */
    private VPSubmissionDTO parseSubmission(final HttpServletRequest request)
            throws IOException {

        // Parse form parameters first.
        VPSubmissionDTO dto = new VPSubmissionDTO();
        parseFormEncodedSubmission(request, dto);

        // If no relevant form params are present, try JSON body.
        if (StringUtils.isBlank(dto.getVpToken())
                && StringUtils.isBlank(dto.getState())
                && StringUtils.isBlank(dto.getError())
                && dto.getPresentationSubmission() == null) {
            dto = parseJsonSubmission(request);
        }

        return dto;
    }

    /**
     * Parse form-encoded submission.
     *
     * @param request HTTP request
     * @param dto     DTO to populate
     */
    private void parseFormEncodedSubmission(final HttpServletRequest request,
            final VPSubmissionDTO dto) {

        dto.setVpToken(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.VP_TOKEN));

        String presSubStr = getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION);
        if (StringUtils.isNotBlank(presSubStr)) {
            try {
                dto.setPresentationSubmission(
                        JsonParser.parseString(presSubStr).getAsJsonObject());
            } catch (JsonSyntaxException e) {
            }
        }

        dto.setState(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.STATE));
        dto.setError(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.ERROR));
        dto.setErrorDescription(getDecodedParameter(request,
                OpenID4VPConstants.ResponseParams.ERROR_DESCRIPTION));
    }

    /**
     * Parse JSON submission body.
     *
     * @param request HTTP request
     * @return Parsed DTO
     * @throws IOException If reading fails
     */
    private VPSubmissionDTO parseJsonSubmission(final HttpServletRequest request)
            throws IOException {

        String body = new String(request.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        return GSON.fromJson(body, VPSubmissionDTO.class);
    }

    /**
     * Get URL-decoded parameter value.
     *
     * @param request   HTTP request
     * @param paramName Parameter name
     * @return Decoded value or original if decoding fails
     */
    private String getDecodedParameter(final HttpServletRequest request,
            final String paramName) {

        String value = null;
        if (request.getParameterMap() != null) {
            String[] values = (String[]) request.getParameterMap().get(paramName);
            if (values != null && values.length > 0) {
                value = values[0];
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
     * Notify status listeners for long polling.
     *
     * @param requestId  The request ID (state)
     * @param submission The VP submission
     */
    private void notifyStatusListeners(final String requestId,
            final VPSubmission submission) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }

        // Store submission in wallet data cache for status checks
        if (walletDataCache != null) {
            walletDataCache.storeSubmission(requestId, submission);
        } else {
            LOG.warn("WalletDataCache is null; submission will not be persisted.");
        }

        // Use the centralized notification service
        if (statusNotificationService != null) {
            if (StringUtils.isNotBlank(submission.getError())) {
                statusNotificationService.notifySubmissionError(
                        requestId,
                        submission.getError(),
                        submission.getErrorDescription());
            } else {
                statusNotificationService.notifyVPSubmitted(requestId, submission);
            }
        } else if (statusListenerCache != null) {
            // Direct processing: pass submission to listeners
            statusListenerCache.notifyListenersWithSubmission(requestId, submission);
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
            responseObj.addProperty("transaction_id", submission.getTransactionId());
        }

        String responseJson = GSON.toJson(responseObj);

        byte[] payload = responseJson.getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();

    }

    /**
     * Send error response per OAuth 2.0 spec.
     *
     * @param response         HTTP response
     * @param statusCode       HTTP status code
     * @param errorCode        Error code
     * @param errorDescription Error description
     * @throws IOException If writing fails
     */
    private void sendErrorResponse(final HttpServletResponse response,
            final int statusCode,
            final String errorCode,
            final String errorDescription)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + ";charset=UTF-8");
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Sanitize error values: errorCode is always a server-defined constant,
        // but errorDescription may include user-originated text (e.g. validation messages).
        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", sanitize(errorCode));
        if (StringUtils.isNotBlank(errorDescription)) {
            errorObj.addProperty("error_description", sanitize(errorDescription));
        }

        byte[] payload = GSON.toJson(errorObj).getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    /**
     * Get tenant ID from request context.
     *
     * @param request HTTP request
     * @return Tenant ID
     */
    private int getTenantId(final HttpServletRequest request) {
        // Delegates to ServletUtil which reads from the identity framework context
        // and request attributes — no direct header access.
        return org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil.getTenantId(request);
    }

}

