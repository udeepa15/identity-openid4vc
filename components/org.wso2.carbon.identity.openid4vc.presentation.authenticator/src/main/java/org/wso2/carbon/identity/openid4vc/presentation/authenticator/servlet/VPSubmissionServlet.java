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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS_SUCCESS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SUPER_TENANT_ID_PLACEHOLDER;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.TENANT_DOMAIN_PATTERN;

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
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .setPrettyPrinting()
            .create();

    /**
     * Maximum allowed length for any request parameter value.
     */
    private static final int MAX_PARAM_LENGTH = 65536;


    /**
     * Initialize the servlet and its dependencies.
     *
     * @throws ServletException If an error occurs during initialization.
     */
    @Override
    public void init() throws ServletException {

        super.init();
    }

    /**
     * Handle POST requests containing VP submissions.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @throws IOException      If an I/O error occurs.
     */
    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response)
            throws IOException {

        try {
            // Parse submission directly into the model.
            VPSubmission submission = parseSubmission(request);

            if (!validateRequiredSubmissionFields(submission, response)) {
                return;
            }

            AuthenticationContext context = FrameworkUtils
                    .getAuthenticationContextFromCache(submission.getRequestId());

            // Retrieve VPContext and expected definition ID from the same context.
            VPContext vpContext = getVPContext(context).orElse(null);
            String expectedDefinitionId = StringUtils.trimToNull(context.getAuthenticatorProperties().
                    get(PROP_PRESENTATION_DEFINITION_ID));

            if (vpContext == null) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid state parameter."));
                return;
            }

            try {
                if (!validatePresentationDefinitionId(expectedDefinitionId,
                        submission.getPresentationSubmission(), response)) {
                    return;
                }

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
 
                if (!verificationResult.isVerified()) {
                    vpContext.setRequestStatus(VPRequestStatus.FAILED);
                    updateVPContext(submission.getRequestId(), vpContext);
                    
                    String errorMsg = "VP verification failed.";
                    if (verificationResult.getErrors() != null && !verificationResult.getErrors().isEmpty()) {
                        errorMsg = "Verification failed: " + String.join(", ", verificationResult.getErrors());
                    }
                    sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                    errorMsg));
                    return;
                }
 
                // Store verification result in the request context for handoff to the authenticator.
                vpContext.setVerificationResult(verificationResult);
                
                // Add PresentationMetadata for Audit Logging and Adaptive Auth
                if (verificationResult.getMetadata() != null) {
                    context.setProperty("vp_metadata", verificationResult.getMetadata());
                    // Since context is modified, we save it immediately
                    FrameworkUtils.addAuthenticationContextToCache(submission.getRequestId(), context);
                }
            } catch (VerificationException e) {
                vpContext.setRequestStatus(VPRequestStatus.FAILED);
                updateVPContext(submission.getRequestId(), vpContext);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "VP verification failed: " + e.getMessage()));
                return;
            } catch (JsonSyntaxException e) {
                vpContext.setRequestStatus(VPRequestStatus.FAILED);
                updateVPContext(submission.getRequestId(), vpContext);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                                "Invalid presentation_submission format."));
                return;
            }

            // Update the request status.
            updateRequestStatus(submission.getRequestId());

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
     * Validate required fields in the VP submission payload.
     *
     * @param submission Parsed submission payload.
     * @param response HTTP response.
     * @return True when all required fields are present.
     * @throws IOException If writing the error response fails.
     */
    private boolean validateRequiredSubmissionFields(VPSubmission submission,
                                                     HttpServletResponse response)
            throws IOException {

        if (StringUtils.isBlank(submission.getRequestId())) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Missing state parameter."));
            return false;
        }

        if (StringUtils.isBlank(submission.getVpToken())) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Missing vp_token."));
            return false;
        }

        if (StringUtils.isBlank(submission.getPresentationSubmission())) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Missing presentation submission parameter."));
            return false;
        }

        return true;
    }

    /**
     * Validate submitted presentation definition ID against authenticator configuration.
     *
     * @param expectedDefinitionId Expected definition ID from authenticator properties.
     * @param presentationSubmissionJson Raw presentation_submission JSON.
     * @param response HTTP response.
     * @return True when definition IDs match.
     * @throws IOException If writing error response fails.
     */
    private boolean validatePresentationDefinitionId(String expectedDefinitionId,
                                                     String presentationSubmissionJson,
                                                     HttpServletResponse response)
            throws IOException {

        String submittedDefinitionId = getSubmittedPresentationDefinitionId(presentationSubmissionJson);

        if (StringUtils.isBlank(expectedDefinitionId)
                || StringUtils.isBlank(submittedDefinitionId)
                || !StringUtils.equals(expectedDefinitionId, submittedDefinitionId)) {

            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Submitted presentation definition does not match the configured definition."));
            return false;
        }

        return true;
    }

    private String getSubmittedPresentationDefinitionId(String presentationSubmissionJson) {

        try {
            JsonObject submissionJson = GSON.fromJson(presentationSubmissionJson, JsonObject.class);
            if (submissionJson == null || !submissionJson.has("definition_id")
                    || submissionJson.get("definition_id").isJsonNull()) {
                return null;
            }

            return StringUtils.trimToNull(submissionJson.get("definition_id").getAsString());
        } catch (JsonSyntaxException | UnsupportedOperationException e) {
            return null;
        }
    }

    private VPSubmission parseSubmission(HttpServletRequest request)
            throws IOException {
 
        String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        VPSubmission submission = new VPSubmission();

        if (StringUtils.isNotBlank(body) && body.trim().startsWith("{")) {
            // Handle JSON body.
            try {
                return GSON.fromJson(body, VPSubmission.class);
            } catch (JsonSyntaxException e) {
                LOG.warn("Failed to parse JSON submission body.");
            }
        } else {
            // Handle form-encoded body.
            parseFormEncodedSubmission(body, submission);
        }
 
        return submission;
    }

    private void parseFormEncodedSubmission(String formBody,
                                            VPSubmission submission) {
 
        submission.setVpToken(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.VP_TOKEN));
        submission.setPresentationSubmission(getDecodedFormParameter(formBody,
                OpenID4VPConstants.ResponseParams.PRESENTATION_SUBMISSION));
        submission.setRequestId(getDecodedFormParameter(formBody, OpenID4VPConstants.ResponseParams.STATE));
    }

    /**
     * Get URL-decoded parameter value from a form-encoded body.
     *
     * @param formBody  The raw form-encoded body string.
     * @param paramName Parameter name to extract.
     * @return Decoded value, or null if not found or invalid.
     */
    private String getDecodedFormParameter(String formBody, String paramName) {

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
                String decodedValue = URLDecoder.decode(value, StandardCharsets.UTF_8);
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
            } catch (IllegalArgumentException e) {
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
    private String decodeFormToken(String value) {

        if (value == null) {
            return null;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
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
    private String sanitize(String input) {

        if (input == null) {
            return "";
        }
        // Remove carriage-return, newline and HTML tag characters.
        return input.replace('\r', '_').replace('\n', '_')
                .replaceAll("[<>\"']", "_");
    }

    /**
     * Update the request status in the context for poller handoff.
     *
     * @param requestId  The request ID (state).
     */
    private void updateRequestStatus(String requestId) {

        // Update the context with submission status for poller handoff.
        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        VPContext vpContext = getVPContext(context).orElse(null);

        if (vpContext != null) {
            // Update status to VP_SUBMITTED for the poller.
            vpContext.setRequestStatus(VPRequestStatus.VP_SUBMITTED);
            updateVPContext(requestId, vpContext);
        } else {
            LOG.warn("VPContext not found for request ID; submission status will not be updated.");
        }
    }

    private Optional<VPContext> getVPContext(AuthenticationContext context) {

        if (context == null) {
            return Optional.empty();
        }

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return Optional.of((VPContext) vpContextObj);
        }

        return Optional.empty();
    }

    private void updateVPContext(String contextId, VPContext vpContext) {

        if (StringUtils.isBlank(contextId) || vpContext == null) {
            return;
        }

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(contextId);
        if (context == null) {
            return;
        }

        context.setProperty(Constraints.CONTEXT_VP_CONTEXT, vpContext);
        FrameworkUtils.addAuthenticationContextToCache(contextId, context);

        String internalContextId = context.getContextIdentifier();
        if (StringUtils.isNotBlank(internalContextId) && !internalContextId.equals(contextId)) {
            FrameworkUtils.addAuthenticationContextToCache(internalContextId, context);
        }

        String mappedId = (String) context.getProperty(Constraints.CONTEXT_VP_MAPPED_ID);
        if (StringUtils.isNotBlank(mappedId) && !mappedId.equals(contextId)
                && !mappedId.equals(internalContextId)) {
            FrameworkUtils.addAuthenticationContextToCache(mappedId, context);
        }
    }

    /**
     * Send success response to wallet.
     *
     * @param response   HTTP response.
     * @throws IOException If writing fails.
     */
    private void sendSuccessResponse(HttpServletResponse response)
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
    private void sendErrorResponse(HttpServletResponse response,
                                   int statusCode,
                                   VPAuthenticatorException exception)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        // Prevent browsers from MIME-sniffing the JSON response as HTML.
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);

        // Use exception values for error response.
        JsonObject errorObj = new JsonObject();
        errorObj.addProperty(RESPONSE_ERROR, sanitize(exception.getOAuth2ErrorCode()));
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION,
                sanitize(exception.getMessage()));
        errorObj.addProperty(RESPONSE_ERROR_CODE, exception.getCode());

        byte[] payload = GSON.toJson(errorObj).getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    /**
     * Resolve the tenant ID from the request context or attributes.
     *
     * @param request HTTP request.
     * @return Tenant ID.
     */
    private int getTenantId(HttpServletRequest request) {

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

        return SUPER_TENANT_ID_PLACEHOLDER;
    }
}

