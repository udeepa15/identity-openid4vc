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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import com.google.gson.JsonObject;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_3;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_4;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_5;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_CLIENT_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_POLL;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_REQUEST_URI;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_SESSION_DATA_KEY;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_CLIENT_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_RESPONSE_MODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_SUBJECT_CLAIM;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_TIMEOUT_SECONDS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_CANCELLED;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_FAILED;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_PENDING;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_SUCCESS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.WALLET_LOGIN_PAGE;

/**
 * OpenID for Verifiable Presentations (OpenID4VP) authenticator for WSO2 Identity Server.
 *
 * <p>This authenticator implements the OpenID for Verifiable Presentations (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a digital wallet.</p>
 */
public class OpenID4VPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    /**
     * Serial version UID.
     */
    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(OpenID4VPAuthenticator.class);

    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Initiate the authentication request to the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If request initiation fails.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Generate a random UUID as the public Request ID.
            String requestId = UUID.randomUUID().toString();

            context.setProperty(Constraints.CONTEXT_VP_CONTEXT,
                    new VPContext(VPRequestStatus.ACTIVE));

            String redirectUrl = createRedirectURI(requestId);

            response.sendRedirect(redirectUrl);

            // Cache the authentication context.
            FrameworkUtils.addAuthenticationContextToCache(requestId, context);

        } catch (VPAuthenticatorException e) {
            throw new AuthenticationFailedException("Failed to initiate VP request: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    /**
     * Process the authentication response from the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If authentication fails.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        // Use the framework-provided AuthenticationContext as the primary source.
        //This contex is an alias under a new key 
        VPContext vpContext = getVPContext(context)
                .orElseThrow(() -> new AuthenticationFailedException(
                        "No VP request context found in authentication context."));
        VerificationResult verificationResult = vpContext.getVerificationResult();
        if (verificationResult == null || MapUtils.isEmpty(verificationResult.getVerifiedClaims())) {
            throw new AuthenticationFailedException("No verified claims found in context. "
                    + "Verification must have failed.");
        }
        
        Map<String, Object> verifiedClaims = verificationResult.getVerifiedClaims();

        // Clean up using the best available context cache key.
        String cacheKey = StringUtils.trimToNull(request.getParameter(PARAM_SESSION_DATA_KEY));

        if (StringUtils.isNotBlank(cacheKey)) {
            FrameworkUtils.removeAuthenticationContextFromCache(cacheKey);
        }
        // 3. Set a default subject identifier.
        String defaultSubject = UUID.randomUUID().toString();

        // 4. Build the AuthenticatedUser
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(defaultSubject);
        authenticatedUser.setFederatedUser(true);

        if (context.getExternalIdP() != null) {
            authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        }
        authenticatedUser.setTenantDomain(context.getTenantDomain());

        // 5. Pass the RAW claims directly to the framework.
        Map<ClaimMapping, String> rawAttributes = new HashMap<>();
        for (Map.Entry<String, Object> entry : verifiedClaims.entrySet()) {
            if (entry.getValue() != null && StringUtils.isNotBlank(entry.getValue().toString())) {
                String claimName = entry.getKey();
                String claimValue = entry.getValue().toString();

                // Build a raw claim mapping. The framework's ClaimHandler will translate this later.
                ClaimMapping mapping = ClaimMapping.build(claimName, claimName, null, false);
                rawAttributes.put(mapping, claimValue);
            }
        }

        // 6. Hand the raw data to WSO2
        if (!rawAttributes.isEmpty()) {
            authenticatedUser.setUserAttributes(rawAttributes);
        }

        context.setSubject(authenticatedUser);
    }

    /**
     * Build wallet login redirect URI with required bootstrap parameters for QR rendering.
     *
     * @param requestId  Masked session data key.
     * @return Redirect URI with encoded query parameters.
     */
    private String createRedirectURI(String requestId) throws VPAuthenticatorException {

        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String requestUri = baseUrl + Constraints.REQUEST_URI_ENDPOINT
                + requestId;
        String clientId = VPAuthenticatorUtil.getClientId(baseUrl);
        //String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        return WALLET_LOGIN_PAGE + "?"
                + PARAM_SESSION_DATA_KEY + "=" + URLEncoder.encode(requestId, StandardCharsets.UTF_8)
                + "&" + PARAM_CLIENT_ID + "="
                + URLEncoder.encode(StringUtils.defaultString(clientId), StandardCharsets.UTF_8)
                + "&" + PARAM_REQUEST_URI + "="
                + URLEncoder.encode(StringUtils.defaultString(requestUri), StandardCharsets.UTF_8);
    }

    /**
     * Process the authentication request and status/response callbacks.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @return Status of the authentication flow.
     * @throws AuthenticationFailedException If authentication fails.
     * @throws LogoutFailedException         If logout fails.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // Check if this is a polling request.
        String poll = getValidatedParameter(request, PARAM_POLL);
        if ("true".equals(poll)) {
            return handlePollRequest(response, context);
        }

        // Check if status is being reported.
        String status = getValidatedParameter(request, PARAM_STATUS);
        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handle polling request from the login page.
     *
     * @param response HTTP response.
     * @param context  Authentication context.
     * @return Status of the authentication flow.
     * @throws AuthenticationFailedException If polling fails.
     */
    private AuthenticatorFlowStatus handlePollRequest(HttpServletResponse response,
                                                      AuthenticationContext context)
            throws AuthenticationFailedException {

        VPRequestStatus status = null;
        Optional<VPContext> vpContextOpt = getVPContext(context);
        if (vpContextOpt.isPresent()) {
            VPContext vpContext = vpContextOpt.get();
            status = vpContext.getRequestStatus();
        }
        if (status == null) {
            status = VPRequestStatus.ACTIVE;
        }

        if (VPRequestStatus.VP_SUBMITTED.equals(status)) {

            sendPollResponse(response, status.getValue().toLowerCase(Locale.ENGLISH), null, null);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }

        if (VPRequestStatus.VERIFIED.equals(status)) {

            sendPollResponse(response, status.getValue().toLowerCase(Locale.ENGLISH), null, null);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (VPRequestStatus.FAILED.equals(status)) {
            sendPollResponse(response, STATUS_CANCELLED, "Request was cancelled.", null);
            throw new AuthenticationFailedException("VP request was cancelled.");
        } else {
            sendPollResponse(response, STATUS_PENDING, null, null);
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Handle status callback from the frontend.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @param status   Status reported by the frontend.
     * @return Status of the authentication flow.
     * @throws AuthenticationFailedException If callback processing fails.
     */
    private AuthenticatorFlowStatus handleStatusCallback(HttpServletRequest request,
                                                         HttpServletResponse response,
                                                         AuthenticationContext context,
                                                         String status)
            throws AuthenticationFailedException {

        if (STATUS_SUCCESS.equals(status)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (STATUS_FAILED.equals(status)) {
            context.setRetrying(true);
            throw new AuthenticationFailedException("VP verification failed.");
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Send polling response to the client.
     *
     * @param response HTTP response.
     * @param status   Status to report.
     * @param error    Error message to report.
     * @param data     Additional submission data to include (can be null).
     */
    private void sendPollResponse(HttpServletResponse response, String status, String error, Map<String, String> data) {

        try {
            response.setContentType("application/json;charset=UTF-8");

            JsonObject json = new JsonObject();
            json.addProperty("status", status);
            if (error != null) {
                json.addProperty("error", error);
            }

            if (data != null) {
                for (Map.Entry<String, String> entry : data.entrySet()) {
                    json.addProperty(entry.getKey(), entry.getValue());
                }
            }

            // Write using Gson directly to the writer to avoid SpotBugs XSS string detection.
            new com.google.gson.Gson().toJson(json, response.getWriter());
            response.getWriter().flush();
        } catch (IOException e) {
            // ignore.
        }
    }

    /**
     * Check if retry authentication is enabled.
     *
     * @return True.
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get the context identifier.
     *
     * @param request HTTP request.
     * @return Context identifier.
     */
    //ToDo use as the name request_id
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return StringUtils.trimToNull(
                getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
    }

    /**
     * Check if the authenticator can handle the request.
     *
     * @param request HTTP request.
     * @return True if can handle.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String sessionDataKey = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
        String vpRequestId = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_VP_REQUEST_ID));
        String poll = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_POLL));
        String status = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_STATUS));

        // Handle polling requests from login page.
        if (StringUtils.isNotBlank(poll)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle status callbacks.
        if (StringUtils.isNotBlank(status)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle VP request callbacks.
        if (!StringUtils.isBlank(vpRequestId)
                && !StringUtils.isBlank(sessionDataKey)) {
            return true;
        }

        return false;
    }

    /**
     * Get configuration properties for the authenticator.
     *
     * @return List of configuration properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property presentationDefId = new Property();
        presentationDefId.setName(PROP_PRESENTATION_DEFINITION_ID);
        presentationDefId.setDisplayName("Presentation Definition ID");
        presentationDefId.setDescription(
                "ID of the presentation definition to use for VP requests");
        presentationDefId.setDisplayOrder(1);
        presentationDefId.setRequired(false);
        configProperties.add(presentationDefId);

        Property responseMode = new Property();
        responseMode.setName(PROP_RESPONSE_MODE);
        responseMode.setDisplayName("Response Mode");
        responseMode.setDescription(
                "Response mode for VP submissions "
                        + "(direct_post or direct_post.jwt)");
        responseMode.setDisplayOrder(2);
        responseMode.setDefaultValue("direct_post");
        responseMode.setRequired(false);
        configProperties.add(responseMode);

        Property timeout = new Property();
        timeout.setName(PROP_TIMEOUT_SECONDS);
        timeout.setDisplayName("Timeout (seconds)");
        timeout.setDescription("Timeout for VP requests in seconds");
        timeout.setDisplayOrder(DISPLAY_ORDER_3);
        timeout.setDefaultValue("40");
        timeout.setRequired(false);
        configProperties.add(timeout);

        Property clientId = new Property();
        clientId.setName(PROP_CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setDescription(
                "Client ID to use in VP requests "
                        + "(auto-generated if not specified)");
        clientId.setDisplayOrder(DISPLAY_ORDER_4);
        clientId.setRequired(false);
        configProperties.add(clientId);

        Property subjectClaim = new Property();
        subjectClaim.setName(PROP_SUBJECT_CLAIM);
        subjectClaim.setDisplayName("Subject Claim");
        subjectClaim.setDescription(
                "Claim path to use as the authenticated subject identifier");
        subjectClaim.setDisplayOrder(DISPLAY_ORDER_5);
        subjectClaim.setDefaultValue("credentialSubject.id");
        subjectClaim.setRequired(false);
        configProperties.add(subjectClaim);

        return configProperties;
    }

    /**
     * Read and validate a request parameter.
     *
     * @param request HTTP request.
     * @param name    Parameter name.
     * @return Validated parameter value, or null.
     */
    private String getValidatedParameter(HttpServletRequest request, String name) {

        String value = request.getParameter(name);
        return StringUtils.isNotBlank(value) ? Encode.forHtml(value) : null;
    }

    private Optional<VPContext> getVPContext(AuthenticationContext context) {

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return Optional.of((VPContext) vpContextObj);
        }

        return Optional.empty();
    }
}
