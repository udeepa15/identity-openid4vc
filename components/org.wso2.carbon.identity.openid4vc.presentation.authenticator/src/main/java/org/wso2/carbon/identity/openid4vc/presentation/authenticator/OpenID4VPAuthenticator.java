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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.QRCodeUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.ALPHANUM_PATTERN;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DEFAULT_TENANT_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_3;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_4;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DISPLAY_ORDER_5;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_POLL;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PARAM_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_CLIENT_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_RESPONSE_MODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_SUBJECT_CLAIM;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.PROP_TIMEOUT_SECONDS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SESSION_TRANSACTION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SESSION_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SUPER_TENANT_ID_PLACEHOLDER;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.TENANT_DOMAIN_PATTERN;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.UI_QR_CONTENT;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.UI_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.UI_REQUEST_URI;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.UI_SESSION_DATA_KEY;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.UI_TRANSACTION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.WALLET_LOGIN_PAGE;

/**
 * OpenID4VP Wallet Authenticator for WSO2 Identity Server.
 * 
 * This authenticator implements the OpenID for Verifiable Presentations
 * (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a
 * digital wallet.
 */
public class OpenID4VPAuthenticator extends AbstractApplicationAuthenticator
    implements FederatedApplicationAuthenticator {

    // Use @Serial annotation for serialVersionUID
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

    @Override
    protected void initiateAuthenticationRequest(final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Create VP request using the service
            VPRequest vpRequestResponse = getVPRequestService().createVPRequest(context);

            // Store request ID in session
            context.setProperty(SESSION_VP_REQUEST_ID, vpRequestResponse.getRequestId());
            context.setProperty(SESSION_TRANSACTION_ID, vpRequestResponse.getTransactionId());


            // Generate QR code content
            String qrContent = QRCodeUtil.generateRequestUriQRContent(
                    vpRequestResponse.getRequestUri(),
                    vpRequestResponse.getClientId());

            request.setAttribute(UI_SESSION_DATA_KEY, context.getContextIdentifier());
            request.setAttribute(UI_REQUEST_ID, vpRequestResponse.getRequestId());
            request.setAttribute(UI_TRANSACTION_ID, vpRequestResponse.getTransactionId());
            request.setAttribute(UI_REQUEST_URI, vpRequestResponse.getRequestUri());
            request.setAttribute(UI_QR_CONTENT, qrContent);

            // Redirect the browser to authenticationendpoint UI with required parameters.
            String redirectUrl = WALLET_LOGIN_PAGE
                    + "?sessionDataKey=" + URLEncoder.encode(context.getContextIdentifier(), StandardCharsets.UTF_8)
                    + "&requestId=" + URLEncoder.encode(vpRequestResponse.getRequestId(), StandardCharsets.UTF_8)
                    + "&transactionId=" + URLEncoder.
                    encode(vpRequestResponse.getTransactionId(), StandardCharsets.UTF_8)
                    + "&requestUri=" + URLEncoder.encode(vpRequestResponse.getRequestUri(), StandardCharsets.UTF_8)
                    + "&qrContent=" + URLEncoder.encode(qrContent, StandardCharsets.UTF_8);

            response.sendRedirect(redirectUrl);

        } catch (VPAuthenticatorException e) {
            throw new AuthenticationFailedException("Failed to create VP request: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationContext context) throws AuthenticationFailedException {

        // Retrieve Session Info first to get requestId
        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);

        VPSubmission submission = null;
        // Try to get submission from Cache (polling/redirect)
        if (StringUtils.isNotBlank(requestId)) {
            submission = VPSubmissionCache.getInstance().getSubmission(requestId);
        }

        if (submission == null) {
            throw new AuthenticationFailedException("No VP submission received");
        }

        try {
            int tenantId = getTenantId(context);

            VerificationResult verificationResult;

            try {
                // Parse the presentation_submission string into the DTO
                Gson gson = new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .create();
                PresentationSubmission presentationSubmission = gson
                        .fromJson(submission.getPresentationSubmission(), PresentationSubmission.class);

                verificationResult = VPServiceDataHolder
                        .getVerificationService()
                        .verify(
                                presentationSubmission,
                                tenantId,
                                submission.getVpToken());
            } catch (VerificationException e) {
                throw new AuthenticationFailedException(
                        "VP verification failed: " + e.getMessage(), e);
            } catch (com.google.gson.JsonSyntaxException e) {
                throw new AuthenticationFailedException(
                        "Invalid presentation_submission format: " + e.getMessage(), e);
            }

            if (!VerificationResult.VerificationStatus.VERIFIED.equals(verificationResult.getStatus())) {
                throw new AuthenticationFailedException("VP verification status is not VERIFIED");
            }

            Map<String, Object> verifiedClaims = new HashMap<>(verificationResult.getVerifiedClaims());

            // Fix 1: Always resolve IDP claim mappings, even when getExternalIdP() is null.
            ClaimMapping[] idpClaimMappings = resolveIdpClaimMappings(context);

            // Derive subject claim name from IDP's userIdClaim configuration when available.
            String subjectRemoteClaim = resolveSubjectRemoteClaim(context, idpClaimMappings);

            boolean isSubjectClaimConfigured = isSubjectClaimConfigured(context);

            // If IDP subject claim is configured, enforce it.
                // Otherwise, use a transient random UUID as the subject identifier.
            String username = isSubjectClaimConfigured
                    ? extractUsername(verifiedClaims, subjectRemoteClaim)
                    : generateTransientSubjectIdentifier();

            if (isSubjectClaimConfigured && StringUtils.isBlank(username)) {
                throw new AuthenticationFailedException("No user identifier found in verified credentials");
            }

            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(username);
            authenticatedUser.setFederatedUser(true);
            if (context.getExternalIdP() != null) {
                authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
            }
            authenticatedUser.setTenantDomain(context.getTenantDomain());

            Map<ClaimMapping, String> userAttributes = mapVerifiedClaimsToLocal(verifiedClaims, idpClaimMappings);

            if (!userAttributes.isEmpty()) {
                authenticatedUser.setUserAttributes(userAttributes);
            }
            context.setSubject(authenticatedUser);

        } catch (RuntimeException e) {
            throw new AuthenticationFailedException("Authentication failed: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the username from verified claims using only the IDP-configured subject claim.
     *
     * <p>The remote claim name to use as subject is resolved from the IDP's {@code userIdClaim}
        * remote URI. If that cannot be determined (IDP not configured, or no matching mapping), this
     * method returns {@code null}, which causes authentication to fail with a clear error rather
     * than silently picking the wrong field.</p>
     *
     * @param verifiedClaims     Claims extracted and verified from the VC
     * @param subjectRemoteClaim The remote (VC-side) claim name that corresponds to the IDP subject
     * @return Username string, or null if not determinable
     */
    private String extractUsername(final Map<String, Object> verifiedClaims,
                                   final String subjectRemoteClaim) {
        if (StringUtils.isBlank(subjectRemoteClaim)) {
            return null;
        }
        Object val = verifiedClaims.get(subjectRemoteClaim);
        return (val != null && StringUtils.isNotBlank(val.toString())) ? val.toString() : null;
    }


    /**
     * Generate a transient random subject identifier when no subject claim is configured.
     *
     * @return Random UUID string
     */
    private String generateTransientSubjectIdentifier() {

        return UUID.randomUUID().toString();
    }

    /**
     * Map verified claims to WSO2 ClaimMappings using IDP-configured mappings.
     *
     * <p>If no mappings are configured, an empty map is returned and no claim mapping is applied.</p>
     */
    private Map<ClaimMapping, String> mapVerifiedClaimsToLocal(Map<String, Object> verifiedClaims,
                                                               ClaimMapping[] idpClaimMappings) {
        Map<ClaimMapping, String> mappedClaims = new HashMap<>();
        if (idpClaimMappings == null) {
            // No IDP mappings configured.
            return mappedClaims;
        }

        for (ClaimMapping mapping : idpClaimMappings) {
            if (mapping == null || mapping.getRemoteClaim() == null
                    || StringUtils.isBlank(mapping.getRemoteClaim().getClaimUri())) {
                continue;
            }

            String remoteClaim = mapping.getRemoteClaim().getClaimUri();
            // Direct top-level match
            if (verifiedClaims.containsKey(remoteClaim)) {
                mappedClaims.put(mapping, verifiedClaims.get(remoteClaim).toString());
            } else {
                // Try credentialSubject nested map (for non-SD-JWT paths)
                Object cs = verifiedClaims.get("credentialSubject");
                if (cs instanceof Map) {
                    Object val = ((Map<?, ?>) cs).get(remoteClaim);
                    if (val != null) {
                        mappedClaims.put(mapping, val.toString());
                        continue;
                    }
                }
                // Try vc.credentialSubject (nested JWT VC)
                Object vcObj = verifiedClaims.get("vc");
                if (vcObj instanceof Map) {
                    Object csObj = ((Map<?, ?>) vcObj).get("credentialSubject");
                    if (csObj instanceof Map) {
                        Object val = ((Map<?, ?>) csObj).get(remoteClaim);
                        if (val != null) {
                            mappedClaims.put(mapping, val.toString());
                        }
                    }
                }
                // Claim not present in VC — skip silently (Fix 4 applies here too via extractClaimsFromVP)
            }
        }
        return mappedClaims;
    }

    // --- SD-JWT Verification Methods ---



    @Override
    public AuthenticatorFlowStatus process(final HttpServletRequest request,
                                           final HttpServletResponse response,
                                           final AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // Check if this is a polling request
        String poll = getValidatedParameter(request, PARAM_POLL);
        if ("true".equals(poll)) {
            return handlePollRequest(response, context);
        }

        // Check if status is being reported
        String status = getValidatedParameter(request, PARAM_STATUS);
        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handle polling request from the login page.
     */
    private AuthenticatorFlowStatus handlePollRequest(final HttpServletResponse response,
                                                  final AuthenticationContext context)
            throws AuthenticationFailedException {
        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);
        if (StringUtils.isBlank(requestId)) {
            throw new AuthenticationFailedException("VP request ID not found in session");
        }

        try {
            VPRequestServiceImpl requestService = getVPRequestService();
            int tenantId = getTenantId(context);
            VPRequest vpRequest = requestService.getVPRequestById(requestId, tenantId);

            if (vpRequest == null) {
                sendPollResponse(response, "error", "Request not found");
                return AuthenticatorFlowStatus.INCOMPLETE;
            }

            VPRequestStatus status = vpRequest.getStatus();

            if (VPRequestStatus.VP_SUBMITTED.equals(status) ||
                    VPRequestStatus.COMPLETED.equals(status)) {

                sendPollResponse(response, status.getValue().toLowerCase(Locale.ENGLISH), null);

                if (VPRequestStatus.COMPLETED.equals(status)) {
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } else if (VPRequestStatus.EXPIRED.equals(status)) {
                sendPollResponse(response, "expired", "Request expired");
                throw new AuthenticationFailedException("VP request has expired");
            } else if (VPRequestStatus.CANCELLED.equals(status)) {
                sendPollResponse(response, "cancelled", "Request was cancelled");
                throw new AuthenticationFailedException("VP request was cancelled");
            } else {
                sendPollResponse(response, "pending", null);
            }

            return AuthenticatorFlowStatus.INCOMPLETE;

        } catch (VPAuthenticatorException e) {
            sendPollResponse(response, "error", e.getMessage());
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    /**
     * Handle status callback from the frontend.
     */
    private AuthenticatorFlowStatus handleStatusCallback(final HttpServletRequest request,
                                                     final HttpServletResponse response,
                                                     final AuthenticationContext context,
                                                     final String status)
            throws AuthenticationFailedException {

        if ("success".equals(status)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if ("failed".equals(status)) {
            throw new AuthenticationFailedException("VP verification failed");
        } else if ("expired".equals(status)) {
            throw new AuthenticationFailedException("VP request expired");
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Send polling response to the client.
     */
    private void sendPollResponse(HttpServletResponse response, String status, String error) {
        try {
            response.setContentType("application/json;charset=UTF-8");

            JsonObject json = new JsonObject();
            json.addProperty("status", status);
            if (error != null) {
                json.addProperty("error", error);
            }

            // Write using Gson directly to the writer to avoid SpotBugs XSS string detection
            new com.google.gson.Gson().toJson(json, response.getWriter());
            response.getWriter().flush();
        } catch (IOException e) {
            // ignore
        }
    }


    /**
     * Resolve the IDP's ClaimMappings reliably from the authentication context.
     *
     * <p>When the framework sets up a federated flow, {@code context.getExternalIdP()} may be null
     * at the time {@code processAuthenticationResponse} runs (e.g. in redirect-back scenarios).
     * This method falls back to resolving the IDP by name via {@link IdentityProviderManager} if
     * the direct accessor returns null, ensuring IDP claim mappings are always available.</p>
     *
     * @param context Authentication context
     * @return IDP claim mappings, never null (empty array if none configured)
     */
    private ClaimMapping[] resolveIdpClaimMappings(AuthenticationContext context) {

        // Fast path: ExternalIdP is already populated.
        if (context.getExternalIdP() != null) {
            ClaimMapping[] mappings = context.getExternalIdP().getClaimMappings();
            return mappings != null ? mappings : new ClaimMapping[0];
        }

        // Slow path: resolve the IDP name from SequenceConfig and look it up.
        try {
            String idpName = resolveIdpNameFromSequenceConfig(context);
            if (StringUtils.isNotBlank(idpName)) {
                String tenantDomain = context.getTenantDomain();
                IdentityProvider idp = IdentityProviderManager.getInstance().getIdPByName(idpName, tenantDomain);
                if (idp != null && idp.getClaimConfig() != null) {
                    ClaimMapping[] mappings = idp.getClaimConfig().getClaimMappings();
                    return mappings != null ? mappings : new ClaimMapping[0];
                }
            }
        } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not resolve IDP claim mappings from SequenceConfig.", e);
            }
        }
        return new ClaimMapping[0];
    }

    /**
     * Resolve the remote (VC-side) claim name that corresponds to the IDP's configured subject
     * claim URI ({@code userIdClaim}).
     *
        * <p>The IDP's {@code userIdClaim} is expected to be the <em>external IdP claim</em>
        * (remote claim) such as {@code email}. This method finds the ClaimMapping whose remote
        * claim URI matches that value and returns the same remote claim name, which is the field
        * name we must look for inside the Verifiable Credential.</p>
     *
     * @param context          Authentication context
     * @param idpClaimMappings Resolved IDP claim mappings
     * @return Remote claim name for the subject, or null if not determinable
     */
    private String resolveSubjectRemoteClaim(AuthenticationContext context, ClaimMapping[] idpClaimMappings) {
        try {
            String userIdClaimUri = resolveConfiguredSubjectClaimUri(context);

            if (StringUtils.isBlank(userIdClaimUri) || idpClaimMappings == null) {
                return null;
            }

            // Find the remote claim whose remote URI matches the userIdClaim.
            for (ClaimMapping mapping : idpClaimMappings) {
                if (mapping.getRemoteClaim() != null
                        && userIdClaimUri.equals(mapping.getRemoteClaim().getClaimUri())) {
                    return mapping.getRemoteClaim() != null
                            ? mapping.getRemoteClaim().getClaimUri()
                            : null;
                }

                // Backward compatibility: allow old configurations where userIdClaim was local.
                if (mapping.getLocalClaim() != null
                        && userIdClaimUri.equals(mapping.getLocalClaim().getClaimUri())) {
                    return mapping.getRemoteClaim() != null
                            ? mapping.getRemoteClaim().getClaimUri()
                            : null;
                }
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not resolve subject remote claim.", e);
            }
        }
        return null;
    }

    /**
     * Check whether the IDP has configured a subject claim.
     *
     * @param context Authentication context
     * @return True if subject claim is configured
     */
    private boolean isSubjectClaimConfigured(AuthenticationContext context) {

        return StringUtils.isNotBlank(resolveConfiguredSubjectClaimUri(context));
    }

    /**
     * Resolve the configured subject claim URI ({@code userIdClaim}) from the IDP.
     *
     * @param context Authentication context
     * @return Configured subject claim URI, or null
     */
    private String resolveConfiguredSubjectClaimUri(AuthenticationContext context) {

        try {
            // Try ExternalIdP directly first.
            if (context.getExternalIdP() != null && context.getExternalIdP().getIdentityProvider() != null
                    && context.getExternalIdP().getIdentityProvider().getClaimConfig() != null) {
                String userIdClaimUri = context.getExternalIdP().getIdentityProvider()
                        .getClaimConfig().getUserClaimURI();
                if (StringUtils.isNotBlank(userIdClaimUri)) {
                    return userIdClaimUri;
                }
            }

            // Fall back to IdentityProviderManager lookup.
            String idpName = resolveIdpNameFromSequenceConfig(context);
            if (StringUtils.isNotBlank(idpName)) {
                IdentityProvider idp = IdentityProviderManager.getInstance()
                        .getIdPByName(idpName, context.getTenantDomain());
                if (idp != null && idp.getClaimConfig() != null) {
                    return idp.getClaimConfig().getUserClaimURI();
                }
            }
        } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not resolve configured subject claim.", e);
            }
        }
        return null;
    }

    /**
     * Extract the IDP name from the SequenceConfig StepMap when {@code getExternalIdP()} is null.
     * Shared by {@link #resolveIdpClaimMappings} and {@link #resolveSubjectRemoteClaim}.
     */
    private String resolveIdpNameFromSequenceConfig(AuthenticationContext context) {
        if (context.getSequenceConfig() == null) {
            return null;
        }
        Map<Integer, StepConfig> stepMap = context.getSequenceConfig().getStepMap();
        if (stepMap == null) {
            return null;
        }
        StepConfig stepConfig = stepMap.get(context.getCurrentStep());
        if (stepConfig == null) {
            return null;
        }
        for (org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig
                authConfig : stepConfig.getAuthenticatorList()) {
            if (getName().equals(authConfig.getName())
                    && authConfig.getIdpNames() != null
                    && !authConfig.getIdpNames().isEmpty()) {
                return authConfig.getIdpNames().get(0);
            }
        }
        return null;
    }

    /**
     * Get tenant ID from authentication context.
     *
     * @param context Authentication context
     * @return Tenant ID
     */
    private int getTenantId(final AuthenticationContext context) {
        // Default to super tenant
        int tenantId = SUPER_TENANT_ID_PLACEHOLDER;

        String tenantDomain = context.getTenantDomain();
        if (StringUtils.isNotBlank(tenantDomain)) {
            try {
                tenantId = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignored: Failed to resolve tenant ID, using default
                if (log.isDebugEnabled()) {
                    log.debug("Failed to resolve tenant ID. Using default super tenant ID.", e);
                }
            }
        }

        return tenantId;
    }

    /**
     * Get VPRequestService instance.
     */
    private VPRequestServiceImpl getVPRequestService() {
        return VPServiceDataHolder.getVPRequestService();
    }







    /**
     * Check if retry authentication is enabled.
     *
     * @return False
     */
    @Override
    protected boolean retryAuthenticationEnabled() {
        return false;
    }

    /**
     * Get the context identifier.
     *
     * @param request HTTP request
     * @return Context identifier
     */
    @Override
    public String getContextIdentifier(final HttpServletRequest request) {
        return StringUtils.trimToNull(getValidatedParameter(request, "sessionDataKey"));
    }

    /**
     * Check if the authenticator can handle the request.
     *
     * @param request HTTP request
     * @return True if can handle
     */
    @Override
    public boolean canHandle(final HttpServletRequest request) {
        String sessionDataKey = StringUtils.trimToNull(
            getValidatedParameter(request, "sessionDataKey"));
        String vpRequestId = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_VP_REQUEST_ID));
        String poll = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_POLL));
        String status = StringUtils.trimToNull(
            getValidatedParameter(request, PARAM_STATUS));

        // Handle polling requests from login page
        if (StringUtils.isNotBlank(poll)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle status callbacks
        if (StringUtils.isNotBlank(status)
                && StringUtils.isNotBlank(sessionDataKey)) {
            return true;
        }

        // Handle VP request callbacks
        if (!StringUtils.isBlank(vpRequestId) && !StringUtils.isBlank(sessionDataKey)) {
            return true;
        }

        return false;
    }

    /**
     * Get configuration properties.
     *
     * @return List of properties
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
        timeout.setDefaultValue("300");
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
    private String getValidatedParameter(final HttpServletRequest request, final String name) {

        String value = getParameter(request, name);
        if (StringUtils.isNotBlank(value) && value.matches(ALPHANUM_PATTERN)) {
            return value;
        }
        return null;
    }

    /**
     * Get tenant ID from request.
     *
     * @param request HTTP request
     * @return tenant ID
     */
    private int getTenantId(final HttpServletRequest request) {

        String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
        if (StringUtils.isBlank(tenantDomain)) {
            Object tenantDomainAttribute = request.getAttribute("tenantDomain");
            tenantDomain = tenantDomainAttribute instanceof String ? (String) tenantDomainAttribute : null;
        }

        if (StringUtils.isNotBlank(tenantDomain)
                && tenantDomain.matches(TENANT_DOMAIN_PATTERN)) {
            try {
                return org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignore.
            }
        }

        return DEFAULT_TENANT_ID;
    }

    /**
     * Read and sanitize a request parameter.
     *
     * @param request HTTP request.
     * @param name    Parameter name.
     * @return Sanitized parameter value, or null.
     */
    private String getParameter(final HttpServletRequest request, final String name) {

        if (request == null || StringUtils.isBlank(name)) {
            return null;
        }

        String value = request.getParameter(name);
        if (StringUtils.isBlank(value)) {
            return null;
        }

        return Encode.forJava(sanitizeParam(value));
    }

    /**
     * Strip CRLF/control characters from request parameter input.
     *
     * @param value Request parameter value.
     * @return Sanitized parameter value.
     */
    private String sanitizeParam(final String value) {

        if (value == null) {
            return null;
        }
        return value.replace('\r', '_').replace('\n', '_').replaceAll("[\\p{Cntrl}]", "");
    }
}
