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
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

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
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.CLAIM_CREDENTIAL_SUBJECT;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.CLAIM_VC;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DEFAULT_VP_REQUEST_EXPIRY_MS;
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
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_EXPIRED;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_FAILED;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_PENDING;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.STATUS_SUCCESS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SUPER_TENANT_ID_PLACEHOLDER;
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
            String publicRequestId = UUID.randomUUID().toString();

            // Proactively cache a shadow copy of the context using the alias ID.
            // This ensures the framework's internal context remains clean while the alias holds the OpenID4VP state.
            FrameworkUtils.addAuthenticationContextToCache(publicRequestId, context);

            // Retrieve the alias context and initialize it with OpenID4VP specific state.
            AuthenticationContext aliasContext = FrameworkUtils.getAuthenticationContextFromCache(publicRequestId);
            if (aliasContext == null) {
                throw new AuthenticationFailedException(
                        "Failed to retrieve authentication context for request ID: " + publicRequestId);
            }

            VPServiceDataHolder.getVPContextService().setVPContext(aliasContext,
                    new VPContext(VPRequestStatus.ACTIVE));

            // Resolve metadata using the alias context to ensure URLs point to the correct ID.
            Map<String, String> metadata = getVPRequestService().getVPRequestMetadata(publicRequestId);

            String redirectUrl = createRedirectURI(
                    WALLET_LOGIN_PAGE,
                    publicRequestId,
                    metadata.get(PARAM_CLIENT_ID),
                    metadata.get(PARAM_REQUEST_URI));

            response.sendRedirect(redirectUrl);

        } catch (VPAuthenticatorException e) {
            throw new AuthenticationFailedException("Failed to initiate VP request: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    /**
     * Build wallet login redirect URI with required bootstrap parameters for QR rendering.
     *
     * @param walletPath Wallet login page path.
     * @param sessionId  Masked session data key.
     * @param clientId   Client ID used in the VP request.
     * @param requestUri Request URI for by-reference OpenID4VP flow.
     * @return Redirect URI with encoded query parameters.
     */
    private String createRedirectURI(String walletPath,
                                     String sessionId,
                                     String clientId,
                                     String requestUri) {

        String separator = walletPath.contains("?") ? "&" : "?";

        return walletPath + separator
                + PARAM_SESSION_DATA_KEY + "=" + URLEncoder.encode(sessionId, StandardCharsets.UTF_8)
                + "&" + PARAM_CLIENT_ID + "="
                + URLEncoder.encode(StringUtils.defaultString(clientId), StandardCharsets.UTF_8)
                + "&" + PARAM_REQUEST_URI + "="
                + URLEncoder.encode(StringUtils.defaultString(requestUri), StandardCharsets.UTF_8);
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

        String publicRequestId = request.getParameter(Constraints.PARAM_VP_REQUEST_ID);
        if (StringUtils.isBlank(publicRequestId)) {
            throw new AuthenticationFailedException("Public request ID missing in the response.");
        }

        // Retrieve the isolated VP context using the alias ID.
        VPContext vpContext = VPServiceDataHolder.getVPContextService().getVPContext(publicRequestId)
                .orElseThrow(() -> new AuthenticationFailedException("No VP request context found for ID: "
                        + publicRequestId));
        Map<String, Object> verifiedClaims = vpContext.getVerifiedClaims();

        if (MapUtils.isEmpty(verifiedClaims)) {
            throw new AuthenticationFailedException("No verified claims found in context. "
                    + "Verification must have failed.");
        }

        // Clean up the alias context from the cache.
        FrameworkUtils.removeAuthenticationContextFromCache(publicRequestId);
//ToDo: use clearCacheEntry
        ClaimMapping[] idpClaimMappings = resolveIdpClaimMappings(context);

        // Derive subject claim name from IDP's userIdClaim configuration when available.
        String subjectRemoteClaim = resolveSubjectRemoteClaim(context, idpClaimMappings);

        boolean isSubjectClaimConfigured = StringUtils.isNotBlank(resolveConfiguredSubjectClaimUri(context));

        // If IDP subject claim is configured, enforce it.
        // Otherwise, use a transient random UUID as the subject identifier.
        String username = isSubjectClaimConfigured
                ? extractUsername(verifiedClaims, subjectRemoteClaim)
                : UUID.randomUUID().toString();
//ToDo: check the framework and remove  subjectclaim set and username
        if (isSubjectClaimConfigured && StringUtils.isBlank(username)) {
            throw new AuthenticationFailedException("No user identifier found in verified credentials.");
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
    }

    /**
     * Extract the username from verified claims using only the IDP-configured subject claim.
     *
     * <p>The remote claim name to use as subject is resolved from the IDP's {@code userIdClaim}
     * remote URI. If that cannot be determined (IDP not configured, or no matching mapping), this
     * method returns {@code null}, which causes authentication to fail with a clear error rather
     * than silently picking the wrong field.</p>
     *
     * @param verifiedClaims     Claims extracted and verified from the VC.
     * @param subjectRemoteClaim The remote (VC-side) claim name that corresponds to the IDP subject.
     * @return Username string, or null if not determinable.
     */
    private String extractUsername(Map<String, Object> verifiedClaims,
                                   String subjectRemoteClaim) {

        if (StringUtils.isBlank(subjectRemoteClaim)) {
            return null;
        }
        return MapUtils.getString(verifiedClaims, subjectRemoteClaim);
    }

    /**
     * Map verified claims to WSO2 ClaimMappings using IDP-configured mappings.
     *
     * <p>If no mappings are configured, an empty map is returned and no claim mapping is applied.</p>
     *
     * @param verifiedClaims   Claims extracted and verified from the VC.
     * @param idpClaimMappings Mappings configured for the Identity Provider.
     * @return Map of local claim mappings to values.
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
            String remoteValue = MapUtils.getString(verifiedClaims, remoteClaim);

            if (StringUtils.isNotBlank(remoteValue)) {
                mappedClaims.put(mapping, remoteValue);
            } else {
                // Try credentialSubject nested map (for non-SD-JWT paths).
                Object cs = verifiedClaims.get(CLAIM_CREDENTIAL_SUBJECT);
                if (cs instanceof Map) {
                    Object val = ((Map<?, ?>) cs).get(remoteClaim);
                    if (val != null) {
                        mappedClaims.put(mapping, val.toString());
                        continue;
                    }
                }
                // Try vc.credentialSubject (nested JWT VC).
                Object vcObj = verifiedClaims.get(CLAIM_VC);
                if (vcObj instanceof Map) {
                    Object csObj = ((Map<?, ?>) vcObj).get(CLAIM_CREDENTIAL_SUBJECT);
                    if (csObj instanceof Map) {
                        Object val = ((Map<?, ?>) csObj).get(remoteClaim);
                        if (val != null) {
                            mappedClaims.put(mapping, val.toString());
                        }
                    }
                }
            }
        }
        return mappedClaims;
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
        Optional<VPContext> vpContextOpt = VPServiceDataHolder.getVPContextService().getVPContext(context);
        if (vpContextOpt.isPresent()) {
            VPContext vpContext = vpContextOpt.get();
            status = vpContext.getRequestStatus();

            // Check if the request has expired based on the 60-second window.
            if (VPRequestStatus.ACTIVE.equals(status) && isRequestExpired(vpContext)) {
                status = VPRequestStatus.EXPIRED;
                vpContext.setRequestStatus(status);
            }
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
        } else if (VPRequestStatus.EXPIRED.equals(status)) {
            sendPollResponse(response, STATUS_EXPIRED, "Request expired.", null);
            throw new AuthenticationFailedException("VP request has expired.");
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
        } else if (STATUS_EXPIRED.equals(status)) {
            context.setRetrying(true);
            throw new AuthenticationFailedException("VP request expired.");
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
     * Resolve the IDP's ClaimMappings reliably from the authentication context.
     *
     * <p>When the framework sets up a federated flow, {@code context.getExternalIdP()} may be null
     * at the time {@code processAuthenticationResponse} runs (e.g. in redirect-back scenarios).
     * This method falls back to resolving the IDP by name via {@link IdentityProviderManager} if
     * the direct accessor returns null, ensuring IDP claim mappings are always available.</p>
     *
     * @param context Authentication context.
     * @return IDP claim mappings, never null (empty array if none configured).
     */
    private ClaimMapping[] resolveIdpClaimMappings(AuthenticationContext context) {

        // ExternalIdP is already populated.
        if (context.getExternalIdP() != null) {
            ClaimMapping[] mappings = context.getExternalIdP().getClaimMappings();
            return mappings != null ? mappings : new ClaimMapping[0];
        }

        // Resolve the IDP name from SequenceConfig and look it up.
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
     * @param context          Authentication context.
     * @param idpClaimMappings Resolved IDP claim mappings.
     * @return Remote claim name for the subject, or null if not determinable.
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
                    return mapping.getRemoteClaim().getClaimUri();
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
     * Resolve the configured subject claim URI ({@code userIdClaim}) from the IDP.
     *
     * @param context Authentication context.
     * @return Configured subject claim URI, or null.
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
     *
     * @param context Authentication context.
     * @return IDP name or null.
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
        for (AuthenticatorConfig authConfig : stepConfig.getAuthenticatorList()) {
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
     * @param context Authentication context.
     * @return Tenant ID.
     */
    private int getTenantId(AuthenticationContext context) {

        // Default to super tenant.
        int tenantId = SUPER_TENANT_ID_PLACEHOLDER;

        String tenantDomain = context.getTenantDomain();
        if (StringUtils.isNotBlank(tenantDomain)) {
            try {
                tenantId = org.wso2.carbon.identity.core.util.IdentityTenantUtil
                        .getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignored: Failed to resolve tenant ID, using default.
                if (log.isDebugEnabled()) {
                    log.debug("Failed to resolve tenant ID. "
                            + "Using default super tenant ID.", e);
                }
            }
        }

        return tenantId;
    }

    /**
     * Get VPRequestService instance.
     *
     * @return VPRequestService instance.
     */
    private VPRequestServiceImpl getVPRequestService() {

        return VPServiceDataHolder.getVPRequestService();
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

    /**
     * Check if the VP request has expired based on the configured active window.
     *
     * @param vpRequestContext VP request context.
     * @return True if expired, false otherwise.
     */
    private boolean isRequestExpired(VPContext vpContext) {

        if (vpContext == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        return (currentTime - vpContext.getCreatedAt()) > DEFAULT_VP_REQUEST_EXPIRY_MS;
    }
}
