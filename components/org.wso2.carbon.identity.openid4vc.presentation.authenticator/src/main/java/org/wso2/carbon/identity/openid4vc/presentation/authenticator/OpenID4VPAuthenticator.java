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

import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.QRCodeUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
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

/**
 * OpenID4VP Wallet Authenticator for WSO2 Identity Server.
 * 
 * This authenticator implements the OpenID for Verifiable Presentations
 * (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a
 * digital wallet.
 */
public class OpenID4VPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator, VPStatusListenerCache.StatusCallback {

    // Use @Serial annotation for serialVersionUID
    @java.io.Serial
    private static final long serialVersionUID = 1L;

    // Authenticator configuration properties
    private static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    private static final Log log = LogFactory.getLog(OpenID4VPAuthenticator.class);

    // Request parameter names
    private static final String PARAM_VP_REQUEST_ID = "vp_request_id";

    private static final String PARAM_STATUS = "status";
    private static final String PARAM_POLL = "poll";

    // Session data keys
    private static final String SESSION_VP_REQUEST_ID = "openid4vp_request_id";
    private static final String SESSION_TRANSACTION_ID = "openid4vp_transaction_id";
    private static final String UI_SESSION_DATA_KEY = "openid4vp_ui_session_data_key";
    private static final String UI_REQUEST_ID = "openid4vp_ui_request_id";
    private static final String UI_TRANSACTION_ID = "openid4vp_ui_transaction_id";
    private static final String UI_REQUEST_URI = "openid4vp_ui_request_uri";
    private static final String UI_QR_CONTENT = "openid4vp_ui_qr_content";

    // Configuration property keys
    private static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    private static final String PROP_RESPONSE_MODE = "ResponseMode";
    private static final String PROP_TIMEOUT_SECONDS = "TimeoutSeconds";
    private static final String PROP_CLIENT_ID = "ClientId";
    private static final String PROP_DID_METHOD = "DIDMethod";
    private static final String PROP_SUBJECT_CLAIM = "SubjectClaim";
    private static final String DEFAULT_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";

    private static final int DISPLAY_ORDER_3 = 3;
    private static final int DISPLAY_ORDER_4 = 4;
    private static final int DISPLAY_ORDER_5 = 5;
    private static final int SUPER_TENANT_ID_PLACEHOLDER = -1234;

    // Instance variable to store received VP submission (direct processing)
    private volatile VPSubmission receivedSubmission;

    // StatusCallback interface implementation for direct processing
    @Override
    public void onStatusChange(String status) {

    }

    @Override
    public void onTimeout() {
        // No-op: timeout handling is managed by the VP request expiry in VPRequestService.
    }

    @Override
    public void onSubmissionReceived(VPSubmission submission) {
        // Use a defensive copy to prevent external mutation of the internal state (EI_EXPOSE_REP2 fix)
        if (submission != null) {
            this.receivedSubmission = new VPSubmission.Builder()
                    .submissionId(submission.getSubmissionId())
                    .requestId(submission.getRequestId())
                    .transactionId(submission.getTransactionId())
                    .vpToken(submission.getVpToken())
                    .presentationSubmission(submission.getPresentationSubmission())
                    .error(submission.getError())
                    .errorDescription(submission.getErrorDescription())
                    .verificationStatus(submission.getVerificationStatus())
                    .verificationResult(submission.getVerificationResult())
                    .submittedAt(submission.getSubmittedAt())
                    .tenantId(submission.getTenantId())
                    .build();
        } else {
            this.receivedSubmission = null;
        }
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Create VP request
            VPRequestResponseDTO vpRequestResponse = createVPRequest(context);

            // Store request ID in session
            context.setProperty(SESSION_VP_REQUEST_ID, vpRequestResponse.getRequestId());
            context.setProperty(SESSION_TRANSACTION_ID, vpRequestResponse.getTransactionId());

            // Register this authenticator as a listener for direct processing
            VPStatusListenerCache listenerCache = VPStatusListenerCache.getInstance();
            listenerCache.registerListener(
                    vpRequestResponse.getRequestId(),
                    "auth-" + context.getContextIdentifier(),
                    this  // Pass this authenticator instance as the callback
            );

            // Generate QR code content
            String qrContent = QRCodeUtil.generateRequestUriQRContent(
                    vpRequestResponse.getRequestUri(),
                    vpRequestResponse.getAuthorizationDetails().getClientId());

            request.setAttribute(UI_SESSION_DATA_KEY, context.getContextIdentifier());
            request.setAttribute(UI_REQUEST_ID, vpRequestResponse.getRequestId());
            request.setAttribute(UI_TRANSACTION_ID, vpRequestResponse.getTransactionId());
            request.setAttribute(UI_REQUEST_URI, vpRequestResponse.getRequestUri());
            request.setAttribute(UI_QR_CONTENT, qrContent);

            // Redirect the browser to authenticationendpoint UI with required parameters.
            // Using redirect avoids cross-webapp RequestDispatcher limitations.
            String redirectUrl = DEFAULT_LOGIN_PAGE
                    + "?sessionDataKey=" + URLEncoder.encode(context.getContextIdentifier(), StandardCharsets.UTF_8)
                    + "&requestId=" + URLEncoder.encode(vpRequestResponse.getRequestId(), StandardCharsets.UTF_8)
                    + "&transactionId=" + URLEncoder.
                    encode(vpRequestResponse.getTransactionId(), StandardCharsets.UTF_8)
                    + "&requestUri=" + URLEncoder.encode(vpRequestResponse.getRequestUri(), StandardCharsets.UTF_8)
                    + "&qrContent=" + URLEncoder.encode(qrContent, StandardCharsets.UTF_8);

            response.sendRedirect(redirectUrl);

        } catch (VPException e) {
            throw new AuthenticationFailedException("Failed to create VP request", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to login page", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {

        // Retrieve Session Info first to get requestId
        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);

        // Try to get submission from instance variable (direct listener) or Cache (polling/redirect)
        VPSubmission submission = this.receivedSubmission;
        if (submission == null && StringUtils.isNotBlank(requestId)) {
            // Fallback: Check WalletDataCache
             submission = WalletDataCache.getInstance().getSubmission(requestId);
        }

        if (submission == null) {
            throw new AuthenticationFailedException("No VP submission received");
        }

        try {
            int tenantId = getTenantId(context);
            VPRequest vpRequest = null;

            if (StringUtils.isNotBlank(requestId)) {
                try {
                    vpRequest = getVPRequestService().getVPRequestById(requestId, tenantId);
                } catch (VPException e) {
                    // Ignore for now or handle appropriately
                }
            }

            // Derive the Presentation Definition ID from the VP request.
            // The Verification Component is responsible for resolving it to the
            // full definition and enforcing claim constraints.
            String presentationDefinitionId = (vpRequest != null)
                    ? vpRequest.getPresentationDefinitionId()
                    : null;

            // Single unified verification call.
            // The Verification Component handles format detection, cryptographic
            // verification, disclosure processing, and PD constraint enforcement.
            VerificationResult verificationResult;
            try {
                // Parse the presentation_submission string into the DTO
                PresentationSubmission presentationSubmission = new com.google.gson.Gson()
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
            String issuerSubject = resolveIssuerSubjectIdentifier(verifiedClaims);
            if (StringUtils.isBlank(issuerSubject)) {
                throw new AuthenticationFailedException("No VC issuer found in verified credentials");
            }

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
    private String extractUsername(Map<String, Object> verifiedClaims, String subjectRemoteClaim) {
        if (StringUtils.isBlank(subjectRemoteClaim)) {
            // No IDP subject claim configured — cannot safely determine the user identifier.
            // Authentication will fail with an explicit message.
            return null;
        }
        Object val = verifiedClaims.get(subjectRemoteClaim);
        return (val != null && StringUtils.isNotBlank(val.toString())) ? val.toString() : null;
    }

    /**
     * Resolve issuer from verified claims for issuer-only authentication mode.
     *
     * @param verifiedClaims Claims extracted and verified from the VC
     * @return Issuer value if available, or null
     */
    private String resolveIssuerSubjectIdentifier(Map<String, Object> verifiedClaims) {
        if (verifiedClaims == null || verifiedClaims.isEmpty()) {
            return null;
        }

        Object issuer = verifiedClaims.get("iss");
        if (issuer == null) {
            issuer = verifiedClaims.get("issuer");
        }
        if (issuer != null && StringUtils.isNotBlank(issuer.toString())) {
            return issuer.toString();
        }

        Object vcObject = verifiedClaims.get("vc");
        if (vcObject instanceof Map) {
            Object nestedIssuer = ((Map<?, ?>) vcObject).get("issuer");
            if (nestedIssuer != null && StringUtils.isNotBlank(nestedIssuer.toString())) {
                return nestedIssuer.toString();
            }
        }
        return null;
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
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // Check if this is a polling request
        String poll = ServletUtil.getValidatedAlphaNumParameter(request, PARAM_POLL);
        if ("true".equals(poll)) {
            return handlePollRequest(response, context);
        }

        // Check if status is being reported
        String status = ServletUtil.getValidatedAlphaNumParameter(request, PARAM_STATUS);
        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handle polling request from the login page.
     */
    private AuthenticatorFlowStatus handlePollRequest(HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {
        String requestId = (String) context.getProperty(SESSION_VP_REQUEST_ID);
        if (StringUtils.isBlank(requestId)) {
            throw new AuthenticationFailedException("VP request ID not found in session");
        }

        try {
            VPRequestService requestService = getVPRequestService();
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

        } catch (VPException e) {
            sendPollResponse(response, "error", e.getMessage());
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    /**
     * Handle status callback from the frontend.
     */
    private AuthenticatorFlowStatus handleStatusCallback(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context,
            String status)
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
     * Create a VP request for the authentication session.
     */
    private VPRequestResponseDTO createVPRequest(AuthenticationContext context) throws VPException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();

        // Set DID Method if configured
        String didMethod = authenticatorProperties.get(PROP_DID_METHOD);
        if (StringUtils.isNotBlank(didMethod)) {
            createDTO.setDidMethod(didMethod);
        }

        // Set Signing Algorithm (Default to EdDSA)
        String signingAlgorithm = authenticatorProperties.get(OpenID4VPConstants.ConfigKeys.SIGNING_ALGORITHM);
        if (StringUtils.isBlank(signingAlgorithm)) {
            signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;
        }
        createDTO.setSigningAlgorithm(signingAlgorithm);

        // Set client ID from config or generate from tenant
        String clientId = authenticatorProperties.get(PROP_CLIENT_ID);
        if (StringUtils.isBlank(clientId)) {
            clientId = buildClientId();
        }
        createDTO.setClientId(clientId);

        // NEW: Use per-application presentation definition mapping
        // Resolution order:
        // 1. Check application-specific mapping in
        // IDN_APPLICATION_PRESENTATION_DEFINITION table
        // 2. Fall back to authenticator configuration property (backward compatible)
        // 3. Use inline default definition if neither exists
        String presentationDefId = resolvePresentationDefinitionId(context);

        if (log.isInfoEnabled()) {
            log.info("Resolved presentation definition ID for the authentication flow.");
        }

        if (StringUtils.isNotBlank(presentationDefId)) {
            createDTO.setPresentationDefinitionId(presentationDefId);
        } else {
            throw new VPException("No presentation definition found for the application.");
        }

        // Set response mode
        String responseMode = authenticatorProperties.get(PROP_RESPONSE_MODE);
        if (StringUtils.isBlank(responseMode)) {
            responseMode = OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST;
        }
        createDTO.setResponseMode(responseMode);

        // Set transaction ID to context identifier for correlation
        createDTO.setTransactionId(context.getContextIdentifier());

        // Create VP request
        VPRequestService vpRequestService = getVPRequestService();
        int tenantId = getTenantId(context);
        return vpRequestService.createVPRequest(createDTO, tenantId);
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
     * Resolve the presentation definition ID for the application.
     * 
     * The presentation definition ID is stored directly in the authenticator configuration.
     * The listener handles creating the definition and updating the configuration with the ID.
     * 
     * @param context Authentication context
     * @return Presentation definition ID or null
     * @throws VPException If error occurs during resolution
     */
    private String resolvePresentationDefinitionId(AuthenticationContext context) {


        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String configId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);

            if (StringUtils.isBlank(configId)) {
                String idpName = null;
                if (context.getExternalIdP() != null) {
                    idpName = context.getExternalIdP().getIdPName();
                }

                // If getExternalIdP() is null, try to find the IdP name from SequenceConfig
                if (StringUtils.isBlank(idpName) && context.getSequenceConfig() != null) {
                    Map<Integer, StepConfig> stepMap = context.getSequenceConfig().getStepMap();
                    if (stepMap != null) {
                        StepConfig stepConfig = stepMap.get(context.getCurrentStep());
                        if (stepConfig != null) {
                            for (org.wso2.carbon.identity.application.authentication.framework
                                    .config.model.AuthenticatorConfig 
                                    authConfig : stepConfig.getAuthenticatorList()) {
                                if (getName().equals(authConfig.getName()) && 
                                        authConfig.getIdpNames() != null && !authConfig.getIdpNames().isEmpty()) {
                                    idpName = authConfig.getIdpNames().get(0);
                                    break;
                                }
                            }
                        }
                    }
                }

                String tenantDomain = context.getTenantDomain();
                if (StringUtils.isNotBlank(idpName)) {
                    IdentityProvider idp = IdentityProviderManager.getInstance()
                            .getIdPByName(idpName, tenantDomain);
                    if (idp != null) {
                    if (log.isInfoEnabled()) {
                        log.info("Found IDP while resolving presentation definition ID.");
                    }
                    for (FederatedAuthenticatorConfig fedAuthConfig : idp.getFederatedAuthenticatorConfigs()) {
                        if (log.isInfoEnabled()) {
                            log.info("Checking federated authenticator configuration "
                                    + "for presentation definition ID.");
                        }
                        if (getName().equals(fedAuthConfig.getName())) {
                            for (Property property : fedAuthConfig.getProperties()) {
                                if (log.isInfoEnabled()) {
                                    log.info("Checking federated authenticator property "
                                            + "for presentation definition ID.");
                                }
                                if (PROP_PRESENTATION_DEFINITION_ID.equals(property.getName())) {
                                    configId = property.getValue();
                                    break;
                                }
                            }
                            break;
                        }
                    }
                } else {
                    if (log.isInfoEnabled()) {
                        log.info("IDP could not be resolved for presentation definition ID lookup.");
                    }
                }
            }
        }

        if (StringUtils.isNotBlank(configId)) {
            if (log.isInfoEnabled()) {
                log.info("Successfully resolved presentation definition ID from authenticator configuration.");
            }
            return configId;
        }

    } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e) {
        // Ignored: Config might not be available
        if (log.isInfoEnabled()) {
            log.info("Exception occurred while resolving presentation definition ID.", e);
        }
    }

    // Fallback or default
    return null;
    }




    /**
     * Build client ID for the request.
     *
     * @param context Authentication context
     * @return Client ID
     */
    private String buildClientId() {
        // Use fixed DID for demo purposes as requested
        return "did:web:masked-unprofitably-ardith.ngrok-free.dev";
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
    private VPRequestService getVPRequestService() {
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
        return StringUtils.trimToNull(ServletUtil.getValidatedAlphaNumParameter(request, "sessionDataKey"));
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
            ServletUtil.getValidatedAlphaNumParameter(request, "sessionDataKey"));
        String vpRequestId = StringUtils.trimToNull(
            ServletUtil.getValidatedAlphaNumParameter(request, PARAM_VP_REQUEST_ID));
        String poll = StringUtils.trimToNull(
            ServletUtil.getValidatedAlphaNumParameter(request, PARAM_POLL));
        String status = StringUtils.trimToNull(
            ServletUtil.getValidatedAlphaNumParameter(request, PARAM_STATUS));

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
}
