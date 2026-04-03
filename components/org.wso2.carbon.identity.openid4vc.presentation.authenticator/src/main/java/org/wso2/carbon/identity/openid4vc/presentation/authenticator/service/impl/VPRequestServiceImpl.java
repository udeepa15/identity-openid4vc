/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl implements VPRequestService {

    private static final Log log = LogFactory.getLog(VPRequestServiceImpl.class);

    // Use property keys from Constraints
    private static final String PROP_PRESENTATION_DEFINITION_ID = Constraints.PROP_PRESENTATION_DEFINITION_ID;
    private static final String PROP_RESPONSE_MODE = Constraints.PROP_RESPONSE_MODE;
    private static final String PROP_CLIENT_ID = Constraints.PROP_CLIENT_ID;
    private static final String AUTHENTICATOR_NAME = Constraints.AUTHENTICATOR_NAME;
    private static final long DEFAULT_EXPIRY_MS = 600000; // 10 minutes

    private final AtomicReference<VPRequestDAO> vpRequestDAORef;
    private final AtomicReference<PresentationDefinitionService> presentationDefinitionServiceRef;
    private volatile String baseUrl;

    /**
     * Default constructor.
     * Note: baseUrl is lazily loaded on first use to avoid OSGi activation timing issues
     * where IdentityUtil may not have loaded identity.xml yet.
     */
    public VPRequestServiceImpl() {
        this.vpRequestDAORef = new AtomicReference<>(new VPRequestDAO());
        this.presentationDefinitionServiceRef =
                new AtomicReference<>(VPServiceDataHolder.getPresentationDefinitionService());
    }

    /**
     * Constructor for dependency injection.
     */

    public VPRequestServiceImpl(VPRequestDAO vpRequestDAO, PresentationDefinitionService presentationDefinitionService,
            String baseUrl) {
        this.vpRequestDAORef = new AtomicReference<>(vpRequestDAO);
        this.presentationDefinitionServiceRef = new AtomicReference<>(presentationDefinitionService);
        this.baseUrl = baseUrl;
    }

    private VPRequestDAO getVPRequestDAO() throws VPAuthenticatorException {
        VPRequestDAO dao = vpRequestDAORef.get();
        if (dao == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "VP request DAO is not initialized");
        }
        return dao;
    }

    private PresentationDefinitionService getPresentationDefinitionService() throws VPAuthenticatorException {
        PresentationDefinitionService service = presentationDefinitionServiceRef.get();
        if (service == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not initialized");
        }
        return service;
    }

    /**
     * Get the base URL, lazily loading from configuration on first access.
     */
    private String getBaseUrl() {
        if (baseUrl == null) {
            baseUrl = getConfiguredBaseUrl();
        }
        return baseUrl;
    }

    @Override
    public VPRequest createVPRequest(AuthenticationContext context) throws VPAuthenticatorException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        // 1. Resolve basic configuration
        String didMethod = authenticatorProperties.get(Constraints.PROP_DID_METHOD);
        if (StringUtils.isBlank(didMethod)) {
            didMethod = Constraints.DEFAULT_DID_METHOD_WEB;
        }

        String signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;

        String clientId = authenticatorProperties.get(Constraints.PROP_CLIENT_ID);
        if (StringUtils.isBlank(clientId)) {
            clientId = IdentityUtil.getHostName();
        }

        if (StringUtils.isBlank(clientId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Client ID (hostname) cannot be null or empty.");
        }

        String presentationDefinitionId = context
                .getAuthenticatorProperties().get(PROP_PRESENTATION_DEFINITION_ID);

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                    "No presentation definition found for the application.");
        }

        int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());

        // 2. Resolve identifiers and timestamps
        String requestId = generateRequestId();
        String transactionId = context.getContextIdentifier();
        String nonce = generateNonce();
        long createdAt = System.currentTimeMillis();
        long expiresAt = calculateExpiryTime(createdAt);

        // 3. Resolve and process presentation definition
        String presentationDefinition = resolvePresentationDefinition(presentationDefinitionId, null, tenantId);

        // 4. Build the final request object
        String responseUri = buildResponseUri(getBaseUrl());

        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .transactionId(transactionId)
                .clientId(clientId)
                .nonce(nonce)
                .presentationDefinitionId(presentationDefinitionId)
                .presentationDefinition(presentationDefinition)
                .responseUri(responseUri)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .didMethod(didMethod)
                .signingAlgorithm(signingAlgorithm)
                .build();

        // 5. Generate request JWT
        String requestJwt = buildRequestObjectJwt(vpRequest, didMethod, signingAlgorithm);
        vpRequest.setRequestJwt(requestJwt);

        // Store in cache
        getVPRequestDAO().createVPRequest(vpRequest);

        vpRequest.setRequestUri(buildRequestUri(getBaseUrl(), requestId));


        vpRequest.setAuthorizationDetails(buildAuthorizationDetails(vpRequest, presentationDefinition));

        return vpRequest;
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        // Retrieve from DAO (Cache)
        VPRequest vpRequest = getVPRequestDAO().getVPRequestById(requestId, tenantId);

        if (vpRequest == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                    "VP request not found: " + requestId);
        }
        
        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
                StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
                PresentationDefinition pd = null;
                try {
                    pd = getPresentationDefinitionService().getPresentationDefinitionById(
                        vpRequest.getPresentationDefinitionId(), tenantId);
                } catch (Exception e) {
                    throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Error fetching presentation definition", e);
                }
            if (pd != null) {
                vpRequest.setPresentationDefinition(
                        PresentationDefinitionUtil.buildDefinitionJson(pd));
            }
        }

        return vpRequest;
    }

    @Override
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        // Retrieve from DAO (Cache)
        VPRequest vpRequest = getVPRequestDAO().getVPRequestByTransactionId(transactionId, tenantId);

        if (vpRequest == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                    "Transaction not found: " + transactionId);
        }

        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
               StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
           PresentationDefinition pd = null;
           try {
               pd = getPresentationDefinitionService().getPresentationDefinitionById(
                       vpRequest.getPresentationDefinitionId(), tenantId);
           } catch (Exception e) {
               throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                       "Error fetching presentation definition", e);
           }
           if (pd != null) {
               vpRequest.setPresentationDefinition(
                       PresentationDefinitionUtil.buildDefinitionJson(pd));
           }
       }

        return vpRequest;
    }

    @Override
    public VPRequest getVPRequestStatus(String transactionId, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        VPRequest vpRequest = getVPRequestByTransactionId(transactionId, tenantId);

        // Populate request URI if enabled
        vpRequest.setRequestUri(buildRequestUri(getBaseUrl(), vpRequest.getRequestId()));


        return vpRequest;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (isExpired(vpRequest.getExpiresAt())) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                    "VP request has expired: " + requestId);
        }

        // Update in DAO (Cache)
        getVPRequestDAO().updateVPRequestStatus(requestId, status, tenantId);
    }

    @Override
    public String getRequestUri(String requestId, int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        // Validate request exists
        getVPRequestById(requestId, tenantId);

        return buildRequestUri(getBaseUrl(), requestId);
    }

    @Override
    public String getRequestJwt(final String requestId, final int tenantId)
            throws VPAuthenticatorClientException, VPAuthenticatorException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (isExpired(vpRequest.getExpiresAt())) {
            throw new VPAuthenticatorClientException(
                    VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                    "VP request has expired: " + requestId);
        }

        // Check if request is still active
        if (vpRequest.getStatus() != VPRequestStatus.ACTIVE) {
            throw new VPAuthenticatorClientException(
                    VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request is no longer active: " + requestId);
        }

        // Return existing JWT
        if (StringUtils.isNotBlank(vpRequest.getRequestJwt())) {
            return vpRequest.getRequestJwt();
        }

        throw new VPAuthenticatorServerException(
            VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
            "Request JWT is missing for request: " + requestId);
    }

    /**
     * Resolve the presentation definition from ID or inline value.
     *
     * @param definitionId      The presentation definition ID
     * @param inlineDefinition  The inline presentation definition
     * @param tenantId          The tenant ID
     * @return The resolution presentation definition JSON
     * @throws VPAuthenticatorException If an error occurs during resolution
     */
    private String resolvePresentationDefinition(final String definitionId,
                                                 final String inlineDefinition,
                                                 final int tenantId)
            throws VPAuthenticatorException {

        // If inline definition provided, validate and use it
        if (StringUtils.isNotBlank(inlineDefinition)) {
            if (!PresentationDefinitionUtil
                    .isValidPresentationDefinition(inlineDefinition)) {
                throw new VPAuthenticatorClientException(
                        VPAuthenticatorErrorCode
                                .INVALID_PRESENTATION_DEFINITION,
                        "Invalid presentation definition JSON");
            }
            return inlineDefinition;
        }

        // Otherwise, fetch from stored definitions
        if (StringUtils.isNotBlank(definitionId)) {
            PresentationDefinition definition = null;
            try {
                definition = getPresentationDefinitionService()
                        .getPresentationDefinitionById(definitionId, tenantId);
            } catch (Exception e) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Error fetching presentation definition", e);
            }
            return PresentationDefinitionUtil.buildDefinitionJson(definition);
        }

        throw new VPAuthenticatorClientException(
                VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                "No presentation definition available");
    }

    /**
     * Validate the creation request.
     */

    /**
     * Build authorization details for request-by-value response mode.
     *
     * @param vpRequest              The original VP request
     * @param presentationDefinition The presentation definition JSON string
     * @return The authorization details
     */
    private VPRequest.AuthorizationDetails buildAuthorizationDetails(
            final VPRequest vpRequest, final String presentationDefinition) {
        VPRequest.AuthorizationDetails details =
                new VPRequest.AuthorizationDetails();
        details.setClientId(vpRequest.getClientId());
        details.setResponseType(
                OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);
        details.setResponseMode(vpRequest.getResponseMode());
        details.setResponseUri(vpRequest.getResponseUri());
        details.setNonce(vpRequest.getNonce());
        details.setState(vpRequest.getRequestId());

        // Convert String to JsonObject for the model
        if (presentationDefinition != null) {
            JsonObject pdJson = JsonParser.parseString(presentationDefinition)
                    .getAsJsonObject();
            details.setPresentationDefinition(pdJson);
        }
        return details;
    }


    /**
     * Build the request object as a JWT.
     * Note: In production, this should be properly signed with the verifier's
     * private key.
     *
     * @param vpRequest         The VP request model
     * @param didMethod         The DID method to use
     * @param signingAlgorithm  The signing algorithm to use
     * @return The signed request object JWT
     * @throws VPAuthenticatorException If an error occurs during JWT building
     */
    private String buildRequestObjectJwt(final VPRequest vpRequest,
                                         final String didMethod,
                                         final String signingAlgorithm)
            throws VPAuthenticatorException {
        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();
            String activeBaseUrl = getBaseUrl();

            String did = provider.getDID(tenantId, activeBaseUrl);
            String keyId = provider.getSigningKeyId(tenantId, activeBaseUrl);

            // Create claims set
            com.nimbusds.jwt.JWTClaimsSet.Builder claimsBuilder =
                    new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .issuer(did)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                            OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_MODE,
                            vpRequest.getResponseMode())
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_URI,
                            vpRequest.getResponseUri())
                    .claim(OpenID4VPConstants.RequestParams.NONCE,
                            vpRequest.getNonce())
                    .claim(OpenID4VPConstants.RequestParams.STATE,
                            vpRequest.getRequestId())
                    .claim(OpenID4VPConstants.RequestParams.CLIENT_ID,
                            vpRequest.getClientId())
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            // Set expiration
            Date exp = new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS);
            claimsBuilder.expirationTime(exp);

            // Add presentation definition JSON object
            JsonObject storedPdJson = JsonParser.parseString(
                    vpRequest.getPresentationDefinition()).getAsJsonObject();
            JsonObject pdJsonToEmbed;
            if (storedPdJson.has("requested_credentials")) {
                // Simple format, generate the full PE format dynamically
                List<String> inputDescriptors = new ArrayList<>();
                int descIndex = 1;
                JsonArray reqCreds = storedPdJson
                        .getAsJsonArray("requested_credentials");
                for (JsonElement credElem : reqCreds) {
                    if (credElem.isJsonObject()) {
                        JsonObject credObj = credElem.getAsJsonObject();
                        String type = credObj.has("type")
                                ? credObj.get("type").getAsString() : null;
                        String purpose = credObj.has("purpose")
                                ? credObj.get("purpose").getAsString() : null;
                        String issuer = credObj.has("issuer")
                                ? credObj.get("issuer").getAsString() : null;
                        List<String> claims = new ArrayList<>();
                        if (credObj.has("requested_claims")) {
                            JsonArray reqClaims = credObj
                                    .getAsJsonArray("requested_claims");
                            for (JsonElement claim : reqClaims) {
                                claims.add(claim.getAsString());
                            }
                        }

                        String descId = type != null ? type.toLowerCase(
                                Locale.ENGLISH) + "_descriptor" + descIndex
                                : "descriptor_" + descIndex;
                        inputDescriptors.add(PresentationDefinitionUtil
                                .buildInputDescriptorFromRequestedCredential(
                                        descId, type, purpose, claims, issuer));
                        descIndex++;
                    }
                }

                String fullPdString = PresentationDefinitionUtil
                        .buildPresentationDefinition(
                        UUID.randomUUID().toString(),
                        "Dynamic Presentation Definition",
                        "Dynamically generated from requested credentials",
                        inputDescriptors.toArray(new String[0]));
                pdJsonToEmbed = JsonParser.parseString(fullPdString)
                        .getAsJsonObject();
            } else {
                // Fallback if it's already a full PE definition
                pdJsonToEmbed = storedPdJson;
            }

            // Convert to Map for Nimbus
            @SuppressWarnings("unchecked")
            Map<String, Object> pdMap = new Gson()
                    .fromJson(pdJsonToEmbed, Map.class);
            claimsBuilder.claim("presentation_definition", pdMap);

            // Add client_metadata
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put("client_name", did);

            Map<String, Object> vpFormats = new HashMap<>();

            Map<String, Object> ldpVp = new HashMap<>();
            ldpVp.put("proof_type",
                    Arrays.asList("Ed25519Signature2018",
                            "Ed25519Signature2020", "RsaSignature2018"));
            vpFormats.put("ldp_vp", ldpVp);

            Map<String, Object> vcSdJwt = new HashMap<>();
            vcSdJwt.put("sd-jwt_alg_values", Arrays.asList("RS256", "EdDSA"));
            vcSdJwt.put("kb-jwt_alg_values", Arrays.asList("RS256", "EdDSA"));
            vpFormats.put("vc+sd-jwt", vcSdJwt);

            clientMetadata.put("vp_formats", vpFormats);
            claimsBuilder.claim("client_metadata", clientMetadata);

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create header
            JWSHeader header = new JWSHeader.Builder(
                    provider.getSigningAlgorithm())
                    .keyID(keyId)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"))
                    .build();

            JWSObject jwsObject = new JWSObject(header,
                    new Payload(claimsSet.toJSONObject()));

            // Sign using provider logic
            JWSSigner signer = provider.getSigner(tenantId);
            jwsObject.sign(signer);

            return jwsObject.serialize();

        } catch (com.nimbusds.jose.JOSEException
                 | com.google.gson.JsonParseException
                 | org.wso2.carbon.identity.openid4vc.presentation.common
                         .exception.VPException | IllegalArgumentException e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Error building request object JWT", e);
        }
    }

    /**
     * Generate a unique request ID.
     *
     * @return A unique request identifier
     */
    private String generateRequestId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique transaction ID.
     *
     * @return A unique transaction identifier
     */
    private String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique nonce.
     *
     * @return A unique nonce string
     */
    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

    /**
     * Calculate expiry time (default 10 minutes).
     *
     * @param createdAt The creation time in milliseconds
     * @return The expiration time in milliseconds
     */
    private long calculateExpiryTime(final long createdAt) {
        return createdAt + DEFAULT_EXPIRY_MS;
    }

    /**
     * Check if the request is expired.
     *
     * @param expiresAt The expiration time in milliseconds
     * @return True if the request is expired, false otherwise
     */
    private boolean isExpired(final long expiresAt) {
        return System.currentTimeMillis() > expiresAt;
    }

    /**
     * Build the response URI.
     *
     * @param currentBaseUrl The base URL to use
     * @return The complete response URI
     */
    private String buildResponseUri(final String currentBaseUrl) {
        String endpoint = "/openid4vp/v1/response";
        if (currentBaseUrl.endsWith("/")) {
            return currentBaseUrl.substring(0, currentBaseUrl.length() - 1)
                    + endpoint;
        }
        return currentBaseUrl + endpoint;
    }

    /**
     * Build the request URI for a specific request ID.
     *
     * @param currentBaseUrl The base URL to use
     * @param requestId      The request identifier
     * @return The complete request URI
     */
    private String buildRequestUri(final String currentBaseUrl,
                                   final String requestId) {
        String endpoint = "/openid4vp/v1/vp-request/"
                + requestId;
        if (currentBaseUrl.endsWith("/")) {
            return currentBaseUrl.substring(0, currentBaseUrl.length() - 1)
                    + endpoint;
        }
        return currentBaseUrl + endpoint;
    }

    /**
     * Get configured base URL for building URIs.
     *
     * @return The configured base URL
     */
    private String getConfiguredBaseUrl() {
        return IdentityUtil.getServerURL("", true, true);
    }

    /**
     * Extract the IDP name from the SequenceConfig StepMap.
     *
     * @param context Authentication context
     * @return IDP name if found, null otherwise
     */
    private String resolveIdpNameFromSequenceConfig(
            final AuthenticationContext context) {
        if (context.getSequenceConfig() == null) {
            return null;
        }
        Map<Integer, StepConfig> stepMap = context.getSequenceConfig()
                .getStepMap();
        if (stepMap == null) {
            return null;
        }
        StepConfig stepConfig = stepMap.get(context.getCurrentStep());
        if (stepConfig == null) {
            return null;
        }
        for (AuthenticatorConfig authConfig : stepConfig
                .getAuthenticatorList()) {
            if (AUTHENTICATOR_NAME.equals(authConfig.getName())
                    && authConfig.getIdpNames() != null
                    && !authConfig.getIdpNames().isEmpty()) {
                return authConfig.getIdpNames().get(0);
            }
        }
        return null;
    }
}
