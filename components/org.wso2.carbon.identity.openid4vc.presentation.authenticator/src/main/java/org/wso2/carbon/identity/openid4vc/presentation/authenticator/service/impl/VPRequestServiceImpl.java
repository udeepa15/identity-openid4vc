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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl implements VPRequestService {

    private static final Log log = LogFactory.getLog(VPRequestServiceImpl.class);

    // Configuration property keys
    private static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    private static final String PROP_RESPONSE_MODE = "ResponseMode";
    private static final String PROP_CLIENT_ID = "ClientId";
    private static final String PROP_DID_METHOD = "DIDMethod";
    private static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";

    private final AtomicReference<VPRequestDAO> vpRequestDAORef;
    private final AtomicReference<PresentationDefinitionService> presentationDefinitionServiceRef;
    private volatile String baseUrl;

    /**
     * Default constructor.
     * Note: baseUrl is lazily loaded on first use to avoid OSGi activation timing issues
     * where IdentityUtil may not have loaded identity.xml yet.
     */
    public VPRequestServiceImpl() {
        this.vpRequestDAORef = new AtomicReference<>(new VPRequestDAOImpl());
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

    private VPRequestDAO getVPRequestDAO() throws VPException {
        VPRequestDAO dao = vpRequestDAORef.get();
        if (dao == null) {
            throw new VPException("VP request DAO is not initialized");
        }
        return dao;
    }

    private PresentationDefinitionService getPresentationDefinitionService() throws VPException {
        PresentationDefinitionService service = presentationDefinitionServiceRef.get();
        if (service == null) {
            throw new VPException("Presentation definition service is not initialized");
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
    public VPRequestDTO createVPRequest(AuthenticationContext context) throws VPException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        VPRequestDTO createDTO = new VPRequestDTO();

        // Set DID Method if configured
        String didMethod = authenticatorProperties.get(PROP_DID_METHOD);
        if (StringUtils.isNotBlank(didMethod)) {
            createDTO.setDidMethod(didMethod);
        }

        // Set Signing Algorithm (Default to EdDSA)
        String signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;
        createDTO.setSigningAlgorithm(signingAlgorithm);

        // Set client ID from config or hostname
        String clientId = authenticatorProperties.get(PROP_CLIENT_ID);
        if (StringUtils.isBlank(clientId)) {
            clientId = IdentityUtil.getHostName();
        }

        if (StringUtils.isBlank(clientId)) {
            throw new VPException("Client ID (hostname) cannot be null or empty.");
        }
        createDTO.setClientId(clientId);

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
        String responseMode = OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST;
        createDTO.setResponseMode(responseMode);

        // Set transaction ID to context identifier for correlation
        createDTO.setTransactionId(context.getContextIdentifier());

        int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
        return createVPRequest(createDTO, tenantId);
    }

    @Override
    public VPRequestDTO createVPRequest(VPRequestDTO requestDTO, int tenantId)
            throws VPException {

        // Validate input
        validateCreateRequest(requestDTO);

        // Generate identifiers
        String requestId = generateRequestId();
        String transactionId = StringUtils.isNotBlank(requestDTO.getTransactionId())
                ? requestDTO.getTransactionId()
                : generateTransactionId();
        String nonce = StringUtils.isNotBlank(requestDTO.getNonce()) ? requestDTO.getNonce()
                : generateNonce();

        // Resolve presentation definition
        String presentationDefinition = resolvePresentationDefinition(requestDTO, tenantId);
        String didMethod = "web"; // Force did:web
        String signingAlgorithm = requestDTO.getSigningAlgorithm(); // Use explicit algo from DTO

        // Extract and clean internal configuration
        if (StringUtils.isNotBlank(presentationDefinition)) {
            try {
                JsonObject pdJson = JsonParser.parseString(presentationDefinition).getAsJsonObject();
                if (pdJson.has("_internal")) {
                    JsonObject internal = pdJson.getAsJsonObject("_internal");
                    if (StringUtils.isBlank(signingAlgorithm) && internal.has("signing_algorithm")) {
                        signingAlgorithm = internal.get("signing_algorithm").getAsString();
                    }
                    // Remove internal config to keep spec compliant
                    pdJson.remove("_internal");
                    presentationDefinition = pdJson.toString();
                }

            } catch (com.google.gson.JsonParseException | IllegalStateException e) {
                // Ignore malformed JSON or invalid access
            }
        }
        if (StringUtils.isBlank(signingAlgorithm)) {
            signingAlgorithm = "EdDSA"; // Default to EdDSA if not provided
        }

        // Calculate timestamps
        long createdAt = System.currentTimeMillis();
        long expiresAt = calculateExpiryTime(createdAt);

        // Build response URI
        String responseUri = buildResponseUri(getBaseUrl());

        // Create VP request model
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .transactionId(transactionId)
                .clientId(requestDTO.getClientId())
                .nonce(nonce)
                .presentationDefinitionId(requestDTO.getPresentationDefinitionId())
                .presentationDefinition(presentationDefinition) // Still set it in memory
                .responseUri(responseUri)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .didMethod(didMethod)
                .signingAlgorithm(signingAlgorithm)
                .build();

        // Generate and set the Request JWT immediately
        String requestJwt = buildRequestObjectJwt(vpRequest, didMethod, signingAlgorithm);
        vpRequest.setRequestJwt(requestJwt);

        // Persist to database (which is now backed by Cache via DAO)
        getVPRequestDAO().createVPRequest(vpRequest);

        // Generate request URI if enabled
        String requestUri = null;
        if (isRequestUriEnabled()) {
            requestUri = buildRequestUri(getBaseUrl(), requestId);
        }

        // Build authorization details for by-value mode
        AuthorizationDetailsDTO authorizationDetails = buildAuthorizationDetails(
                vpRequest, presentationDefinition);

        // Build response
        VPRequestDTO response = new VPRequestDTO();
        response.setTransactionId(transactionId);
        response.setRequestId(requestId);
        response.setRequestUri(requestUri);
        response.setAuthorizationDetails(authorizationDetails);
        response.setExpiresAt(expiresAt);
        response.setStatus(vpRequest.getStatus());

        return response;
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Retrieve from DAO (Cache)
        VPRequest vpRequest = getVPRequestDAO().getVPRequestById(requestId, tenantId);

        if (vpRequest == null) {
            throw new VPRequestNotFoundException(requestId);
        }
        
        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
                StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
                PresentationDefinition pd = getPresentationDefinitionService().getPresentationDefinitionById(
                    vpRequest.getPresentationDefinitionId(), tenantId);
            if (pd != null) {
                vpRequest.setPresentationDefinition(
                        PresentationDefinitionUtil.buildDefinitionJson(pd));
            }
        }

        return vpRequest;
    }

    @Override
    public VPRequest getVPRequestByTransactionId(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Retrieve from DAO (Cache)
        VPRequest vpRequest = getVPRequestDAO().getVPRequestByTransactionId(transactionId, tenantId);

        if (vpRequest == null) {
            throw new VPRequestNotFoundException("Transaction not found: " + transactionId);
        }

        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
               StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
           PresentationDefinition pd = getPresentationDefinitionService().getPresentationDefinitionById(
                   vpRequest.getPresentationDefinitionId(), tenantId);
           if (pd != null) {
               vpRequest.setPresentationDefinition(
                       PresentationDefinitionUtil.buildDefinitionJson(pd));
           }
       }

        return vpRequest;
    }

    @Override
    public VPRequestDTO getVPRequestStatus(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestByTransactionId(transactionId, tenantId);

        VPRequestDTO statusDTO = new VPRequestDTO();
        statusDTO.setStatus(vpRequest.getStatus());
        statusDTO.setRequestId(vpRequest.getRequestId());
        statusDTO.setTransactionId(vpRequest.getTransactionId());

        return statusDTO;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (isExpired(vpRequest.getExpiresAt())) {
            throw new VPRequestExpiredException(requestId);
        }

        // Update in DAO (Cache)
        getVPRequestDAO().updateVPRequestStatus(requestId, status, tenantId);
    }

    @Override
    public String getRequestUri(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate request exists
        getVPRequestById(requestId, tenantId);

        return buildRequestUri(getBaseUrl(), requestId);
    }

    @Override
    public String getRequestJwt(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (isExpired(vpRequest.getExpiresAt())) {
            throw new VPRequestExpiredException(requestId);
        }

        // Check if request is still active
        if (vpRequest.getStatus() != VPRequestStatus.ACTIVE) {
            throw new VPException("Request is no longer active: " + requestId);
        }

        // Return existing JWT if already generated
        if (StringUtils.isNotBlank(vpRequest.getRequestJwt())) {
            return vpRequest.getRequestJwt();
        }

        // Regenerate JWT if missing (fallback)
        // Use stored metadata if available, otherwise default
        String didMethod = "web"; // Force did:web
        String signingAlgorithm = StringUtils.isNotBlank(vpRequest.getSigningAlgorithm()) ? 
        vpRequest.getSigningAlgorithm() : "RS256";

        String requestJwt = buildRequestObjectJwt(vpRequest, didMethod, signingAlgorithm);

        // Store generated JWT
        getVPRequestDAO().updateVPRequestJwt(requestId, requestJwt, tenantId);

        return requestJwt;
    }

    @Override
    public void deleteVPRequest(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate exists (optional, could just delete)
        getVPRequestById(requestId, tenantId);

        // Delete from DAO (Cache)
        getVPRequestDAO().deleteVPRequest(requestId, tenantId);
    }

    @Override
    public int processExpiredRequests(int tenantId) throws VPException {
        // markExpiredRequests logic - delegated to DAO/Cache expiry
        return getVPRequestDAO().markExpiredRequests(tenantId);
    }

    @Override
    public boolean isRequestActive(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        if (isExpired(vpRequest.getExpiresAt())) {
            return false;
        }

        return vpRequest.getStatus() == VPRequestStatus.ACTIVE;
    }

    /**
     * Validate the request creation DTO.
     */
    private void validateCreateRequest(VPRequestDTO requestDTO) throws VPException {
        if (requestDTO == null) {
            throw new VPException("Request creation DTO cannot be null");
        }

        if (StringUtils.isBlank(requestDTO.getClientId())) {
            throw new VPException("Client ID is required");
        }

        // Either presentation definition ID or inline definition required
        if (StringUtils.isBlank(requestDTO.getPresentationDefinitionId()) &&
                requestDTO.getPresentationDefinition() == null) {
            throw new VPException("Either presentationDefinitionId or presentationDefinition is required");
        }
    }

    /**
     * Resolve the presentation definition from ID or inline value.
     */
    private String resolvePresentationDefinition(VPRequestDTO requestDTO, int tenantId)
            throws VPException {

        // If inline definition provided, validate and use it
        if (requestDTO.getPresentationDefinition() != null) {
            String definitionJson = requestDTO.getPresentationDefinition().toString();
            if (!PresentationDefinitionUtil.isValidPresentationDefinition(definitionJson)) {
                throw new VPException("Invalid presentation definition JSON");
            }
            return definitionJson;
        }

        // Otherwise, fetch from stored definitions
        String definitionId = requestDTO.getPresentationDefinitionId();
        if (StringUtils.isNotBlank(definitionId)) {
                PresentationDefinition definition = getPresentationDefinitionService().getPresentationDefinitionById(
                    definitionId, tenantId);
            return PresentationDefinitionUtil.buildDefinitionJson(definition);
        }

        throw new VPException("No presentation definition available");
    }

    /**
     * Build authorization details DTO for by-value response mode.
     */
    private AuthorizationDetailsDTO buildAuthorizationDetails(VPRequest vpRequest,
            String presentationDefinition) {
        AuthorizationDetailsDTO details = new AuthorizationDetailsDTO();
        details.setClientId(vpRequest.getClientId());
        details.setResponseType(OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);
        details.setResponseMode(vpRequest.getResponseMode());
        details.setResponseUri(vpRequest.getResponseUri());
        details.setNonce(vpRequest.getNonce());
        details.setState(vpRequest.getRequestId());

        // Convert String to JsonObject for the DTO
        if (presentationDefinition != null) {
            JsonObject pdJson = JsonParser.parseString(presentationDefinition).getAsJsonObject();
            details.setPresentationDefinition(pdJson);
        }

        return details;
    }


    /**
     * Build the request object as a JWT.
     * Note: In production, this should be properly signed with the verifier's
     * private key.
     */
    private String buildRequestObjectJwt(VPRequest vpRequest, String didMethod, String signingAlgorithm) {
        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();
            String baseUrl = getBaseUrl();

            String did = provider.getDID(tenantId, baseUrl);
            String keyId = provider.getSigningKeyId(tenantId, baseUrl);

            // Create claims set
            com.nimbusds.jwt.JWTClaimsSet.Builder claimsBuilder = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .issuer(did)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                            OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_MODE, vpRequest.getResponseMode())
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_URI, vpRequest.getResponseUri())
                    .claim(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce())
                    .claim(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId())
                    .claim(OpenID4VPConstants.RequestParams.CLIENT_ID, vpRequest.getClientId())
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            // Set expiration (10 minutes)
            Date exp = new Date(System.currentTimeMillis() + 600000);
            claimsBuilder.expirationTime(exp);

            // Add presentation definition JSON object
            JsonObject storedPdJson = com.google.gson.JsonParser.parseString(vpRequest.getPresentationDefinition())
                    .getAsJsonObject();
            
            JsonObject pdJsonToEmbed;
            if (storedPdJson.has("requested_credentials")) {
                // It's the simple format, generate the full PE format dynamically
                java.util.List<String> inputDescriptors = new java.util.ArrayList<>();
                int descIndex = 1;
                com.google.gson.JsonArray reqCreds = storedPdJson.getAsJsonArray("requested_credentials");
                for (com.google.gson.JsonElement credElem : reqCreds) {
                    if (credElem.isJsonObject()) {
                        JsonObject credObj = credElem.getAsJsonObject();
                        String type = credObj.has("type") ? credObj.get("type").getAsString() : null;
                        String purpose = credObj.has("purpose") ? credObj.get("purpose").getAsString() : null;
                        String issuer = credObj.has("issuer") ? credObj.get("issuer").getAsString() : null;
                        
                        java.util.List<String> claims = new java.util.ArrayList<>();
                        if (credObj.has("requested_claims")) {
                            com.google.gson.JsonArray reqClaims = credObj.getAsJsonArray("requested_claims");
                            for (com.google.gson.JsonElement claim : reqClaims) {
                                claims.add(claim.getAsString());
                            }
                        }
                        
                        String descId = type != null ? type.toLowerCase(Locale.ENGLISH) + "_descriptor" +
                        descIndex : "descriptor_" + descIndex;
                        inputDescriptors.add(
                                PresentationDefinitionUtil.buildInputDescriptorFromRequestedCredential(
                                        descId, type, purpose, claims, issuer));
                        descIndex++;
                    }
                }
                
                String fullPdString = PresentationDefinitionUtil.buildPresentationDefinition(
                        UUID.randomUUID().toString(), 
                        "Dynamic Presentation Definition", 
                        "Dynamically generated from requested credentials", 
                        inputDescriptors.toArray(new String[0]));
                pdJsonToEmbed = com.google.gson.JsonParser.parseString(fullPdString).getAsJsonObject();
            } else {
                // Fallback if it's already a full PE definition
                pdJsonToEmbed = storedPdJson;
            }

            // Convert to Map for Nimbus
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> pdMap = new com.google.gson.Gson()
                    .fromJson(pdJsonToEmbed, java.util.Map.class);
            claimsBuilder.claim("presentation_definition", pdMap);

            // Add client_metadata
            java.util.Map<String, Object> clientMetadata = new java.util.HashMap<>();
            clientMetadata.put("client_name", did);

            java.util.Map<String, Object> vpFormats = new java.util.HashMap<>();

            java.util.Map<String, Object> ldpVp = new java.util.HashMap<>();
            ldpVp.put("proof_type",
                    java.util.Arrays.asList("Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"));
            vpFormats.put("ldp_vp", ldpVp);

            java.util.Map<String, Object> vcSdJwt = new java.util.HashMap<>();
            vcSdJwt.put("sd-jwt_alg_values", java.util.Arrays.asList("RS256", "EdDSA"));
            vcSdJwt.put("kb-jwt_alg_values", java.util.Arrays.asList("RS256", "EdDSA"));
            vpFormats.put("vc+sd-jwt", vcSdJwt);

            clientMetadata.put("vp_formats", vpFormats);
            claimsBuilder.claim("client_metadata", clientMetadata);

            com.nimbusds.jwt.JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create header
            com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(
                    provider.getSigningAlgorithm())
                    .keyID(keyId)
                    .type(new com.nimbusds.jose.JOSEObjectType("oauth-authz-req+jwt"))
                    .build();

            com.nimbusds.jose.JWSObject jwsObject = new com.nimbusds.jose.JWSObject(header,
                    new com.nimbusds.jose.Payload(claimsSet.toJSONObject()));

            // Sign using provider logic
            com.nimbusds.jose.JWSSigner signer = provider.getSigner(tenantId);
            jwsObject.sign(signer);

            return jwsObject.serialize();

        } catch (com.nimbusds.jose.JOSEException | com.google.gson.JsonParseException | VPException |
                 IllegalArgumentException e) {
            throw new RuntimeException("Error building request object JWT", e);
        }
    }

    /**
     * Resolve the presentation definition ID for the application.
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

                if (StringUtils.isBlank(idpName)) {
                    idpName = resolveIdpNameFromSequenceConfig(context);
                }

                String tenantDomain = context.getTenantDomain();
                if (StringUtils.isNotBlank(idpName)) {
                    IdentityProvider idp = IdentityProviderManager.getInstance()
                            .getIdPByName(idpName, tenantDomain);
                    if (idp != null) {
                        for (FederatedAuthenticatorConfig fedAuthConfig : idp.getFederatedAuthenticatorConfigs()) {
                            if (AUTHENTICATOR_NAME.equals(fedAuthConfig.getName())) {
                                for (Property property : fedAuthConfig.getProperties()) {
                                    if (PROP_PRESENTATION_DEFINITION_ID.equals(property.getName())) {
                                        return property.getValue();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return configId;
        } catch (org.wso2.carbon.idp.mgt.IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while resolving presentation definition ID.", e);
            }
        }
        return null;
    }

    /**
     * Generate a unique request ID.
     */
    private String generateRequestId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique transaction ID.
     */
    private String generateTransactionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a unique nonce.
     */
    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

    /**
     * Calculate expiry time (default 10 minutes).
     */
    private long calculateExpiryTime(long createdAt) {
        return createdAt + 600000;
    }

    /**
     * Check if the request is expired.
     */
    private boolean isExpired(long expiresAt) {
        return System.currentTimeMillis() > expiresAt;
    }

    /**
     * Build the response URI.
     */
    private String buildResponseUri(String baseUrl) {
        String endpoint = "/identity/openid4vc/presentation/submission";
        if (baseUrl.endsWith("/")) {
            return baseUrl.substring(0, baseUrl.length() - 1) + endpoint;
        }
        return baseUrl + endpoint;
    }

    /**
     * Build the request URI for a specific request ID.
     */
    private String buildRequestUri(String baseUrl, String requestId) {
        String endpoint = "/identity/openid4vc/presentation/requests/" + requestId;
        if (baseUrl.endsWith("/")) {
            return baseUrl.substring(0, baseUrl.length() - 1) + endpoint;
        }
        return baseUrl + endpoint;
    }

    /**
     * Check if request URI is enabled (always true for this implementation).
     */
    private boolean isRequestUriEnabled() {
        return true;
    }

    /**
     * Get configured base URL for building URIs.
     */
    private String getConfiguredBaseUrl() {
        return IdentityUtil.getServerURL("", true, true);
    }

    /**
     * Extract the IDP name from the SequenceConfig StepMap.
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
            if (AUTHENTICATOR_NAME.equals(authConfig.getName())
                    && authConfig.getIdpNames() != null
                    && !authConfig.getIdpNames().isEmpty()) {
                return authConfig.getIdpNames().get(0);
            }
        }
        return null;
    }
}
