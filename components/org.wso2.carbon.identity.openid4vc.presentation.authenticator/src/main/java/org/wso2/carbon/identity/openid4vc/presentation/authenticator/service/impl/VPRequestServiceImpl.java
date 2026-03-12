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
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl.VPRequestDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl implements VPRequestService {

    private final VPRequestDAO vpRequestDAO;
    private final PresentationDefinitionService presentationDefinitionService;
    private volatile String baseUrl;

    /**
     * Default constructor.
     * Note: baseUrl is lazily loaded on first use to avoid OSGi activation timing issues
     * where IdentityUtil may not have loaded identity.xml yet.
     */
    public VPRequestServiceImpl() {
        this.vpRequestDAO = new VPRequestDAOImpl();
        this.presentationDefinitionService = new PresentationDefinitionServiceImpl();
    }

    /**
     * Constructor for dependency injection.
     */

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public VPRequestServiceImpl(VPRequestDAO vpRequestDAO, PresentationDefinitionService presentationDefinitionService,
            String baseUrl) {
        this.vpRequestDAO = vpRequestDAO;
        this.presentationDefinitionService = presentationDefinitionService;
        this.baseUrl = baseUrl;
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
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public VPRequestResponseDTO createVPRequest(VPRequestCreateDTO requestCreateDTO, int tenantId)
            throws VPException {

        // Validate input
        validateCreateRequest(requestCreateDTO);

        // Generate identifiers
        String requestId = OpenID4VPUtil.generateRequestId();
        String transactionId = StringUtils.isNotBlank(requestCreateDTO.getTransactionId())
                ? requestCreateDTO.getTransactionId()
                : OpenID4VPUtil.generateTransactionId();
        String nonce = StringUtils.isNotBlank(requestCreateDTO.getNonce()) ? requestCreateDTO.getNonce()
                : OpenID4VPUtil.generateNonce();

        // Resolve presentation definition
        String presentationDefinition = resolvePresentationDefinition(requestCreateDTO, tenantId);
        String didMethod = "web"; // Force did:web
        String signingAlgorithm = requestCreateDTO.getSigningAlgorithm(); // Use explicit algo from DTO

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

            } catch (Exception e) {
                // Ignore
            }
        }
        if (StringUtils.isBlank(signingAlgorithm)) {
            signingAlgorithm = "EdDSA"; // Default to EdDSA if not provided
        }

        // Calculate timestamps
        long createdAt = System.currentTimeMillis();
        long expiresAt = OpenID4VPUtil.calculateExpiryTime(createdAt);

        // Build response URI
        String responseUri = OpenID4VPUtil.buildResponseUri(getBaseUrl());

        // Create VP request model
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .transactionId(transactionId)
                .clientId(requestCreateDTO.getClientId())
                .nonce(nonce)
                .presentationDefinitionId(requestCreateDTO.getPresentationDefinitionId())
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
        vpRequestDAO.createVPRequest(vpRequest);

        // Generate request URI if enabled
        String requestUri = null;
        if (OpenID4VPUtil.isRequestUriEnabled()) {
            requestUri = OpenID4VPUtil.buildRequestUri(getBaseUrl(), requestId);
        }

        // Build authorization details for by-value mode
        AuthorizationDetailsDTO authorizationDetails = buildAuthorizationDetails(
                vpRequest, presentationDefinition);

        // Build response
        VPRequestResponseDTO response = new VPRequestResponseDTO();
        response.setTransactionId(transactionId);
        response.setRequestId(requestId);
        response.setRequestUri(requestUri);
        response.setAuthorizationDetails(authorizationDetails);
        response.setExpiresAt(expiresAt);

        return response;
    }

    @Override
    public VPRequest getVPRequestById(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Retrieve from DAO (Cache)
        VPRequest vpRequest = vpRequestDAO.getVPRequestById(requestId, tenantId);

        if (vpRequest == null) {
            throw new VPRequestNotFoundException(requestId);
        }
        
        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
                StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
            PresentationDefinition pd = presentationDefinitionService.getPresentationDefinitionById(
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
        VPRequest vpRequest = vpRequestDAO.getVPRequestByTransactionId(transactionId, tenantId);

        if (vpRequest == null) {
            throw new VPRequestNotFoundException("Transaction not found: " + transactionId);
        }

        // Populate presentation definition if missing
        if (StringUtils.isBlank(vpRequest.getPresentationDefinition()) &&
               StringUtils.isNotBlank(vpRequest.getPresentationDefinitionId())) {
           PresentationDefinition pd = presentationDefinitionService.getPresentationDefinitionById(
                   vpRequest.getPresentationDefinitionId(), tenantId);
           if (pd != null) {
               vpRequest.setPresentationDefinition(
                       PresentationDefinitionUtil.buildDefinitionJson(pd));
           }
       }

        return vpRequest;
    }

    @Override
    public VPRequestStatusDTO getVPRequestStatus(String transactionId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestByTransactionId(transactionId, tenantId);

        VPRequestStatusDTO statusDTO = new VPRequestStatusDTO();
        statusDTO.setStatus(vpRequest.getStatus());
        statusDTO.setRequestId(vpRequest.getRequestId());

        return statusDTO;
    }

    @Override
    public void updateVPRequestStatus(String requestId, VPRequestStatus status, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            throw new VPRequestExpiredException(requestId);
        }

        // Update in DAO (Cache)
        vpRequestDAO.updateVPRequestStatus(requestId, status, tenantId);
    }

    @Override
    public String getRequestUri(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate request exists
        getVPRequestById(requestId, tenantId);

        return OpenID4VPUtil.buildRequestUri(getBaseUrl(), requestId);
    }

    @Override
    public String getRequestJwt(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPRequestExpiredException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        // Check if expired
        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
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
        vpRequestDAO.updateVPRequestJwt(requestId, requestJwt, tenantId);

        return requestJwt;
    }

    @Override
    public void deleteVPRequest(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        // Validate exists (optional, could just delete)
        getVPRequestById(requestId, tenantId);

        // Delete from DAO (Cache)
        vpRequestDAO.deleteVPRequest(requestId, tenantId);
    }

    @Override
    public int processExpiredRequests(int tenantId) throws VPException {
        // markExpiredRequests logic - delegated to DAO/Cache expiry
        return vpRequestDAO.markExpiredRequests(tenantId);
    }

    @Override
    public boolean isRequestActive(String requestId, int tenantId)
            throws VPRequestNotFoundException, VPException {

        VPRequest vpRequest = getVPRequestById(requestId, tenantId);

        if (OpenID4VPUtil.isExpired(vpRequest.getExpiresAt())) {
            return false;
        }

        return vpRequest.getStatus() == VPRequestStatus.ACTIVE;
    }

    /**
     * Validate the request creation DTO.
     */
    private void validateCreateRequest(VPRequestCreateDTO requestCreateDTO) throws VPException {
        if (requestCreateDTO == null) {
            throw new VPException("Request creation DTO cannot be null");
        }

        if (StringUtils.isBlank(requestCreateDTO.getClientId())) {
            throw new VPException("Client ID is required");
        }

        // Either presentation definition ID or inline definition required
        if (StringUtils.isBlank(requestCreateDTO.getPresentationDefinitionId()) &&
                requestCreateDTO.getPresentationDefinition() == null) {
            throw new VPException("Either presentationDefinitionId or presentationDefinition is required");
        }
    }

    /**
     * Resolve the presentation definition from ID or inline value.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private String resolvePresentationDefinition(VPRequestCreateDTO requestCreateDTO, int tenantId)
            throws VPException {

        // If inline definition provided, validate and use it
        if (requestCreateDTO.getPresentationDefinition() != null) {
            String definitionJson = requestCreateDTO.getPresentationDefinition().toString();
            if (!PresentationDefinitionUtil.isValidPresentationDefinition(definitionJson)) {
                throw new VPException("Invalid presentation definition JSON");
            }
            return definitionJson;
        }

        // Otherwise, fetch from stored definitions
        String definitionId = requestCreateDTO.getPresentationDefinitionId();
        if (StringUtils.isNotBlank(definitionId)) {
            PresentationDefinition definition = presentationDefinitionService.getPresentationDefinitionById(
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
     * Get configured base URL for building URIs.
     */
    private String getConfiguredBaseUrl() {
        return OpenID4VPUtil.getBaseUrl();
    }

    /**
     * Build the request object as a JWT.
     * Note: In production, this should be properly signed with the verifier's
     * private key.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
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
                    .issueTime(new java.util.Date())
                    .jwtID(java.util.UUID.randomUUID().toString());

            // Set expiration (10 minutes)
            java.util.Date exp = new java.util.Date(System.currentTimeMillis() + 600000);
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
                        
                        String descId = type != null ? type.toLowerCase(java.util.Locale.ENGLISH) + "_descriptor" +
                        descIndex : "descriptor_" + descIndex;
                        inputDescriptors.add(
                                PresentationDefinitionUtil.buildInputDescriptorFromRequestedCredential(
                                        descId, type, purpose, claims, issuer));
                        descIndex++;
                    }
                }
                
                String fullPdString = PresentationDefinitionUtil.buildPresentationDefinition(
                        java.util.UUID.randomUUID().toString(), 
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

        } catch (Exception e) {
            throw new RuntimeException("Error building request object JWT", e);
        }
    }
}
