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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
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

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 */
public class VPRequestServiceImpl extends VPRequestService {

    /**
     * Key for the presentation definition ID property.
     */
    private static final String PROP_PRESENTATION_DEFINITION_ID = Constraints.PROP_PRESENTATION_DEFINITION_ID;

    /**
     * Default expiry time for VP requests in milliseconds (1 minutes).
     */
    private static final long DEFAULT_EXPIRY_MS = 60000;

    /**
     * Holder for the PresentationDefinitionService reference.
     */
    private final AtomicReference<PresentationDefinitionService> presentationDefinitionServiceRef;

    /**
     * Cached base URL for building URIs.
     */
    private volatile String baseUrl;

    public VPRequestServiceImpl() {

        this.presentationDefinitionServiceRef =
                new AtomicReference<>(VPServiceDataHolder.getPresentationDefinitionService());
    }

    /**
     * Constructor for dependency injection.
     *
     * @param presentationDefinitionService The presentation definition service.
     * @param baseUrl                       The base URL for the server.
     */
    public VPRequestServiceImpl(PresentationDefinitionService presentationDefinitionService,
            String baseUrl) {

        this.presentationDefinitionServiceRef = new AtomicReference<>(presentationDefinitionService);
        this.baseUrl = baseUrl;
    }


    /**
     * Get the presentation definition service with initialization check.
     *
     * @return PresentationDefinitionService instance.
     * @throws VPAuthenticatorException If the service is not initialized.
     */
    private PresentationDefinitionService getPresentationDefinitionService() throws VPAuthenticatorException {

        PresentationDefinitionService service = presentationDefinitionServiceRef.get();
        if (service == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not initialized.");
        }
        return service;
    }

    @Override
    public String generateRequestJwt(String requestId) throws VPAuthenticatorException {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        if (context == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "No authentication context found for request ID: " + requestId);
        }

        VPContext vpContext = VPServiceDataHolder.getVPContextService().getVPContext(requestId)
                .orElseThrow(() -> new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "No VP context found for request ID: " + requestId));

        // 1. Resolve basic configuration.
        String didMethod = Constraints.DEFAULT_DID_METHOD_WEB;
        String signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;
        String baseUrl = resolveTenantAwareBaseUrl();

        String clientId = getClientId(baseUrl);
        String presentationDefinitionId = context.getAuthenticatorProperties().get(PROP_PRESENTATION_DEFINITION_ID);

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                    "No presentation definition found for the application.");
        }

        int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());

        // 2. Resolve identifiers and timestamps.
        String nonce = vpContext.getNonce();
        if (StringUtils.isBlank(nonce)) {
            nonce = generateNonce();
            vpContext.setNonce(nonce);
            VPServiceDataHolder.getVPContextService().updateVPContext(requestId, vpContext);
        }

        long createdAt = vpContext.getCreatedAt();
        long expiresAt = calculateExpiryTime(createdAt, DEFAULT_EXPIRY_MS);

        // 3. Resolve and process presentation definition.
        String presentationDefinition = resolvePresentationDefinition(presentationDefinitionId, tenantId);

        // 4. Build temporary request object for JWT generation.
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .clientId(clientId)
                .nonce(nonce)
                .presentationDefinitionId(presentationDefinitionId)
                .presentationDefinition(presentationDefinition)
                .responseUri(buildResponseUri(baseUrl))
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .didMethod(didMethod)
                .signingAlgorithm(signingAlgorithm)
                .build();

        return buildRequestObjectJwt(vpRequest, didMethod);
    }

    @Override
    public Map<String, String> getVPRequestMetadata(AuthenticationContext context) throws VPAuthenticatorException {

        String baseUrl = resolveTenantAwareBaseUrl();
        String requestId = context.getContextIdentifier();

        Map<String, String> metadata = new HashMap<>();
        metadata.put(Constraints.PARAM_CLIENT_ID, getClientId(baseUrl));
        metadata.put(Constraints.PARAM_REQUEST_URI, buildRequestUri(baseUrl, requestId));

        return metadata;
    }

    private String getClientId(String baseUrl) throws VPAuthenticatorClientException {

        if (StringUtils.isBlank(baseUrl)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Base URL cannot be null or empty.");
        }

        return Constraints.DID_WEB_PREFIX + baseUrl
                .replaceFirst(Constraints.URL_SCHEME_REGEX, "")
                .replaceAll(Constraints.TRAILING_SLASH_REGEX, "");
    }

    @Override
    public VPRequest createVPRequest(AuthenticationContext context) throws VPAuthenticatorException {

        String requestId = context.getContextIdentifier();
        String requestJwt = generateRequestJwt(requestId);
        
        Map<String, String> metadata = getVPRequestMetadata(context);

        return new VPRequest.Builder()
                .requestId(requestId)
                .clientId(metadata.get(Constraints.PARAM_CLIENT_ID))
                .requestJwt(requestJwt)
                .requestUri(metadata.get(Constraints.PARAM_REQUEST_URI))
                .status(VPRequestStatus.ACTIVE)
                .build();
    }


    /**
     * Resolve the presentation definition from ID or inline value.
     *
     * @param definitionId      The presentation definition ID.
     * @param tenantId          The tenant ID.
     * @return The resolution presentation definition JSON.
     * @throws VPAuthenticatorException If an error occurs during resolution.
     */
    private String resolvePresentationDefinition(final String definitionId,
                                                 final int tenantId)
            throws VPAuthenticatorException {

        if (StringUtils.isNotBlank(definitionId)) {
            PresentationDefinition definition = null;
            try {
                definition = getPresentationDefinitionService()
                        .getPresentationDefinitionById(definitionId, tenantId);
            } catch (Exception e) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Error fetching presentation definition.", e);
            }
            return PresentationDefinitionUtil.buildDefinitionJson(definition);
        }

        throw new VPAuthenticatorClientException(
                VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                "No presentation definition available.");
    }

    /**
     * Build the request object as a JWT.
     *
     * <p>Note: In production, this should be properly signed with the verifier's
     * private key.</p>
     *
     * @param vpRequest         The VP request model.
     * @param didMethod         The DID method to use.
     * @return The signed request object JWT.
     * @throws VPAuthenticatorException If an error occurs during JWT building.
     */
    private String buildRequestObjectJwt(final VPRequest vpRequest,
                                         final String didMethod)
            throws VPAuthenticatorException {

        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();
            String activeBaseUrl = resolveTenantAwareBaseUrl();

            String did = provider.getDID(tenantId, activeBaseUrl);
            String keyId = provider.getSigningKeyId(tenantId, activeBaseUrl);

            // Create claims set.
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

            // Set expiration.
            Date exp = new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS);
            claimsBuilder.expirationTime(exp);

            // Add presentation definition JSON object.
            JsonObject storedPdJson = JsonParser.parseString(
                    vpRequest.getPresentationDefinition()).getAsJsonObject();
            // Convert to Map for Nimbus.
            @SuppressWarnings("unchecked")
            Map<String, Object> pdMap = new Gson()
                    .fromJson(storedPdJson, Map.class);
            claimsBuilder.claim(Constraints.CLAIM_PRESENTATION_DEFINITION, pdMap);

            // Add client_metadata.
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put(Constraints.METADATA_CLIENT_NAME, did);

            Map<String, Object> vpFormats = new HashMap<>();

            Map<String, Object> vcSdJwt = new HashMap<>();
            vcSdJwt.put(Constraints.METADATA_SD_JWT_ALG_VALUES,
                    Arrays.asList(Constraints.ALG_RS256, Constraints.ALG_EDDSA));
            vcSdJwt.put(Constraints.METADATA_KB_JWT_ALG_VALUES,
                    Arrays.asList(Constraints.ALG_RS256, Constraints.ALG_EDDSA));
            vpFormats.put(Constraints.FORMAT_VC_SD_JWT, vcSdJwt);

            clientMetadata.put(Constraints.METADATA_VP_FORMATS, vpFormats);
            claimsBuilder.claim(Constraints.CLAIM_CLIENT_METADATA, clientMetadata);

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create header.
            JWSHeader header = new JWSHeader.Builder(
                    provider.getSigningAlgorithm())
                    .keyID(keyId)
                    .type(new JOSEObjectType(Constraints.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                    .build();

            JWSObject jwsObject = new JWSObject(header,
                    new Payload(claimsSet.toJSONObject()));

            // Sign using provider logic.
            JWSSigner signer = provider.getSigner(tenantId);
            jwsObject.sign(signer);

            return jwsObject.serialize();

        } catch (com.nimbusds.jose.JOSEException
                 | com.google.gson.JsonParseException
                 | org.wso2.carbon.identity.openid4vc.presentation.common
                         .exception.VPException | IllegalArgumentException e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Error building request object JWT.", e);
        }
    }


    /**
     * Generate a unique nonce.
     *
     * @return A unique nonce string.
     */
    private String generateNonce() {

        return UUID.randomUUID().toString();
    }

    /**
     * Calculate expiry time.
     *
     * @param createdAt The creation time in milliseconds.
     * @param timeoutMs The timeout duration in milliseconds.
     * @return The expiration time in milliseconds.
     */
    private long calculateExpiryTime(final long createdAt, final long timeoutMs) {

        return createdAt + timeoutMs;
    }

    /**
     * Build the response URI.
     *
     * @param currentBaseUrl The base URL to use.
     * @return The complete response URI.
     */
    private String buildResponseUri(final String currentBaseUrl) {

        String endpoint = Constraints.RESPONSE_URI_ENDPOINT;
        if (currentBaseUrl.endsWith("/")) {
            return currentBaseUrl.substring(0, currentBaseUrl.length() - 1)
                    + endpoint;
        }
        return currentBaseUrl + endpoint;
    }

    /**
     * Build the request URI for a specific request ID.
     *
     * @param currentBaseUrl The base URL to use.
     * @param requestId      The request identifier.
     * @return The complete request URI.
     */
    private String buildRequestUri(final String currentBaseUrl,
                                   final String requestId) {

        String endpoint = Constraints.REQUEST_URI_ENDPOINT
                + requestId;
        if (currentBaseUrl.endsWith("/")) {
            return currentBaseUrl.substring(0, currentBaseUrl.length() - 1)
                    + endpoint;
        }
        return currentBaseUrl + endpoint;
    }

    /**
     * Resolve tenant-aware base URL from framework utilities.
     *
     * @return Tenant-aware base URL.
     * @throws VPAuthenticatorException If URL resolution fails.
     */
    private String resolveTenantAwareBaseUrl() throws VPAuthenticatorException {

        try {
            return ServiceURLBuilder.create().build().getAbsolutePublicUrlWithoutPath();
        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving tenant-aware base URL.", e);
        }
    }
}
