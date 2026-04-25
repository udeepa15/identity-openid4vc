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
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
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

    private static final String PROP_PRESENTATION_DEFINITION_ID = Constraints.PROP_PRESENTATION_DEFINITION_ID;
    private static final long DEFAULT_EXPIRY_MS = 60000;

    private final AtomicReference<PresentationDefinitionService> presentationDefinitionServiceRef;
    private volatile String baseUrl;

    public VPRequestServiceImpl() {
        this.presentationDefinitionServiceRef =
                new AtomicReference<>(VPServiceDataHolder.getPresentationDefinitionService());
    }

    public VPRequestServiceImpl(PresentationDefinitionService presentationDefinitionService,
                                String baseUrl) {
        this.presentationDefinitionServiceRef = new AtomicReference<>(presentationDefinitionService);
        this.baseUrl = baseUrl;
    }

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

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (!(vpContextObj instanceof VPContext)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "No VP context found for request ID: " + requestId);
        }

        String didMethod = Constraints.DEFAULT_DID_METHOD_WEB;
        String signingAlgorithm = OpenID4VPConstants.Verification.ALG_EDDSA;
        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();

        String clientId = VPAuthenticatorUtil.getClientId(baseUrl);
        String presentationDefinitionId = MapUtils.getString(context.getAuthenticatorProperties(),
                PROP_PRESENTATION_DEFINITION_ID);

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION,
                    "No presentation definition found for the application.");
        }

        int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
        String nonce = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + DEFAULT_EXPIRY_MS;

        String presentationDefinition = resolvePresentationDefinition(presentationDefinitionId, tenantId);

        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(requestId)
                .clientId(clientId)
                .nonce(nonce)
                .presentationDefinitionId(presentationDefinitionId)
                .presentationDefinition(presentationDefinition)
                .responseUri(baseUrl + Constraints.RESPONSE_URI_ENDPOINT)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(expiresAt)
                .tenantId(tenantId)
                .didMethod(didMethod)
                .signingAlgorithm(signingAlgorithm)
                .build();

        return buildRequestObjectJwt(vpRequest, didMethod);
    }

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

    private String buildRequestObjectJwt(final VPRequest vpRequest,
                                         final String didMethod)
            throws VPAuthenticatorException {

        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();
            String activeBaseUrl = VPAuthenticatorUtil
                    .resolveBaseUrl();

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

                            // --- LISSI & EUDI WALLET COMPATIBILITY ---
                            // Lissi strictly requires 'client_id_scheme'. Since WSO2 is signing
                            // this request with a DID, we must explicitly declare the scheme as "did"
                            // and use the DID itself as the client_id.
                            .claim("client_id_scheme", "did")
                            .claim(OpenID4VPConstants.RequestParams.CLIENT_ID, did)
                            // ------------------------------------------

                            .issueTime(new Date())
                            .jwtID(UUID.randomUUID().toString());

            // Set expiration.
            Date exp = new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS);
            claimsBuilder.expirationTime(exp);

            // Add presentation definition JSON object.
            JsonObject storedPdJson = JsonParser.parseString(
                    vpRequest.getPresentationDefinition()).getAsJsonObject();
            @SuppressWarnings("unchecked")
            Map<String, Object> pdMap = new Gson()
                    .fromJson(storedPdJson, Map.class);
            claimsBuilder.claim(Constraints.CLAIM_PRESENTATION_DEFINITION, pdMap);

            // Add client_metadata.
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put(Constraints.METADATA_CLIENT_NAME, did);

            Map<String, Object> vpFormats = new HashMap<>();
            Map<String, Object> vcSdJwt = new HashMap<>();

            // --- LISSI & EUDI WALLET COMPATIBILITY ---
            // European wallets heavily rely on Elliptic Curve (ES256) alongside EdDSA.
            // We must declare support for both algorithms for SD-JWT presentations.
            vcSdJwt.put(Constraints.METADATA_SD_JWT_ALG_VALUES,
                    Arrays.asList(Constraints.ALG_RS256, Constraints.ALG_EDDSA, "ES256"));
            vcSdJwt.put(Constraints.METADATA_KB_JWT_ALG_VALUES,
                    Arrays.asList(Constraints.ALG_RS256, Constraints.ALG_EDDSA, "ES256"));
            // ------------------------------------------

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
}
