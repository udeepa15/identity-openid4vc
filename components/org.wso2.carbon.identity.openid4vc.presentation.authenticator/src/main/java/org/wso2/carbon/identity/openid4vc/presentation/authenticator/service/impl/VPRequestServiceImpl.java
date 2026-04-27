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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.core.util.KeyStoreManager;
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Implementation of VPRequestService for managing VP authorization requests.
 * Optimized for Inji and Lissi wallet compatibility.
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

        // Use the unsecured method for testing
        return buildUnsecuredRequestObjectJwt(vpRequest);
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

    private String buildRequestObjectJwt(final VPRequest vpRequest, final String didMethod)
            throws VPAuthenticatorException {

        try {
            DIDProvider provider = DIDProviderFactory.getProvider(didMethod);
            int tenantId = vpRequest.getTenantId();

            // Hardcoded DID details to match your hosted did.json
            String hardcodedDid = "did:web:masked-unprofitably-ardith.ngrok-free.dev";
            String hardcodedKeyId = "did:web:masked-unprofitably-ardith.ngrok-free.dev#ed25519";

            // 1. Core Claims - Strictly following OID4VP high-assurance profile
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(hardcodedDid)
                    .audience("https://self-issued.me/v2") // Added for standard wallet compatibility
                    .claim("response_type", "vp_token")
                    .claim("response_mode", "direct_post")
                    .claim("response_uri", vpRequest.getResponseUri())
                    .claim("nonce", vpRequest.getNonce())
                    .claim("state", vpRequest.getRequestId())
                    .claim("client_id_scheme", "did")
                    .claim("client_id", hardcodedDid)
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS));

            // 2. DIF Presentation Definition
            JsonObject storedPdJson = JsonParser.parseString(vpRequest.getPresentationDefinition()).getAsJsonObject();
            Map<String, Object> pdMap = new Gson().fromJson(storedPdJson, Map.class);
            claimsBuilder.claim("presentation_definition", pdMap);

            // 3. DCQL Query Structure (Critical for Lissi/Inji UI rendering)
            Map<String, Object> dcqlQuery = new HashMap<>();
            List<Map<String, Object>> credentials = new ArrayList<>();
            Map<String, Object> cred = new HashMap<>();
            cred.put("id", "credential_query_1");
            cred.put("format", "dc+sd-jwt");

            Map<String, Object> meta = new HashMap<>();
            meta.put("vct_values", Arrays.asList("NIC"));
            cred.put("meta", meta);

            List<Map<String, Object>> claimsList = new ArrayList<>();
            Map<String, Object> emailClaim = new HashMap<>();
            emailClaim.put("id", "email");
            emailClaim.put("path", Arrays.asList("email"));
            claimsList.add(emailClaim);
            cred.put("claims", claimsList);

            credentials.add(cred);
            dcqlQuery.put("credentials", credentials);
            claimsBuilder.claim("dcql_query", dcqlQuery);

            // 4. Client Metadata - Dual Format to fix Inji "empty vp_formats" error
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put("client_name", "WSO2 Verifier");

            List<String> algs = Arrays.asList("EdDSA", "ES256");
            Map<String, Object> dcSdJwt = new HashMap<>();
            dcSdJwt.put("sd-jwt_alg_values", algs);
            dcSdJwt.put("kb-jwt_alg_values", algs);

            // Legacy key for Inji
            Map<String, Object> vpFormats = new HashMap<>();
            vpFormats.put("vc+sd-jwt", dcSdJwt);
            clientMetadata.put("vp_formats", vpFormats);

            // Modern key for EUDI/Lissi Profile
            clientMetadata.put("vp_formats_supported", vpFormats);

            claimsBuilder.claim("client_metadata", clientMetadata);

            // 5. Header: Using the hardcoded Key ID from your did.json
            JWSHeader header = new JWSHeader.Builder(provider.getSigningAlgorithm())
                    .keyID(hardcodedKeyId) // Exactly matches the "id" in your verificationMethod
                    .type(new JOSEObjectType("application/oauth-authz-req+jwt"))
                    .build();

            JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toJSONObject()));

            // Sign using provider logic
            JWSSigner signer = provider.getSigner(tenantId);
            jwsObject.sign(signer);

            return jwsObject.serialize();

        } catch (Exception e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Inji-optimized JWT build failed with hardcoded DID", e);
        }
    }

    private String buildUnsecuredRequestObjectJwt(final VPRequest vpRequest)
            throws VPAuthenticatorException {

        try {
            // Hardcoded base URL for the ngrok environment to match response logic
            String ngrokBaseUrl = "https://masked-unprofitably-ardith.ngrok-free.dev";
            String responseUri = ngrokBaseUrl + "/oid4vp/v1/response";

            // Use the redirect_uri scheme which is less restrictive for 'alg: none'
            String clientId = "redirect_uri:" + responseUri;
            String issuer = ngrokBaseUrl;

            // 1. Core Claims - Aligning with the working Lissi Demo format
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .claim("response_type", "vp_token")
                    .claim("response_mode", "direct_post")
                    .claim("response_uri", responseUri)
                    .claim("nonce", vpRequest.getNonce())
                    .claim("state", vpRequest.getRequestId())
                    .claim("client_id", clientId) // Scheme is now redirect_uri:
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            claimsBuilder.expirationTime(new Date(System.currentTimeMillis() + DEFAULT_EXPIRY_MS));

            // 2. DIF Presentation Definition
            JsonObject storedPdJson = JsonParser.parseString(vpRequest.getPresentationDefinition()).getAsJsonObject();
            Map<String, Object> pdMap = new Gson().fromJson(storedPdJson, Map.class);
            claimsBuilder.claim("presentation_definition", pdMap);

            // 3. DCQL Query Structure
            Map<String, Object> dcqlQuery = new HashMap<>();
            List<Map<String, Object>> credentials = new ArrayList<>();
            Map<String, Object> cred = new HashMap<>();
            cred.put("id", "sd-jwt-pid"); // Hardcoded ID similar to demo
            cred.put("format", "dc+sd-jwt");

            Map<String, Object> meta = new HashMap<>();
            meta.put("vct_values", Arrays.asList("NIC"));
            cred.put("meta", meta);

            List<Map<String, Object>> claimsList = new ArrayList<>();
            Map<String, Object> emailClaim = new HashMap<>();
            emailClaim.put("id", "email");
            emailClaim.put("path", Arrays.asList("email")); // Changed .add to .put
            claimsList.add(emailClaim);
            cred.put("claims", claimsList);

            credentials.add(cred);
            dcqlQuery.put("credentials", credentials);
            claimsBuilder.claim("dcql_query", dcqlQuery);

            // 4. Client Metadata
            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put("client_name", "WSO2 Verifier (Test)");

            List<String> algs = Arrays.asList("ES256", "RS256");
            Map<String, Object> dcSdJwt = new HashMap<>();
            dcSdJwt.put("sd-jwt_alg_values", algs);
            dcSdJwt.put("kb-jwt_alg_values", algs);

            Map<String, Object> vpFormats = new HashMap<>();
            vpFormats.put("dc+sd-jwt", dcSdJwt);
            clientMetadata.put("vp_formats", new HashMap<>()); // Matches demo empty object
            clientMetadata.put("vp_formats_supported", vpFormats);

            claimsBuilder.claim("client_metadata", clientMetadata);

            // 5. Header setup with none alg using nimbus-jose-jwt PlainObject
            com.nimbusds.jose.PlainHeader header = new com.nimbusds.jose.PlainHeader.Builder()
                    .type(new JOSEObjectType("JWT")) // Typ usually just 'JWT' for unsecured
                    .build();

            com.nimbusds.jose.PlainObject plainObject = new com.nimbusds.jose.PlainObject(
                    header,
                    new Payload(claimsBuilder.build().toJSONObject())
            );

            // This will return: [header_base64].[payload_base64].
            return plainObject.serialize();

        } catch (Exception e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Unsecured JWT build failed", e);
        }
    }
}
