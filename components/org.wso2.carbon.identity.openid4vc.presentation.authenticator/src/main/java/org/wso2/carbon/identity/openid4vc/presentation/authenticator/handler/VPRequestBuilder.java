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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.handler;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Handler for creating VP authorization requests.
 * 
 * Creates authorization request objects as:
 * 1. Plain JSON for by-value requests
 * 2. JWT (signed) for signed requests
 * 3. Request URI references for by-reference requests
 */
public class VPRequestBuilder {

    private static final Gson gson = new Gson();

    /**
     * Build authorization request as JSON object.
     * 
     * @param vpRequest              The VP request
     * @param presentationDefinition The presentation definition
     * @return JSON string of the authorization request
     */
    public String buildAuthorizationRequestJson(VPRequest vpRequest,
            PresentationDefinition presentationDefinition) {
        JsonObject request = new JsonObject();

        // Required parameters
        request.addProperty(OpenID4VPConstants.RequestParams.CLIENT_ID, vpRequest.getClientId());
        request.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);
        request.addProperty(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce());

        // Response mode
        request.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_MODE,
                vpRequest.getResponseMode());

        // Response URI (for direct_post)
        String responseUri = buildResponseUri(vpRequest);
        request.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_URI, responseUri);

        // State (request ID for correlation)
        request.addProperty(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId());

        // Presentation definition
        if (presentationDefinition != null) {
            String pdJsonStr = PresentationDefinitionUtil.buildDefinitionJson(presentationDefinition);
            if (org.apache.commons.lang.StringUtils.isNotBlank(pdJsonStr) && !"{}".equals(pdJsonStr)) {
                // Embed the presentation definition
                JsonObject pdJson = com.google.gson.JsonParser.parseString(pdJsonStr).getAsJsonObject();
                request.add(OpenID4VPConstants.Protocol.PRESENTATION_DEFINITION, pdJson);
            }
        }

        // Client metadata
        request.add("client_metadata", buildClientMetadata(vpRequest));

        return gson.toJson(request);
    }

    /**
     * Build authorization request as JWT.
     * 
     * @param vpRequest              The VP request
     * @param presentationDefinition The presentation definition
     * @return JWT string of the signed authorization request
     * @throws VPException If JWT creation fails
     */
    public String buildAuthorizationRequestJwt(VPRequest vpRequest,
            PresentationDefinition presentationDefinition)
            throws VPException {

        try {
            // Build header
            JsonObject header = new JsonObject();
            header.addProperty("alg", "RS256");
            header.addProperty("typ", "oauth-authz-req+jwt");

            // Add key ID if available
            String keyId = getSigningKeyId();
            if (StringUtils.isNotBlank(keyId)) {
                header.addProperty("kid", keyId);
            }

            // Build payload
            JsonObject payload = new JsonObject();

            // Standard JWT claims
            payload.addProperty("iss", vpRequest.getClientId());
            payload.addProperty("aud", "https://self-issued.me/v2");
            long now = System.currentTimeMillis() / 1000;
            payload.addProperty("iat", now);
            long expSeconds = (vpRequest.getExpiresAt() - System.currentTimeMillis()) / 1000;
            payload.addProperty("exp", now + expSeconds);
            payload.addProperty("jti", UUID.randomUUID().toString());

            // OAuth parameters
            payload.addProperty(OpenID4VPConstants.RequestParams.CLIENT_ID,
                    vpRequest.getClientId());
            payload.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                    OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN);
            payload.addProperty(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce());
            payload.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_MODE,
                    vpRequest.getResponseMode());

            String responseUri = buildResponseUri(vpRequest);
            payload.addProperty(OpenID4VPConstants.RequestParams.RESPONSE_URI, responseUri);
            payload.addProperty(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId());

            // Presentation definition
            if (presentationDefinition != null) {
                String pdJsonStr = PresentationDefinitionUtil.buildDefinitionJson(presentationDefinition);
                if (org.apache.commons.lang.StringUtils.isNotBlank(pdJsonStr) && !"{}".equals(pdJsonStr)) {
                    JsonObject pdJson = com.google.gson.JsonParser.parseString(pdJsonStr).getAsJsonObject();
                    payload.add(OpenID4VPConstants.Protocol.PRESENTATION_DEFINITION, pdJson);
                }
            }

            // Client metadata
            payload.add("client_metadata", buildClientMetadata(vpRequest));

            // Encode and sign
            String headerBase64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(gson.toJson(header).getBytes(StandardCharsets.UTF_8));
            String payloadBase64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(gson.toJson(payload).getBytes(StandardCharsets.UTF_8));

            String signingInput = headerBase64 + "." + payloadBase64;
            String signature = sign(signingInput);

            return signingInput + "." + signature;

        } catch (Exception e) {
            throw new VPException("Failed to build authorization request JWT", e);
        }
    }

    /**
     * Build authorization details DTO for frontend.
     * 
     * @param vpRequest              The VP request
     * @param presentationDefinition The presentation definition
     * @return AuthorizationDetailsDTO
     */
    public AuthorizationDetailsDTO buildAuthorizationDetails(VPRequest vpRequest,
            PresentationDefinition presentationDefinition) {
        AuthorizationDetailsDTO dto = new AuthorizationDetailsDTO();

        dto.setClientId(vpRequest.getClientId());
        dto.setNonce(vpRequest.getNonce());
        dto.setState(vpRequest.getRequestId());
        dto.setResponseMode(vpRequest.getResponseMode());
        dto.setResponseUri(buildResponseUri(vpRequest));

        if (presentationDefinition != null) {
            String pdJsonStr = PresentationDefinitionUtil.buildDefinitionJson(presentationDefinition);
            if (org.apache.commons.lang.StringUtils.isNotBlank(pdJsonStr) && !"{}".equals(pdJsonStr)) {
                JsonObject pdJson = com.google.gson.JsonParser.parseString(pdJsonStr).getAsJsonObject();
                dto.setPresentationDefinition(pdJson);
            }
        }

        return dto;
    }

    /**
     * Build the response URI for VP submission.
     */
    private String buildResponseUri(VPRequest vpRequest) {
        String baseUrl = IdentityUtil.getServerURL("", true, true);
        return baseUrl + OpenID4VPConstants.Endpoints.VP_RESPONSE;
    }

    /**
     * Build client metadata.
     */
    private JsonObject buildClientMetadata(VPRequest vpRequest) {
        JsonObject metadata = new JsonObject();

        // Verifier name
        String verifierName = IdentityUtil.getProperty("OpenID4VP.VerifierName");
        if (StringUtils.isNotBlank(verifierName)) {
            metadata.addProperty("client_name", verifierName);
        }

        // Logo URI
        String logoUri = IdentityUtil.getProperty("OpenID4VP.LogoUri");
        if (StringUtils.isNotBlank(logoUri)) {
            metadata.addProperty("logo_uri", logoUri);
        }

        // VP formats supported
        JsonObject vpFormats = new JsonObject();

        // JWT VP
        JsonObject jwtVp = new JsonObject();
        com.google.gson.JsonArray jwtAlgs = new com.google.gson.JsonArray();
        jwtAlgs.add("ES256");
        jwtAlgs.add("RS256");
        jwtVp.add("alg", jwtAlgs);
        vpFormats.add("jwt_vp_json", jwtVp);

        // LDP VP
        JsonObject ldpVp = new JsonObject();
        com.google.gson.JsonArray ldpProofs = new com.google.gson.JsonArray();
        ldpProofs.add("Ed25519Signature2020");
        ldpProofs.add("JsonWebSignature2020");
        ldpVp.add("proof_type", ldpProofs);
        vpFormats.add("ldp_vp", ldpVp);

        metadata.add("vp_formats", vpFormats);

        return metadata;
    }

    /**
     * Get the signing key ID.
     */
    private String getSigningKeyId() {
        return IdentityUtil.getProperty("OpenID4VP.SigningKeyId");
    }

    /**
     * Sign the input string.
     * 
     * Note: This is a placeholder implementation. In production, use proper
     * key management with HSM or secure key store.
     */
    private String sign(String signingInput) throws Exception {
        // Get signing key from configuration
        String privateKeyBase64 = IdentityUtil.getProperty("OpenID4VP.SigningKey");

        if (StringUtils.isBlank(privateKeyBase64)) {
            // Return empty signature if no key configured
            // In production, this should throw an error
            return "";
        }

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = signature.sign();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
    }
}
