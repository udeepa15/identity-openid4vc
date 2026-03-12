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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * Utility class containing common functions for Verification operations.
 */
public final class VerificationUtil {

    private static final Log LOG = LogFactory.getLog(VerificationUtil.class);
    private static final Gson GSON = new Gson();

    // Content type constants
    public static final String CONTENT_TYPE_VC_LD_JSON = "application/vc+ld+json";
    public static final String CONTENT_TYPE_JWT = "application/jwt";
    public static final String CONTENT_TYPE_VC_JWT = "application/vc+jwt";
    public static final String CONTENT_TYPE_SD_JWT = "application/vc+sd-jwt";
    public static final String CONTENT_TYPE_JSON = "application/json";

    public static final String NORMALIZED_VC_SD_JWT = "vc+sd-jwt";

    private static final String[] DATE_FORMATS = {
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
            "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
            "yyyy-MM-dd"
    };

    private VerificationUtil() {
        // Prevent instantiation
    }

    /**
     * Remove CRLF characters from a string to prevent log injection.
     *
     * @param input The input string.
     * @return The cleaned string.
     */
    public static String removeCRLF(final String input) {
        if (input == null) {
            return null;
        }
        return input.replace('\n', '_').replace('\r', '_');
    }

    /**
     * Unquotes a JSON string if it's encased in extra quotes.
     * 
     * @param jsonString The input string.
     * @return The unquoted string.
     */
    public static String unquoteJsonString(String jsonString) {
        if (jsonString == null) {
            return null;
        }
        String trimmed = jsonString.trim();
        if (trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            try {
                return GSON.fromJson(trimmed, String.class);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to unquote JSON string, using original", e);
                }
            }
        }
        return jsonString;
    }

    /**
     * Creates a SHA-256 Base64URL-encoded hash for a given string input.
     * 
     * @param input The string to hash.
     * @return Base64Url-encoded SHA-256 hash.
     * @throws NoSuchAlgorithmException
     */
    public static String createHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encodedHash);
    }
    
    /**
     * Creates a raw byte array hash using the specified algorithm.
     * 
     * @param document The document content to hash.
     * @param algorithm The hash algorithm (e.g., "SHA-256").
     * @return The hash as a byte array.
     * @throws NoSuchAlgorithmException
     */
    public static byte[] hashDocument(String document, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(document.getBytes(StandardCharsets.UTF_8));
    }

    public static String normalizeContentType(String contentType) {
        if (contentType == null) {
            return null;
        }
        int semicolonIndex = contentType.indexOf(';');
        if (semicolonIndex > 0) {
            contentType = contentType.substring(0, semicolonIndex);
        }
        return contentType.trim().toLowerCase(java.util.Locale.ENGLISH);
    }

    public static Date parseDate(String dateString) {
        if (dateString == null || dateString.isEmpty()) {
            return null;
        }
        for (String format : DATE_FORMATS) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(format);
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return sdf.parse(dateString);
            } catch (ParseException e) {
                // Try next format
            }
        }
        return null;
    }

    public static Object parseJsonElement(JsonElement element) {
        if (element.isJsonPrimitive()) {
            if (element.getAsJsonPrimitive().isNumber()) {
                return element.getAsNumber();
            } else if (element.getAsJsonPrimitive().isBoolean()) {
                return element.getAsBoolean();
            } else {
                return element.getAsString();
            }
        } else if (element.isJsonArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonElement el : element.getAsJsonArray()) {
                list.add(parseJsonElement(el));
            }
            return list;
        } else if (element.isJsonObject()) {
            Map<String, Object> map = new HashMap<>();
            for (String key : element.getAsJsonObject().keySet()) {
                map.put(key, parseJsonElement(element.getAsJsonObject().get(key)));
            }
            return map;
        }
        return null;
    }

    public static Map<String, Object> parseJwtPart(String part) {
        String decoded = Base64URL.from(part).decodeToString();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = GSON.fromJson(decoded, Map.class);
        return map;
    }

    public static String detectFormat(String vcString) {
        vcString = vcString.trim();
        // Check SD-JWT first: '~' never appears in base64url, so its presence
        // unambiguously identifies an SD-JWT regardless of the number of dots.
        // This must run BEFORE the 3-dot JWT check because an SD-JWT with no
        // disclosures and no KB-JWT (e.g. "header.payload.sig~") has exactly
        // 3 dot-separated parts and would otherwise be misidentified as a JWT.
        if (vcString.contains("~")) {
            return CONTENT_TYPE_SD_JWT;
        }
        if (vcString.split("\\.").length == 3 && !vcString.startsWith("{")) {
            return CONTENT_TYPE_JWT;
        }
        if (vcString.startsWith("{")) {
            return CONTENT_TYPE_VC_LD_JSON;
        }
        return CONTENT_TYPE_VC_LD_JSON;
    }

    /**
     * Extract the VC format from the presentation_submission JSON by reading descriptor_map[0].format.
     */
    public static String extractFormatFromSubmission(String submissionJson) throws CredentialVerificationException {
        try {
            JsonObject submission = JsonParser.parseString(submissionJson).getAsJsonObject();
            JsonArray descriptorMap = submission.getAsJsonArray("descriptor_map");
            if (descriptorMap == null || descriptorMap.size() == 0) {
                throw new CredentialVerificationException(
                        "descriptor_map is missing or empty in presentation_submission.");
            }
            JsonObject firstDescriptor = descriptorMap.get(0).getAsJsonObject();
            if (!firstDescriptor.has("format") || firstDescriptor.get("format").isJsonNull()) {
                throw new CredentialVerificationException("format field is missing in descriptor_map entry.");
            }
            String format = firstDescriptor.get("format").getAsString().trim().toLowerCase(java.util.Locale.ENGLISH);

            if ("vc sd-jwt".equals(format) || "vc_sd_jwt".equals(format) || "vc_sd-jwt".equals(format)) {
                format = NORMALIZED_VC_SD_JWT;
            }
            return format;
        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse presentation_submission JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Extract nonce and audience from VP token.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public static String[] extractNonceAndAudienceFromVpToken(String vpToken, String detectedFormat) {
        try {
            if (NORMALIZED_VC_SD_JWT.equals(detectedFormat)) {
                String[] parts = vpToken.split("~");
                if (parts.length > 1) {
                    String lastPart = parts[parts.length - 1].trim();
                    if (!lastPart.isEmpty() && lastPart.split("\\.").length == 3) {
                        try {
                            SignedJWT kbJwt = SignedJWT.parse(lastPart);
                            String nonce = (String) kbJwt.getJWTClaimsSet().getClaim("nonce");
                            Object audObj = kbJwt.getJWTClaimsSet().getClaim("aud");
                            String aud = audObj instanceof String ? (String) audObj
                                    : (audObj instanceof java.util.List
                                    ? ((java.util.List<?>) audObj).get(0).toString() : null);
                            return new String[]{nonce, aud};
                        } catch (Exception e) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Could not parse KB-JWT to extract nonce/aud.", e);
                            }
                        }
                    }
                }
            } else if ("jwt_vp".equals(detectedFormat) || "jwt_vp_json".equals(detectedFormat)) {
                String[] parts = vpToken.split("\\.");
                if (parts.length >= 2) {
                    Map<String, Object> payload = parseJwtPart(parts[1]);
                    String nonce = payload.containsKey("nonce") ? payload.get("nonce").toString() : null;
                    Object audObj = payload.get("aud");
                    String aud = audObj instanceof String ? (String) audObj
                            : (audObj instanceof java.util.List
                            ? ((java.util.List<?>) audObj).get(0).toString() : null);
                    return new String[]{nonce, aud};
                }
            } else {
                String token = vpToken.trim();
                if (token.startsWith("{")) {
                    JsonObject vpJson = JsonParser.parseString(token).getAsJsonObject();
                    if (vpJson.has("proof")) {
                        JsonObject proof = vpJson.getAsJsonObject("proof");
                        String nonce = proof.has("challenge") ? proof.get("challenge").getAsString() : null;
                        String aud = proof.has("domain") ? proof.get("domain").getAsString() : null;
                        return new String[]{nonce, aud};
                    }
                }
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not extract nonce/audience from VP token.", e);
            }
        }
        return new String[]{null, null};
    }

    /**
     * Extract credentialSubject claims from a JWT-VP or JSON-LD VP token into a flat Map.
     */
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public static Map<String, Object> extractClaimsFromVpToken(String vpToken, String detectedFormat) {
        Map<String, Object> claims = new HashMap<>();
        try {
            JsonObject vpData = null;
            if (CONTENT_TYPE_VC_LD_JSON.equals(detectedFormat) || "ldp_vp".equals(detectedFormat) ||
                    vpToken.trim().startsWith("{")) {
                vpData = JsonParser.parseString(vpToken).getAsJsonObject();
            } else {
                String[] parts = vpToken.split("\\.");
                if (parts.length >= 2) {
                    String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                    vpData = JsonParser.parseString(payload).getAsJsonObject();
                }
            }
            if (vpData != null) {
                flattenVpCredentialSubject(vpData, claims);
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not extract claims from VP token: " + e.getMessage());
            }
        }
        return claims;
    }

    public static void flattenVpCredentialSubject(JsonObject vpData, Map<String, Object> target) {
        JsonObject vp = vpData.has("vp") ? vpData.getAsJsonObject("vp") : vpData;
        if (!vp.has("verifiableCredential")) {
            return;
        }
        JsonElement vcElem = vp.get("verifiableCredential");
        JsonObject vc = null;
        if (vcElem.isJsonArray() && vcElem.getAsJsonArray().size() > 0) {
            JsonElement first = vcElem.getAsJsonArray().get(0);
            if (first.isJsonObject()) {
                vc = first.getAsJsonObject();
            }
        } else if (vcElem.isJsonObject()) {
            vc = vcElem.getAsJsonObject();
        }
        if (vc != null && vc.has("credentialSubject")) {
            JsonObject subject = vc.getAsJsonObject("credentialSubject");
            for (Map.Entry<String, JsonElement> entry : subject.entrySet()) {
                if (entry.getValue().isJsonPrimitive()) {
                    target.put(entry.getKey(), entry.getValue().getAsString());
                } else {
                    target.put(entry.getKey(), parseJsonElement(entry.getValue()));
                }
            }
        }
    }

    public static String extractHost(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String trimmed = value.trim();
        if (!trimmed.contains("://")) {
            if (trimmed.startsWith("did:web:")) {
                String didIdentifier = trimmed.substring("did:web:".length());
                return didIdentifier.split(":")[0].toLowerCase(java.util.Locale.ENGLISH);
            }
            return trimmed.toLowerCase(java.util.Locale.ENGLISH);
        }
        try {
            java.net.URI uri = new java.net.URI(trimmed);
            String host = uri.getHost();
            return host != null ? host.toLowerCase(java.util.Locale.ENGLISH)
                    : trimmed.toLowerCase(java.util.Locale.ENGLISH);
        } catch (java.net.URISyntaxException e) {
            return trimmed.toLowerCase(java.util.Locale.ENGLISH);
        }
    }
}
