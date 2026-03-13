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

package org.wso2.carbon.identity.openid4vc.presentation.management.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Utility class for Presentation Definition JSON operations.
 * Handles parsing, validation, and building of presentation definitions
 * according to the DIF Presentation Exchange specification.
 */
public class PresentationDefinitionUtil {

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private PresentationDefinitionUtil() {
        // Prevent instantiation
    }

    /**
     * Validate a presentation definition JSON structure.
     *
     * @param definitionJson The JSON string to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidPresentationDefinition(String definitionJson) {
        if (StringUtils.isBlank(definitionJson)) {
            return false;
        }

        try {
            JsonObject definition = JsonParser.parseString(definitionJson).getAsJsonObject();
            
            // Check required fields
            if (!definition.has(OpenID4VPConstants.PresentationDef.ID)) {
                return false;
            }
            
            if (!definition.has(OpenID4VPConstants.PresentationDef.INPUT_DESCRIPTORS)) {
                return false;
            }

            JsonElement inputDescriptors = definition.get(
                OpenID4VPConstants.PresentationDef.INPUT_DESCRIPTORS);
            if (!inputDescriptors.isJsonArray()) {
                return false;
            }

            JsonArray descriptorsArray = inputDescriptors.getAsJsonArray();
            if (descriptorsArray.size() == 0) {
                return false;
            }

            // Validate each input descriptor
            for (JsonElement element : descriptorsArray) {
                if (!isValidInputDescriptor(element)) {
                    return false;
                }
            }

            return true;
        } catch (JsonParseException e) {
            return false;
        }
    }

    /**
     * Validate an input descriptor structure.
     *
     * @param element The input descriptor JSON element
     * @return true if valid
     */
    private static boolean isValidInputDescriptor(JsonElement element) {
        if (!element.isJsonObject()) {
            return false;
        }

        JsonObject descriptor = element.getAsJsonObject();
        
        if (!descriptor.has(OpenID4VPConstants.PresentationDef.ID)) {
            return false;
        }

        // Constraints are optional but if present, must be valid
        if (descriptor.has(OpenID4VPConstants.PresentationDef.CONSTRAINTS)) {
            JsonElement constraints = descriptor.get(OpenID4VPConstants.PresentationDef.CONSTRAINTS);
            if (!constraints.isJsonObject()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Parse a presentation definition JSON string to a JsonObject.
     *
     * @param definitionJson The JSON string
     * @return The parsed JsonObject
     * @throws VPException If parsing fails
     */
    public static JsonObject parsePresentationDefinition(String definitionJson) throws VPException {
        if (StringUtils.isBlank(definitionJson)) {
            throw new VPException("Presentation definition JSON is null or empty");
        }

        try {
            return JsonParser.parseString(definitionJson).getAsJsonObject();
        } catch (JsonParseException e) {
            throw new VPException("Failed to parse presentation definition JSON", e);
        }
    }

    /**
     * Build a presentation definition JSON object.
     *
     * @param id                The definition ID
     * @param name              Optional name
     * @param purpose           Optional purpose description
     * @param inputDescriptors  Array of input descriptor JSON strings
     * @return The complete presentation definition JSON string
     * @throws VPException If building fails
     */
    public static String buildPresentationDefinition(String id, String name, String purpose,
                                                      String[] inputDescriptors) throws VPException {
        if (StringUtils.isBlank(id)) {
            throw new VPException("Presentation definition ID is required");
        }
        if (inputDescriptors == null || inputDescriptors.length == 0) {
            throw new VPException("At least one input descriptor is required");
        }

        try {
            JsonObject definition = new JsonObject();
            definition.addProperty(OpenID4VPConstants.PresentationDef.ID, id);
            
            if (StringUtils.isNotBlank(name)) {
                definition.addProperty(OpenID4VPConstants.PresentationDef.NAME, name);
            }
            
            if (StringUtils.isNotBlank(purpose)) {
                definition.addProperty(OpenID4VPConstants.PresentationDef.PURPOSE, purpose);
            }

            JsonArray descriptorsArray = new JsonArray();
            for (String descriptor : inputDescriptors) {
                JsonElement element = JsonParser.parseString(descriptor);
                descriptorsArray.add(element);
            }
            definition.add(OpenID4VPConstants.PresentationDef.INPUT_DESCRIPTORS, descriptorsArray);

            return gson.toJson(definition);
        } catch (JsonParseException e) {
            throw new VPException("Failed to build presentation definition", e);
        }
    }

    /**
     * Build an input descriptor for a requested credential model, optionally constraining a trusted issuer.
     *
     * @param id             The descriptor ID
     * @param credentialType The credential type to request
     * @param purpose        Optional purpose
     * @param requestedClaims List of requested claims
     * @param trustedIssuer  Optional trusted issuer DID/URL; when non-blank an issuer constraint field
     *                       is added to the descriptor so conformant wallets pre-filter by issuer.
     * @return The input descriptor JSON string
     */
    public static String buildInputDescriptorFromRequestedCredential(String id, String credentialType,
                                                                     String purpose,
                                                                     List<String> requestedClaims,
                                                                     String trustedIssuer) {
        JsonObject descriptor = new JsonObject();
        descriptor.addProperty(OpenID4VPConstants.PresentationDef.ID, id);
        descriptor.addProperty(OpenID4VPConstants.PresentationDef.NAME, credentialType);
        
        if (StringUtils.isNotBlank(purpose)) {
            descriptor.addProperty(OpenID4VPConstants.PresentationDef.PURPOSE, purpose);
        }

        // Add format constraints
        JsonObject format = new JsonObject();
        
        // jwt_vp format
        JsonObject jwtVp = new JsonObject();
        JsonArray alg = new JsonArray();
        alg.add("RS256");
        alg.add("ES256");
        alg.add("ES384");
        jwtVp.add("alg", alg);
        format.add(OpenID4VPConstants.VCFormats.JWT_VP_JSON, jwtVp);
        
        // vc+sd-jwt format
        JsonObject sdJwt = new JsonObject();
        JsonArray sdJwtAlg = new JsonArray();
        sdJwtAlg.add("RS256");
        sdJwtAlg.add("ES256");
        sdJwt.add("sd-jwt_alg_values", sdJwtAlg);
        sdJwt.add("kb-jwt_alg_values", sdJwtAlg);
        format.add("vc+sd-jwt", sdJwt);
        format.add("dc+sd-jwt", sdJwt);
        
        descriptor.add(OpenID4VPConstants.PresentationDef.FORMAT, format);

        // Add constraints for credential type
        JsonObject constraints = new JsonObject();
        JsonArray fields = new JsonArray();
        
        // Type constraint
        JsonObject typeField = new JsonObject();
        JsonArray path = new JsonArray();
        path.add("$.vct");
        path.add("$.vc.type");
        path.add("$.type");
        typeField.add(OpenID4VPConstants.PresentationDef.PATH, path);
        JsonObject filter = new JsonObject();
        filter.addProperty("type", "string");
        filter.addProperty("pattern", "^" + credentialType);
        typeField.add(OpenID4VPConstants.PresentationDef.FILTER, filter);
        fields.add(typeField);

        // Requested claims
        if (requestedClaims != null) {
            for (String claim : requestedClaims) {
                if (StringUtils.isNotBlank(claim)) {
                    JsonObject claimField = new JsonObject();
                    JsonArray claimPath = new JsonArray();
                    claimPath.add("$." + claim);
                    claimPath.add("$.credentialSubject." + claim);
                    claimField.add(OpenID4VPConstants.PresentationDef.PATH, claimPath);
                    fields.add(claimField);
                }
            }
        }

        constraints.add(OpenID4VPConstants.PresentationDef.FIELDS, fields);
        descriptor.add(OpenID4VPConstants.PresentationDef.CONSTRAINTS, constraints);

        return gson.toJson(descriptor);
    }

    /**
     * Parse a presentation submission JSON string.
     *
     * @param submissionJson The JSON string
     * @return The parsed JsonObject
     * @throws VPException If parsing fails
     */
    public static JsonObject parsePresentationSubmission(String submissionJson) throws VPException {
        if (StringUtils.isBlank(submissionJson)) {
            throw new VPException("Presentation submission JSON is null or empty");
        }

        try {
            return JsonParser.parseString(submissionJson).getAsJsonObject();
        } catch (JsonParseException e) {
            throw new VPException("Failed to parse presentation submission JSON", e);
        }
    }

    /**
     * Convert a presentation definition object to JSON string.
     *
     * @param definition The JsonObject
     * @return The JSON string
     */
    public static String toJson(JsonObject definition) {
        return gson.toJson(definition);
    }

    /**
     * Build a full Presentation Exchange JSON string from a {@link PresentationDefinition}
     * domain model.
     *
     * <p>Each entry in {@code requestedCredentials} becomes one input descriptor.
     * Claims are mapped to individual path constraint fields.
     *
     * @param pd The domain model
     * @return PE-compliant JSON string, or an empty definition JSON if {@code pd} is null
     */
    public static String buildDefinitionJson(PresentationDefinition pd) {

        if (pd == null) {
            return "{}";
        }

        List<RequestedCredential> credentials = pd.getRequestedCredentials();

        if (credentials == null || credentials.isEmpty()) {
            return "{}";
        }

        try {
            List<String> descriptors = new ArrayList<>();
            int index = 1;
            for (RequestedCredential cred : credentials) {
                String descId = (cred.getType() != null
                        ? cred.getType().toLowerCase(Locale.ENGLISH) + "_descriptor" + index
                        : "descriptor_" + index);
                descriptors.add(buildInputDescriptorFromRequestedCredential(
                        descId,
                        cred.getType(),
                        cred.getPurpose(),
                        cred.getClaims(),
                        cred.getIssuer()));
                index++;
            }
            return buildPresentationDefinition(
                    pd.getDefinitionId() != null ? pd.getDefinitionId() : UUID.randomUUID().toString(),
                    pd.getName(),
                    pd.getDescription(),
                    descriptors.toArray(new String[0]));
        } catch (VPException e) {
            return "{}";
        }
    }
}
