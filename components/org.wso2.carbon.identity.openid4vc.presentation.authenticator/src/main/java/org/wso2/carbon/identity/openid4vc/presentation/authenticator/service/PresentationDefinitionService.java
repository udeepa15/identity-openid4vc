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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import com.google.gson.annotations.SerializedName;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;

import java.util.ArrayList;
import java.util.List;

/**
 * Service interface for managing Presentation Definitions.
 * Presentation Definitions specify what credentials are required for a verifier's use case.
 */
public interface PresentationDefinitionService {

    /**
     * Create a new presentation definition.
     *
     * @param presentationDefinition The presentation definition to create
     * @param tenantId               The tenant ID
     * @return The created presentation definition
     * @throws VPException If an error occurs during creation
     */
    PresentationDefinition createPresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId) throws VPException;

    /**
     * Get a presentation definition by its ID.
     *
     * @param definitionId The unique definition identifier
     * @param tenantId     The tenant ID
     * @return The presentation definition
     * @throws PresentationDefinitionNotFoundException If the definition is not found
     * @throws VPException                             If an error occurs
     */
    PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId) 
            throws PresentationDefinitionNotFoundException, VPException;

    /**
     * Get a presentation definition by its Resource ID.
     *
     * @param resourceId The resource identifier (e.g., Connection ID)
     * @param tenantId   The tenant ID
     * @return The presentation definition, or null if not found
     * @throws VPException If an error occurs
     */
    PresentationDefinition getPresentationDefinitionByResourceId(String resourceId, int tenantId) throws VPException;

    /**
     * Get all presentation definitions for a tenant.
     *
     * @param tenantId The tenant ID
     * @return List of all presentation definitions
     * @throws VPException If an error occurs
     */
    List<PresentationDefinition> getAllPresentationDefinitions(int tenantId) throws VPException;

    /**
     * Update an existing presentation definition.
     *
     * @param presentationDefinition The updated presentation definition
     * @param tenantId               The tenant ID
     * @return The updated presentation definition
     * @throws PresentationDefinitionNotFoundException If the definition is not found
     * @throws VPException                             If an error occurs
     */
    PresentationDefinition updatePresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId) 
            throws PresentationDefinitionNotFoundException, VPException;

    /**
     * Delete a presentation definition.
     *
     * @param definitionId The definition identifier
     * @param tenantId     The tenant ID
     * @throws PresentationDefinitionNotFoundException If the definition is not found
     * @throws VPException                             If an error occurs
     */
    void deletePresentationDefinition(String definitionId, int tenantId) 
            throws PresentationDefinitionNotFoundException, VPException;

    /**
     * Check if a presentation definition exists.
     *
     * @param definitionId The definition identifier
     * @param tenantId     The tenant ID
     * @return true if the definition exists
     * @throws VPException If an error occurs
     */
    boolean presentationDefinitionExists(String definitionId, int tenantId) throws VPException;

    /**
     * Validate a presentation definition JSON structure.
     *
     * @param definitionJson The JSON string to validate
     * @return true if the JSON is a valid presentation definition
     * @throws VPException If an error occurs during validation
     */
    boolean validatePresentationDefinition(String definitionJson) throws VPException;

    /**
     * Build a presentation definition JSON from given parameters.
     *
     * @param id          The definition ID
     * @param name        The definition name
     * @param purpose     The purpose description
     * @param inputDescriptors Array of input descriptor JSON objects
     * @return The complete presentation definition JSON
     * @throws VPException If an error occurs during building
     */
    String buildPresentationDefinitionJson(String id, String name, String purpose, 
            String[] inputDescriptors) throws VPException;
    /**
     * Get Presentation Definition by name.
     *
     * @param name     Name of the presentation definition.
     * @param tenantId Tenant ID.
     * @return PresentationDefinition if found, null otherwise.
     * @throws VPException If an error occurs.
     */
    PresentationDefinition getPresentationDefinitionByName(String name, int tenantId) throws VPException;
    /**
     * Get claims from a presentation definition.
     *
     * @param definitionId The definition identifier
     * @param tenantId     The tenant ID
     * @return List of input descriptor claims
     * @throws PresentationDefinitionNotFoundException If the definition is not found
     * @throws VPException                             If an error occurs
     */
    List<InputDescriptorClaimsDTO> getClaimsFromPresentationDefinition(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException;

    /**
     * DTO for Input Descriptor Claims.
     */
    class InputDescriptorClaimsDTO {
        @SerializedName("input_descriptor_id")
        private String inputDescriptorId;
        private List<ClaimDTO> claims;

        public String getInputDescriptorId() {
            return inputDescriptorId;
        }

        public void setInputDescriptorId(String inputDescriptorId) {
            this.inputDescriptorId = inputDescriptorId;
        }

        public List<ClaimDTO> getClaims() {
            return claims != null ? new ArrayList<>(claims) : null;
        }

        public void setClaims(List<ClaimDTO> claims) {
            this.claims = claims != null ? new ArrayList<>(claims) : null;
        }
    }

    /**
     * DTO for Claim.
     */
    class ClaimDTO {
        private String name;
        private String path;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }
}
