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

package org.wso2.carbon.identity.openid4vc.presentation.management.dao;

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;

import java.util.List;

/**
 * Data Access Object interface for Presentation Definition operations.
 */
public interface PresentationDefinitionDAO {

    /**
     * Create a new presentation definition.
     *
     * @param presentationDefinition Presentation definition to create
     * @throws VPException if creation fails
     */
    void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException;

    /**
     * Get presentation definition by definition ID.
     *
     * @param definitionId Definition ID
     * @param tenantId     Tenant ID
     * @return Presentation definition or null if not found
     * @throws VPException if retrieval fails
     */
    PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws VPException;

    /**
     * Get all presentation definitions for a tenant.
     *
     * @param tenantId Tenant ID
     * @return List of presentation definitions
     * @throws VPException if retrieval fails
     */
    List<PresentationDefinition> getAllPresentationDefinitions(int tenantId) throws VPException;

    /**
     * Update presentation definition.
     *
     * @param presentationDefinition Presentation definition to update
     * @throws VPException if update fails
     */
    void updatePresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException;

    /**
     * Delete presentation definition.
     *
     * @param definitionId Definition ID
     * @param tenantId     Tenant ID
     * @throws VPException if deletion fails
     */
    void deletePresentationDefinition(String definitionId, int tenantId) throws VPException;

    /**
     * Check if a presentation definition exists.
     *
     * @param definitionId Definition ID
     * @param tenantId     Tenant ID
     * @return true if exists
     * @throws VPException if check fails
     */
    boolean presentationDefinitionExists(String definitionId, int tenantId) throws VPException;

    /**
     * Get Presentation Definition by name.
     *
     * @param name     Name of the presentation definition.
     * @param tenantId Tenant ID.
     * @return PresentationDefinition if found, null otherwise.
     * @throws VPException If an error occurs.
     */
    PresentationDefinition getPresentationDefinitionByName(String name, int tenantId) throws VPException;
}
