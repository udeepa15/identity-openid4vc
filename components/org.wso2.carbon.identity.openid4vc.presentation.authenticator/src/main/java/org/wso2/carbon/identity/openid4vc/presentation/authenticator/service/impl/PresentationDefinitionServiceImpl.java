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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.impl.PresentationDefinitionDAOImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService.ClaimDTO;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService.InputDescriptorClaimsDTO;

import java.util.List;

/**
 * Authenticator-scoped PresentationDefinitionService implementation.
 * Delegates to the canonical service logic in the presentation.management bundle.
 */
public class PresentationDefinitionServiceImpl implements PresentationDefinitionService {

    private final PresentationDefinitionDAO presentationDefinitionDAO;

    /**
     * Default constructor.
     */
    public PresentationDefinitionServiceImpl() {
        this.presentationDefinitionDAO = new PresentationDefinitionDAOImpl();
    }

    /**
     * Constructor for dependency injection.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public PresentationDefinitionServiceImpl(PresentationDefinitionDAO presentationDefinitionDAO) {
        this.presentationDefinitionDAO = presentationDefinitionDAO;
    }

    @Override
    public PresentationDefinition createPresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId) throws VPException {

        if (presentationDefinition == null) {
            throw new VPException("Presentation definition cannot be null");
        }
        if (StringUtils.isBlank(presentationDefinition.getName())) {
            throw new VPException("Presentation definition name is required");
        }
        if (presentationDefinition.getRequestedCredentials() == null ||
                presentationDefinition.getRequestedCredentials().isEmpty()) {
            throw new VPException("At least one requested credential is required");
        }

        String definitionId = presentationDefinition.getDefinitionId();
        if (StringUtils.isBlank(definitionId)) {
            definitionId = OpenID4VPUtil.generateRequestId();
        }

        if (presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId)) {
            throw new VPException("Presentation definition with ID already exists: " + definitionId);
        }

        PresentationDefinition toCreate = new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .name(presentationDefinition.getName())
                .description(presentationDefinition.getDescription())
                .requestedCredentials(presentationDefinition.getRequestedCredentials())
                .tenantId(tenantId)
                .build();

        presentationDefinitionDAO.createPresentationDefinition(toCreate);
        return toCreate;
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        if (StringUtils.isBlank(definitionId)) {
            throw new VPException("Definition ID is required");
        }

        PresentationDefinition definition =
                presentationDefinitionDAO.getPresentationDefinitionById(definitionId, tenantId);

        if (definition == null) {
            throw new PresentationDefinitionNotFoundException(definitionId);
        }
        return definition;
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws VPException {
        return presentationDefinitionDAO.getAllPresentationDefinitions(tenantId);
    }

    @Override
    public PresentationDefinition updatePresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        String definitionId = presentationDefinition.getDefinitionId();
        PresentationDefinition existing = getPresentationDefinitionById(definitionId, tenantId);

        PresentationDefinition toUpdate = new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .name(StringUtils.isNotBlank(presentationDefinition.getName())
                        ? presentationDefinition.getName() : existing.getName())
                .description(presentationDefinition.getDescription() != null
                        ? presentationDefinition.getDescription() : existing.getDescription())
                .requestedCredentials(presentationDefinition.getRequestedCredentials() != null
                        ? presentationDefinition.getRequestedCredentials()
                        : existing.getRequestedCredentials())
                .tenantId(tenantId)
                .build();

        presentationDefinitionDAO.updatePresentationDefinition(toUpdate);
        return toUpdate;
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {
        getPresentationDefinitionById(definitionId, tenantId);
        presentationDefinitionDAO.deletePresentationDefinition(definitionId, tenantId);
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws VPException {
        return presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId);
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByName(String name, int tenantId)
            throws VPException {
        if (StringUtils.isBlank(name)) {
            throw new VPException("Presentation definition name is required");
        }
        return presentationDefinitionDAO.getPresentationDefinitionByName(name, tenantId);
    }

    @Override
    public List<InputDescriptorClaimsDTO> getClaimsFromPresentationDefinition(
            String definitionId, int tenantId)
            throws PresentationDefinitionNotFoundException, VPException {

        PresentationDefinition definition = getPresentationDefinitionById(definitionId, tenantId);
        java.util.List<InputDescriptorClaimsDTO> result = new java.util.ArrayList<>();

        List<PresentationDefinition.RequestedCredential> credentials =
                definition.getRequestedCredentials();
        if (credentials == null) {
            return result;
        }

        for (PresentationDefinition.RequestedCredential cred : credentials) {
            InputDescriptorClaimsDTO dto = new InputDescriptorClaimsDTO();
            dto.setInputDescriptorId(cred.getType() != null ? cred.getType() : "unknown");

            java.util.List<ClaimDTO> claimDTOs = new java.util.ArrayList<>();
            if (cred.getClaims() != null) {
                for (String claimName : cred.getClaims()) {
                    ClaimDTO claim = new ClaimDTO();
                    claim.setName(claimName);
                    claim.setPath("$." + claimName);
                    claimDTOs.add(claim);
                }
            }
            dto.setClaims(claimDTOs);
            result.add(dto);
        }
        return result;
    }
}
