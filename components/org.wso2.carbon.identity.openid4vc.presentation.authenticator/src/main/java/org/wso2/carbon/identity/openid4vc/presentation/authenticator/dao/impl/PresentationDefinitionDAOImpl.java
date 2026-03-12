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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl;

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;

import java.util.List;

/**
 * Authenticator-scoped implementation of PresentationDefinitionDAO.
 * Delegates to the canonical implementation in the presentation.management bundle,
 * which handles the 2-table schema (IDN_PRESENTATION_DEFINITION + IDN_PD_CREDENTIAL).
 */
public class PresentationDefinitionDAOImpl implements PresentationDefinitionDAO {

    private final PresentationDefinitionDAO delegate;

    /**
     * Default constructor — uses the canonical 2-table DAO impl.
     */
    public PresentationDefinitionDAOImpl() {
        this.delegate =
                new org.wso2.carbon.identity.openid4vc.presentation.management.dao.impl
                        .PresentationDefinitionDAOImpl();
    }

    @Override
    public void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {
        delegate.createPresentationDefinition(presentationDefinition);
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws VPException {
        return delegate.getPresentationDefinitionById(definitionId, tenantId);
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws VPException {
        return delegate.getAllPresentationDefinitions(tenantId);
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition)
            throws VPException {
        delegate.updatePresentationDefinition(presentationDefinition);
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId) throws VPException {
        delegate.deletePresentationDefinition(definitionId, tenantId);
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws VPException {
        return delegate.presentationDefinitionExists(definitionId, tenantId);
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByName(String name, int tenantId)
            throws VPException {
        return delegate.getPresentationDefinitionByName(name, tenantId);
    }
}
