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

package org.wso2.carbon.identity.openid4vc.presentation.management.listener;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Identity Provider Management Listener for OpenID4VP.
 * This listener manages the lifecycle of Presentation Definitions associated with Identity Providers.
 */
@Component(
        name = "org.wso2.carbon.identity.openid4vc.presentation.management.idp.listener",
        immediate = true,
        service = IdentityProviderMgtListener.class
)
public class OpenID4VPIdentityProviderMgtListener extends AbstractIdentityProviderMgtListener {

    private static final Log LOG = LogFactory.getLog(OpenID4VPIdentityProviderMgtListener.class);
    private static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    private static final String OPENID4VP_AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";

    private volatile PresentationDefinitionService presentationDefinitionService;

    @Reference(name = "presentation.management.service", service = PresentationDefinitionService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionService")
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {

        this.presentationDefinitionService = service;
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {

        this.presentationDefinitionService = null;
    }

    @Override
    public int getDefaultOrderId() {

        return 99;
    }

    @Override
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean doPreAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        handlePrePersistence(identityProvider, tenantDomain, "ADD");
        return true;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        try {
            handlePostPersistence(identityProvider, tenantDomain);
            return true;
        } finally {
            clearOperationContext();
        }
    }

    @Override
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean doPreUpdateIdP(String oldIdPName, IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        handlePrePersistence(identityProvider, tenantDomain, "UPDATE");
        return true;
    }

    @Override
    public boolean doPostUpdateIdP(String oldIdPName, IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        try {
            handlePostPersistence(identityProvider, tenantDomain);
            return true;
        } finally {
            clearOperationContext();
        }
    }

    @Override
    public boolean doPostDeleteIdP(String idPName, String tenantDomain) {

        return true;
    }

    @Override
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public boolean doPreDeleteIdP(String idPName, String tenantDomain) {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            PresentationDefinitionService pdService = this.presentationDefinitionService;

            if (pdService == null) {
                return true;
            }

            String pdName = idPName + " Definition";
            PresentationDefinition existingPd = pdService.getPresentationDefinitionByName(pdName, tenantId);

            if (existingPd != null) {
                pdService.deletePresentationDefinition(existingPd.getDefinitionId(), tenantId);
            }

        } catch (VPException e) {
            LOG.error("Error deleting presentation definition for IDP: " + sanitize(idPName), e);
        }
        return true;
    }

    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION"})
    private void handlePrePersistence(IdentityProvider identityProvider,
                                      String tenantDomain,
                                      String operationType)
            throws IdentityProviderManagementException {

        clearOperationContext();

        if (!isOpenID4VPConnection(identityProvider)) {
            return;
        }

        PresentationDefinitionService pdService = this.presentationDefinitionService;
        if (pdService == null) {
            throw new IdentityProviderManagementException(
                    "Presentation Definition service is unavailable for OpenID4VP connection creation.");
        }

        int tenantId;
        try {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (Exception e) {
            throw new IdentityProviderManagementException("Error resolving tenant id for tenant: "
                    + sanitize(tenantDomain), e);
        }

        String presentationDefinitionId = resolvePresentationDefinitionId(identityProvider);
        if (StringUtils.isNotBlank(presentationDefinitionId)) {
            validatePresentationDefinitionExists(pdService, presentationDefinitionId, tenantId);
            return;
        }

        throw new IdentityProviderManagementException("OpenID4VP connection requires an existing "
                + "presentationDefinitionId. Auto-creation of Presentation Definitions is disabled.");
    }

    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION", "DE_MIGHT_IGNORE"})
    private void handlePostPersistence(IdentityProvider identityProvider, String tenantDomain) {

        if (identityProvider == null) {
            return;
        }

        try {
            PresentationDefinitionService pdService = this.presentationDefinitionService;
            if (pdService == null) {
                return;
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            PresentationDefinition existingPd = resolvePresentationDefinition(identityProvider, pdService, tenantId);
            if (existingPd == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Presentation Definition not found for IDP: "
                            + sanitize(identityProvider.getIdentityProviderName()));
                }
                return;
            }

            List<String> mappedIdpClaims = extractMappedIdpClaims(identityProvider);
            if (!hasClaimChanges(existingPd, mappedIdpClaims)) {
                return;
            }

            PresentationDefinition syncedDefinition = buildSyncedDefinition(existingPd, mappedIdpClaims);
            pdService.updatePresentationDefinition(syncedDefinition, tenantId);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Synchronized " + mappedIdpClaims.size() + " claim(s) to Presentation Definition: "
                        + sanitize(existingPd.getDefinitionId()) + " for IDP: "
                        + sanitize(identityProvider.getIdentityProviderName()));
            }

        } catch (Exception e) {
            LOG.error("Error in post-persistence handling for IDP: "
                    + sanitize(identityProvider.getIdentityProviderName()), e);
        }
    }

    @SuppressFBWarnings(value = {"REC_CATCH_EXCEPTION", "CRLF_INJECTION_LOGS"},
            justification = "Exception is intentionally swallowed for fallback lookup. "
                    + "All logged values are sanitized via sanitize().")
    private PresentationDefinition resolvePresentationDefinition(IdentityProvider identityProvider,
                                                                 PresentationDefinitionService pdService,
                                                                 int tenantId) {

        String presentationDefinitionId = resolvePresentationDefinitionId(identityProvider);

        if (StringUtils.isNotBlank(presentationDefinitionId)) {
            try {
                return pdService.getPresentationDefinitionById(presentationDefinitionId, tenantId);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Presentation Definition not found by ID: " + sanitize(presentationDefinitionId));
                }
            }
        }

        try {
            String pdName = identityProvider.getIdentityProviderName() + " Definition";
            return pdService.getPresentationDefinitionByName(pdName, tenantId);
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Presentation Definition not found by name for IDP: "
                        + sanitize(identityProvider.getIdentityProviderName()));
            }
            return null;
        }
    }

    private String resolvePresentationDefinitionId(IdentityProvider identityProvider) {

        FederatedAuthenticatorConfig[] fedAuthConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        if (fedAuthConfigs == null) {
            return null;
        }

        for (FederatedAuthenticatorConfig config : fedAuthConfigs) {
            if (!OPENID4VP_AUTHENTICATOR_NAME.equals(config.getName())) {
                continue;
            }

            Property[] properties = config.getProperties();
            if (properties == null) {
                return null;
            }

            for (Property prop : properties) {
                if (PROP_PRESENTATION_DEFINITION_ID.equals(prop.getName())
                        && StringUtils.isNotBlank(prop.getValue())) {
                    return prop.getValue();
                }
            }
            return null;
        }

        return null;
    }

    private List<String> extractMappedIdpClaims(IdentityProvider identityProvider) {

        Set<String> claims = new LinkedHashSet<>();

        if (identityProvider == null
                || identityProvider.getClaimConfig() == null
                || identityProvider.getClaimConfig().getClaimMappings() == null) {
            return new ArrayList<>();
        }

        for (ClaimMapping mapping : identityProvider.getClaimConfig().getClaimMappings()) {
            if (mapping != null && mapping.getRemoteClaim() != null
                    && StringUtils.isNotBlank(mapping.getRemoteClaim().getClaimUri())) {
                claims.add(mapping.getRemoteClaim().getClaimUri().trim());
            }
        }

        return new ArrayList<>(claims);
    }

    private boolean hasClaimChanges(PresentationDefinition definition, List<String> mappedIdpClaims) {

        if (definition == null || definition.getRequestedCredentials() == null
                || definition.getRequestedCredentials().isEmpty()) {
            return false;
        }

        Set<String> targetClaims = new LinkedHashSet<>(mappedIdpClaims);

        for (PresentationDefinition.RequestedCredential credential : definition.getRequestedCredentials()) {
            List<String> existingClaims = credential != null ? credential.getClaims() : null;
            Set<String> existingClaimSet = existingClaims != null
                    ? new LinkedHashSet<>(existingClaims)
                    : new LinkedHashSet<String>();

            if (!existingClaimSet.equals(targetClaims)) {
                return true;
            }
        }

        return false;
    }

    private PresentationDefinition buildSyncedDefinition(PresentationDefinition definition,
                                                         List<String> mappedIdpClaims) {

        List<PresentationDefinition.RequestedCredential> updatedCredentials = new ArrayList<>();
        List<PresentationDefinition.RequestedCredential> existingCredentials = definition.getRequestedCredentials();

        if (existingCredentials != null) {
            for (PresentationDefinition.RequestedCredential credential : existingCredentials) {
                if (credential == null) {
                    continue;
                }

                PresentationDefinition.RequestedCredential updatedCredential =
                        new PresentationDefinition.RequestedCredential();
                updatedCredential.setType(credential.getType());
                updatedCredential.setPurpose(credential.getPurpose());
                updatedCredential.setIssuer(credential.getIssuer());
                updatedCredential.setClaims(mappedIdpClaims);
                updatedCredentials.add(updatedCredential);
            }
        }

        return new PresentationDefinition.Builder()
                .definitionId(definition.getDefinitionId())
                .name(definition.getName())
                .description(definition.getDescription())
                .tenantId(definition.getTenantId())
                .requestedCredentials(updatedCredentials)
                .build();
    }

    private String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("\r", "").replace("\n", "");
    }

    private boolean isOpenID4VPConnection(IdentityProvider identityProvider) {

        return getOpenID4VPAuthenticatorConfig(identityProvider) != null;
    }

    private FederatedAuthenticatorConfig getOpenID4VPAuthenticatorConfig(IdentityProvider identityProvider) {

        if (identityProvider == null || identityProvider.getFederatedAuthenticatorConfigs() == null) {
            return null;
        }

        for (FederatedAuthenticatorConfig config : identityProvider.getFederatedAuthenticatorConfigs()) {
            if (config != null && OPENID4VP_AUTHENTICATOR_NAME.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

    private void validatePresentationDefinitionExists(PresentationDefinitionService pdService,
                                                      String definitionId,
                                                      int tenantId)
            throws IdentityProviderManagementException {

        try {
            pdService.getPresentationDefinitionById(definitionId, tenantId);
        } catch (Exception e) {
            throw new IdentityProviderManagementException(
                    "Invalid Presentation Definition ID configured for connection: "
                            + sanitize(definitionId), e);
        }
    }

    private void clearOperationContext() {
        // No operation context is needed when PD auto-creation is disabled.
    }
}
