/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.listener;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Identity Provider Management Listener for OpenID4VP.
 * This listener manages the lifecycle of Presentation Definitions associated with Identity Providers.
 */
public class OpenID4VPIdentityProviderMgtListener extends AbstractIdentityProviderMgtListener {

    private static final Log log = LogFactory.getLog(OpenID4VPIdentityProviderMgtListener.class);
     private static final String PROP_PRESENTATION_DEFINITION = "presentationDefinition";
     private static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    private static final String OPENID4VP_AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";

    @Override
    public int getDefaultOrderId() {

        return 99;
    }

    @Override
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean doPreAddIdP(IdentityProvider identityProvider, String tenantDomain) {

        handlePrePersistence(identityProvider);
        return true;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain) {

        handlePostPersistence(identityProvider, tenantDomain);
        return true;
    }

    @Override
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean doPreUpdateIdP(String oldIdPName, IdentityProvider identityProvider, String tenantDomain) {

        handlePrePersistence(identityProvider);
        return true;
    }

    @Override
    public boolean doPostUpdateIdP(String oldIdPName, IdentityProvider identityProvider, String tenantDomain) {

        handlePostPersistence(identityProvider, tenantDomain);
        return true;
    }

    @Override
    public boolean doPostDeleteIdP(String idPName, String tenantDomain) {

        // IDP delete logic doesn't provide the Resource ID easily in all versions, 
        // but we need to clean up definitions. 
        // Ideally we should delete by Resource ID, but if we don't have it, we might be stuck.
        // However, the IDP deletion usually doesn't cascade to external tables automatically unless we enforce it.
        // For now, let's try to lookup the IDP or assume we need to handle this.
        
        // Actually, since doPostDeleteIdP only gives the name, we might not be able to get the ResourceId 
        // if the IDP is already deleted from DB. 
        // But doPreDeleteIdP gives us a chance.
        return true;
    }

    @Override
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public boolean doPreDeleteIdP(String idPName, String tenantDomain) {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            PresentationDefinitionService pdService = VPServiceDataHolder.getInstance()
                    .getPresentationDefinitionService();

            if (pdService == null) {
                return true;
            }

            // Lookup by name (resource ID linkage removed — no RESOURCE_ID column in the new schema)
            String pdName = idPName + " Definition";
            PresentationDefinition existingPd = pdService.getPresentationDefinitionByName(pdName, tenantId);

            if (existingPd != null) {
                pdService.deletePresentationDefinition(existingPd.getDefinitionId(), tenantId);
            }

        } catch (VPException e) {
            log.error("Error deleting presentation definition for IDP: " + sanitize(idPName), e);
        }
        return true;
    }

    /**
     * Handle pre-persistence logic (PreAdd and PreUpdate).
     * No longer intercepts JSON or generates UUIDs.
     */
    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION"})
    private void handlePrePersistence(IdentityProvider identityProvider) {
        // No-op for ID reference flow
    }

    /**
     * Handle post-persistence logic (PostAdd and PostUpdate).
     * Links the provided Presentation Definition ID to the Identity Provider.
     */
    @SuppressFBWarnings({"CRLF_INJECTION_LOGS", "REC_CATCH_EXCEPTION", "DE_MIGHT_IGNORE"})
    private void handlePostPersistence(IdentityProvider identityProvider, String tenantDomain) {

        if (identityProvider == null) {
            return;
        }

        try {
            PresentationDefinitionService pdService = VPServiceDataHolder.getInstance()
                    .getPresentationDefinitionService();
            if (pdService == null) {
                return;
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            PresentationDefinition existingPd = resolvePresentationDefinition(identityProvider, pdService, tenantId);
            if (existingPd == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Presentation Definition not found for IDP: "
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

            if (log.isDebugEnabled()) {
                log.debug("Synchronized " + mappedIdpClaims.size() + " claim(s) to Presentation Definition: "
                        + sanitize(existingPd.getDefinitionId()) + " for IDP: "
                        + sanitize(identityProvider.getIdentityProviderName()));
            }

        } catch (Exception e) {
            log.error("Error in post-persistence handling for IDP: " +
                    sanitize(identityProvider.getIdentityProviderName()), e);
        }
    }

    /**
     * Resolve the presentation definition associated with the given identity provider.
     *
     * @param identityProvider Identity provider
     * @param pdService        Presentation definition service
     * @param tenantId         Tenant ID
     * @return Associated presentation definition, or null if not found
     */
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
                if (log.isDebugEnabled()) {
                    log.debug("Presentation Definition not found by ID: " + sanitize(presentationDefinitionId));
                }
            }
        }

        try {
            String pdName = identityProvider.getIdentityProviderName() + " Definition";
            return pdService.getPresentationDefinitionByName(pdName, tenantId);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Presentation Definition not found by name for IDP: "
                        + sanitize(identityProvider.getIdentityProviderName()));
            }
            return null;
        }
    }

    /**
     * Resolve configured presentation definition ID from OpenID4VP authenticator properties.
     *
     * @param identityProvider Identity provider
     * @return Presentation definition ID, or null
     */
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

            String legacyPropertyValue = null;
            for (Property prop : properties) {
                if (PROP_PRESENTATION_DEFINITION_ID.equals(prop.getName())
                        && StringUtils.isNotBlank(prop.getValue())) {
                    return prop.getValue();
                }
                if (PROP_PRESENTATION_DEFINITION.equals(prop.getName())
                        && StringUtils.isNotBlank(prop.getValue())) {
                    legacyPropertyValue = prop.getValue();
                }
            }
            return legacyPropertyValue;
        }

        return null;
    }

    /**
     * Extract all non-empty IdP claim names from the claim mappings.
     *
     * @param identityProvider Identity provider
     * @return Ordered and de-duplicated claim names
     */
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

    /**
     * Check whether requested credential claim lists differ from the mapped claims.
     *
     * @param definition       Existing presentation definition
     * @param mappedIdpClaims  Mapped IdP claim names
     * @return True if claims must be updated
     */
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

    /**
     * Build a new presentation definition with synchronized claim lists.
     *
     * @param definition       Existing presentation definition
     * @param mappedIdpClaims  Mapped IdP claim names
     * @return Synchronized presentation definition
     */
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

    /**
     * Sanitize a string to prevent CRLF injection in log messages.
     *
     * @param input The string to sanitize
     * @return Sanitized string with CR/LF characters removed
     */
    private String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("\r", "").replace("\n", "");
    }
}
