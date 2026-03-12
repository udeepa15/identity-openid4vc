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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.listener;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;

/**
 * Identity Provider Management Listener for OpenIDoa4VP.
 * This listener manages the lifecycle of Presentation Definitions associated with Identity Providers.
 */
public class OpenID4VPIdentityProviderMgtListener extends AbstractIdentityProviderMgtListener {

    private static final Log log = LogFactory.getLog(OpenID4VPIdentityProviderMgtListener.class);
    private static final String PROP_PRESENTATION_DEFINITION = "presentationDefinition";
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
            FederatedAuthenticatorConfig[] fedAuthConfigs = identityProvider.getFederatedAuthenticatorConfigs();
            if (fedAuthConfigs == null) {
                return;
            }

            String presentationDefinitionId = null;

            // Find the presentation definition ID property
            for (FederatedAuthenticatorConfig config : fedAuthConfigs) {
                if (OPENID4VP_AUTHENTICATOR_NAME.equals(config.getName())) {
                    Property[] properties = config.getProperties();
                    if (properties != null) {
                        for (Property prop : properties) {
                            if (PROP_PRESENTATION_DEFINITION.equals(prop.getName())) {
                                presentationDefinitionId = prop.getValue();
                                break;
                            }
                        }
                    }
                    break;
                }
            }

            if (StringUtils.isNotBlank(presentationDefinitionId)) {

                String resourceId = identityProvider.getResourceId();
                if (StringUtils.isBlank(resourceId)) {
                    log.error("Resource ID not available in post-persistence for IDP: " +
                            sanitize(identityProvider.getIdentityProviderName()));
                    return;
                }

                PresentationDefinitionService pdService =
                        VPServiceDataHolder.getInstance().getPresentationDefinitionService();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

                PresentationDefinition existingPd = null;
                try {
                    existingPd = pdService.getPresentationDefinitionById(presentationDefinitionId, tenantId);
                } catch (Exception e) {
                    // Ignore, might not exist
                }

                if (existingPd != null) {
                    // The definition is linked to this IDP via the authenticator config property.
                    // No resourceId update needed — RESOURCE_ID column was removed from the schema.
                    if (log.isDebugEnabled()) {
                        log.debug("Presentation Definition " + sanitize(presentationDefinitionId) +
                                " already exists for IDP: " + sanitize(identityProvider.getIdentityProviderName()));
                    }
                } else {
                    log.warn("Presentation Definition not found for ID: " + sanitize(presentationDefinitionId) +
                            " during IDP creation: " + sanitize(identityProvider.getIdentityProviderName()));
                }
            }

        } catch (Exception e) {
            log.error("Error in post-persistence handling for IDP: " +
                    sanitize(identityProvider.getIdentityProviderName()), e);
        }
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
