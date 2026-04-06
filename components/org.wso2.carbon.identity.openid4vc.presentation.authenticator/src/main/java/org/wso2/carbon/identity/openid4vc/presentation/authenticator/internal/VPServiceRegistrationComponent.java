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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.OpenID4VPAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * OSGi component for OpenID4VP service registration.
 *
 * <p>This component:
 * 1. Creates and registers service implementations as OSGi services.
 * 2. Registers the OpenID4VP authenticator with the authentication framework.
 * 3. Initializes the VPServiceDataHolder with required services.</p>
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.service.component", immediate = true)
public class VPServiceRegistrationComponent {

    /**
     * Logger for VPServiceRegistrationComponent.
     */
    private static final Logger LOG = LoggerFactory.getLogger(VPServiceRegistrationComponent.class);

    /**
     * Flag to indicate if the authenticator is already registered.
     */
    private boolean authenticatorRegistered = false;

    /**
     * Activate the OSGi component.
     *
     * @param context The component context.
     */
    @Activate
    protected void activate(ComponentContext context) {

        try {
            // Only register once to avoid duplicates.
            if (authenticatorRegistered) {
                return;
            }

            BundleContext bundleContext = context.getBundleContext();

            // Initialize services using default constructors (which create their own DAOs).
            VPRequestServiceImpl vpRequestService = new VPRequestServiceImpl();

            // Register services with OSGi.
            bundleContext.registerService(VPRequestServiceImpl.class.getName(),
                    vpRequestService, new Hashtable<>());

            // Set services in data holder.
            VPServiceDataHolder.setVPRequestService(vpRequestService);

            // Register OpenID4VP Authenticator.
            OpenID4VPAuthenticator authenticator = new OpenID4VPAuthenticator();
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, new Hashtable<>());

            authenticatorRegistered = true;
        } catch (Throwable e) {
            LOG.error("Error while activating OpenID4VP service registration component.", e);
        }
    }

    /**
     * Deactivate the OSGi component.
     *
     * @param context The component context.
     */
    protected void deactivate(ComponentContext context) {

        // Services are automatically unregistered by OSGi.
        VPServiceDataHolder.setVPRequestService(null);
        authenticatorRegistered = false;
    }

    /**
     * Set the PresentationDefinitionService.
     *
     * @param service The PresentationDefinitionService instance.
     */
    @Reference(name = "presentation.management.service", service = PresentationDefinitionService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionService")
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {

        VPServiceDataHolder.setPresentationDefinitionService(service);
    }

    /**
     * Unset the PresentationDefinitionService.
     *
     * @param service The PresentationDefinitionService instance.
     */
    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {

        VPServiceDataHolder.setPresentationDefinitionService(null);
    }

    /**
     * Set the VerificationService.
     *
     * @param service The VerificationService instance.
     */
    @Reference(name = "openid4vc.presentation.verification.service", service = VerificationService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetVerificationService")
    protected void setVerificationService(VerificationService service) {

        VPServiceDataHolder.setVerificationService(service);
    }

    /**
     * Unset the VerificationService.
     *
     * @param service The VerificationService instance.
     */
    protected void unsetVerificationService(VerificationService service) {

        VPServiceDataHolder.setVerificationService(null);
    }

    /**
     * Set the RealmService.
     *
     * @param realmService The RealmService instance.
     */
    @Reference(name = "user.realm.service", service = RealmService.class, cardinality =
            ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        VPServiceDataHolder.setRealmService(realmService);
    }

    /**
     * Unset the RealmService.
     *
     * @param realmService The RealmService instance.
     */
    protected void unsetRealmService(RealmService realmService) {

        VPServiceDataHolder.setRealmService(null);
    }

    /**
     * Set the ApplicationManagementService.
     *
     * @param applicationManagementService The ApplicationManagementService instance.
     */
    @Reference(name = "org.wso2.carbon.identity.application.mgt.ApplicationManagementService", service =
            org.wso2.carbon.identity.application.mgt.ApplicationManagementService.class, cardinality =
            ReferenceCardinality.MANDATORY, policy =
            ReferencePolicy.DYNAMIC, unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        VPServiceDataHolder.setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unset the ApplicationManagementService.
     *
     * @param applicationManagementService The ApplicationManagementService instance.
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        VPServiceDataHolder.setApplicationManagementService(null);
    }
}
