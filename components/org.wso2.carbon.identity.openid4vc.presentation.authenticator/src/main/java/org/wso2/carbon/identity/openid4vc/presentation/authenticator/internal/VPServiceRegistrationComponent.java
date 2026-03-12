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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.listener.OpenID4VPIdentityProviderMgtListener;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * OSGi component for OpenID4VP service registration.
 * 
 * This component:
 * 1. Creates and registers service implementations as OSGi services
 * 2. Registers the OpenID4VP authenticator with the authentication framework
 * 3. Initializes the VPServiceDataHolder with required services
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.service.component", immediate = true)
public class VPServiceRegistrationComponent {

    private static final Logger LOG = LoggerFactory.getLogger(VPServiceRegistrationComponent.class);

    private static volatile boolean authenticatorRegistered = false;

    @Activate
    @SuppressFBWarnings({ "ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD", "DE_MIGHT_IGNORE", "REC_CATCH_EXCEPTION" })
    protected void activate(ComponentContext context) {
        try {
            // Only register once to avoid duplicates
            if (authenticatorRegistered) {
                return;
            }

            BundleContext bundleContext = context.getBundleContext();

            // Initialize services using default constructors (which create their own DAOs)
            VPRequestService vpRequestService = new VPRequestServiceImpl();


            // Register services with OSGi
            bundleContext.registerService(VPRequestService.class.getName(),
                    vpRequestService, new Hashtable<>());


            // Set services in data holder
            VPServiceDataHolder.getInstance().setVPRequestService(vpRequestService);


            // Register OpenID4VP Authenticator
            OpenID4VPAuthenticator authenticator = new OpenID4VPAuthenticator();
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, new Hashtable<>());

            // Register Identity Provider Management Listener
            bundleContext.registerService(IdentityProviderMgtListener.class.getName(),
                    new OpenID4VPIdentityProviderMgtListener(), new Hashtable<>());

            authenticatorRegistered = true;

        } catch (Exception e) {
            LOG.error("Error while activating OpenID4VP service registration component.", e);
        }
    }

    @SuppressFBWarnings("ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")
    protected void deactivate(ComponentContext context) {
        // Services are automatically unregistered by OSGi
        VPServiceDataHolder.getInstance().setVPRequestService(null);

        authenticatorRegistered = false;

    }

    @Reference(name = "presentation.management.service", service = PresentationDefinitionService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionService")
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {
        VPServiceDataHolder.getInstance().setPresentationDefinitionService(service);
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {
        VPServiceDataHolder.getInstance().setPresentationDefinitionService(null);
    }

    @Reference(name = "user.realm.service", service = RealmService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(realmService);

    }

    protected void unsetRealmService(RealmService realmService) {
        VPServiceDataHolder.getInstance().setRealmService(null);

    }

    @Reference(name = "org.wso2.carbon.identity.application.mgt.ApplicationManagementService", service = 
    org.wso2.carbon.identity.application.mgt.ApplicationManagementService.class, cardinality = 
    ReferenceCardinality.MANDATORY, policy = 
    ReferencePolicy.DYNAMIC, unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        VPServiceDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {
        VPServiceDataHolder.getInstance().setApplicationManagementService(null);

    }
}
