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

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDDocumentServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Data holder for OpenID4VP services.
 * Provides access to OSGi services across the component.
 */
public final class VPServiceDataHolder {

    private static final AtomicReference<RealmService> REALM_SERVICE = new AtomicReference<>();
    private static final AtomicReference<VPRequestService> VP_REQUEST_SERVICE = new AtomicReference<>();
    private static final AtomicReference<PresentationDefinitionService> PRESENTATION_DEFINITION_SERVICE =
            new AtomicReference<>();
    private static final AtomicReference<VerificationService> VERIFICATION_SERVICE = new AtomicReference<>();
    private static final AtomicReference<DIDDocumentService> DID_DOCUMENT_SERVICE = new AtomicReference<>();
    private static final AtomicReference<ApplicationManagementService> APPLICATION_MANAGEMENT_SERVICE =
            new AtomicReference<>();

    private VPServiceDataHolder() {
        // Utility class
    }

    /**
     * Get the RealmService.
     * 
     * @return RealmService instance
     */
    public static RealmService getRealmService() {
        return REALM_SERVICE.get();
    }

    /**
     * Set the RealmService.
     * 
     * @param realmService RealmService instance
     */
    public static void setRealmService(RealmService realmService) {
        REALM_SERVICE.set(realmService);
    }

    /**
     * Get the VPRequestService.
     * 
     * @return VPRequestService instance
     */
    public static VPRequestService getVPRequestService() {
        return VP_REQUEST_SERVICE.get();
    }

    /**
     * Set the VPRequestService.
     * 
     * @param vpRequestService VPRequestService instance
     */
    public static void setVPRequestService(VPRequestService vpRequestService) {
        VP_REQUEST_SERVICE.set(vpRequestService);
    }

    /**
     * Get the PresentationDefinitionService.
     * 
     * @return PresentationDefinitionService instance
     */
    public static PresentationDefinitionService getPresentationDefinitionService() {
        return PRESENTATION_DEFINITION_SERVICE.get();
    }

    /**
     * Set the PresentationDefinitionService.
     * 
     * @param presentationDefinitionService PresentationDefinitionService instance
     */
    public static void setPresentationDefinitionService(
            PresentationDefinitionService presentationDefinitionService) {
        PRESENTATION_DEFINITION_SERVICE.set(presentationDefinitionService);
    }

    /**
     * Get the VerificationService.
     * 
     * @return VerificationService instance
     */
    public static VerificationService getVerificationService() {
        return VERIFICATION_SERVICE.get();
    }

    /**
     * Set the VerificationService.
     * 
     * @param verificationService VerificationService instance
     */
    public static void setVerificationService(VerificationService verificationService) {
        VERIFICATION_SERVICE.set(verificationService);
    }

    /**
     * Get the DIDDocumentService.
     * 
     * @return DIDDocumentService instance
     */
    public static DIDDocumentService getDIDDocumentService() {
        DIDDocumentService service = DID_DOCUMENT_SERVICE.get();
        if (service == null) {
            DID_DOCUMENT_SERVICE.compareAndSet(null, new DIDDocumentServiceImpl());
            service = DID_DOCUMENT_SERVICE.get();
        }
        return service;
    }

    /**
     * Set the DIDDocumentService.
     * 
     * @param didDocumentService DIDDocumentService instance
     */
    public static void setDIDDocumentService(DIDDocumentService didDocumentService) {
        DID_DOCUMENT_SERVICE.set(didDocumentService);
    }

    public static ApplicationManagementService getApplicationManagementService() {
        return APPLICATION_MANAGEMENT_SERVICE.get();
    }

    public static void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        APPLICATION_MANAGEMENT_SERVICE.set(applicationManagementService);
    }
}
