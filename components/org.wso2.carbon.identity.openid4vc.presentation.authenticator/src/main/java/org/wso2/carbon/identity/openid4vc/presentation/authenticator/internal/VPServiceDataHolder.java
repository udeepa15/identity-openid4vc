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
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDDocumentServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl.VCVerificationServiceImpl;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for OpenID4VP services.
 * Provides access to OSGi services across the component.
 */
public class VPServiceDataHolder {

    private static volatile VPServiceDataHolder instance;

    private RealmService realmService;
    private VPRequestService vpRequestService;
    private PresentationDefinitionService presentationDefinitionService;
    private VCVerificationService vcVerificationService;
    private DIDDocumentService didDocumentService;
    private ApplicationManagementService applicationManagementService;

    private VPServiceDataHolder() {
        // Private constructor for singleton
    }

    /**
     * Get the singleton instance.
     * 
     * @return VPServiceDataHolder instance
     */
    @SuppressFBWarnings("MS_EXPOSE_REP")
    public static VPServiceDataHolder getInstance() {
        if (instance == null) {
            synchronized (VPServiceDataHolder.class) {
                if (instance == null) {
                    instance = new VPServiceDataHolder();
                }
            }
        }
        return instance;
    }

    /**
     * Get the RealmService.
     * 
     * @return RealmService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public RealmService getRealmService() {
        return realmService;
    }

    /**
     * Set the RealmService.
     * 
     * @param realmService RealmService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    /**
     * Get the VPRequestService.
     * 
     * @return VPRequestService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public VPRequestService getVPRequestService() {
        return vpRequestService;
    }

    /**
     * Set the VPRequestService.
     * 
     * @param vpRequestService VPRequestService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setVPRequestService(VPRequestService vpRequestService) {
        this.vpRequestService = vpRequestService;
    }

    /**
     * Get the PresentationDefinitionService.
     * 
     * @return PresentationDefinitionService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public PresentationDefinitionService getPresentationDefinitionService() {
        return presentationDefinitionService;
    }

    /**
     * Set the PresentationDefinitionService.
     * 
     * @param presentationDefinitionService PresentationDefinitionService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setPresentationDefinitionService(
            PresentationDefinitionService presentationDefinitionService) {
        this.presentationDefinitionService = presentationDefinitionService;
    }

    /**
     * Get the VCVerificationService.
     * 
     * @return VCVerificationService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public VCVerificationService getVCVerificationService() {
        if (vcVerificationService == null) {
            vcVerificationService = new VCVerificationServiceImpl();
        }
        return vcVerificationService;
    }

    /**
     * Set the VCVerificationService.
     * 
     * @param vcVerificationService VCVerificationService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setVCVerificationService(VCVerificationService vcVerificationService) {
        this.vcVerificationService = vcVerificationService;
    }

    /**
     * Get the DIDDocumentService.
     * 
     * @return DIDDocumentService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public DIDDocumentService getDIDDocumentService() {
        if (didDocumentService == null) {
            didDocumentService = new DIDDocumentServiceImpl();
        }
        return didDocumentService;
    }

    /**
     * Set the DIDDocumentService.
     * 
     * @param didDocumentService DIDDocumentService instance
     */
    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setDIDDocumentService(DIDDocumentService didDocumentService) {
        this.didDocumentService = didDocumentService;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public ApplicationManagementService getApplicationManagementService() {
        return applicationManagementService;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        this.applicationManagementService = applicationManagementService;
    }
}
