/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;

/**
 * Data Holder for OpenID4VP presentation.
 */
@SuppressFBWarnings({"EI_EXPOSE_REP", "EI_EXPOSE_REP2", "MS_EXPOSE_REP", "SING_SINGLETON_GETTER_NOT_SYNCHRONIZED"})
public class OpenID4VCPresentationDataHolder {

    private static final OpenID4VCPresentationDataHolder INSTANCE = new OpenID4VCPresentationDataHolder();
    private VPRequestService vpRequestService;
    private PresentationDefinitionService presentationDefinitionService;
    private ApplicationManagementService applicationManagementService;

    private OpenID4VCPresentationDataHolder() {
    }

    public static OpenID4VCPresentationDataHolder getInstance() {
        return INSTANCE;
    }

    public VPRequestService getVPRequestService() {
        return vpRequestService;
    }

    public void setVPRequestService(VPRequestService vpRequestService) {
        this.vpRequestService = vpRequestService;
    }

    public PresentationDefinitionService getPresentationDefinitionService() {
        return presentationDefinitionService;
    }

    public void setPresentationDefinitionService(PresentationDefinitionService presentationDefinitionService) {
        this.presentationDefinitionService = presentationDefinitionService;
    }

    public ApplicationManagementService getApplicationManagementService() {
        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        this.applicationManagementService = applicationManagementService;
    }
}
