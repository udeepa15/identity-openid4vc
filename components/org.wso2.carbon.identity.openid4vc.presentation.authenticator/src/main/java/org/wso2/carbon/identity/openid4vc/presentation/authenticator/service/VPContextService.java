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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;

import java.util.Optional;

/**
 * Service for managing VP (Verifiable Presentation) context within the authentication session.
 */
public interface VPContextService {

    /**
     * Get the VP context from the authentication context.
     *
     * @param context Authentication context.
     * @return Optional containing the VP context if found.
     */
    Optional<VPContext> getVPContext(AuthenticationContext context);

    /**
     * Set the VP context in the authentication context.
     *
     * @param context   Authentication context.
     * @param vpContext VP context to set.
     */
    void setVPContext(AuthenticationContext context, VPContext vpContext);

    /**
     * Remove the VP context from the authentication context.
     *
     * @param context Authentication context.
     */
    void removeVPContext(AuthenticationContext context);
}
