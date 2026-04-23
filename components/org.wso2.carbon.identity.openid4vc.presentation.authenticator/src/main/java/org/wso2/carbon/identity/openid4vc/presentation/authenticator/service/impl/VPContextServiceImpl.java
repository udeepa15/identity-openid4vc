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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPContextService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;

import java.util.Optional;

/**
 * Implementation of {@link VPContextService}.
 */
public class VPContextServiceImpl implements VPContextService {

    @Override
    public Optional<VPContext> getVPContext(AuthenticationContext context) {

        if (context == null) {
            return Optional.empty();
        }

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return Optional.of((VPContext) vpContextObj);
        }
        return Optional.empty();
    }

    @Override
    public void setVPContext(AuthenticationContext context, VPContext vpContext) {

        if (context != null) {
            context.setProperty(Constraints.CONTEXT_VP_CONTEXT, vpContext);
        }
    }

    @Override
    public void cleanupVPContext(AuthenticationContext context) {

        if (context == null) {
            return;
        }

        // Retrieve the mapped alias ID if it exists and remove from cache.
        String mappedId = (String) context.getProperty(Constraints.CONTEXT_VP_MAPPED_ID);
        if (StringUtils.isNotBlank(mappedId)) {
            FrameworkUtils.removeAuthenticationContextFromCache(mappedId);
        }

        // Remove the internal VPContext property.
        removeVPContext(context);
    }

    @Override
    public void removeVPContext(AuthenticationContext context) {

        if (context != null) {
            context.removeProperty(Constraints.CONTEXT_VP_CONTEXT);
        }
    }

    @Override
    public Optional<VPContext> getVPContext(String contextId) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(contextId);
        return getVPContext(context);
    }

    @Override
    public void updateVPContext(String contextId, VPContext vpContext) {

        if (StringUtils.isBlank(contextId) || vpContext == null) {
            return;
        }

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(contextId);
        if (context != null) {
            setVPContext(context, vpContext);

            // Always update the entry for the provided contextId.
            FrameworkUtils.addAuthenticationContextToCache(contextId, context);

            // Update the internal framework context ID if it's different and available.
            String internalContextId = context.getContextIdentifier();
            if (StringUtils.isNotBlank(internalContextId) && !internalContextId.equals(contextId)) {
                FrameworkUtils.addAuthenticationContextToCache(internalContextId, context);
            }

            // Sync with the mapped alias ID property if it exists in the context.
            String mappedId = (String) context.getProperty(Constraints.CONTEXT_VP_MAPPED_ID);
            if (StringUtils.isNotBlank(mappedId) && !mappedId.equals(contextId)
                    && !mappedId.equals(internalContextId)) {
                FrameworkUtils.addAuthenticationContextToCache(mappedId, context);
            }
        }
    }
}
