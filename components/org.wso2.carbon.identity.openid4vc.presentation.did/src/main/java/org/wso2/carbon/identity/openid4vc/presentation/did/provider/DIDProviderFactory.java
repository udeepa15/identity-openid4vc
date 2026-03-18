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

package org.wso2.carbon.identity.openid4vc.presentation.did.provider;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.impl.DIDWebProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * Factory for creating/retrieving DID Providers.
 */
public class DIDProviderFactory {

    private static final Map<String, DIDProvider> providers = new HashMap<>();

    static {
        register(new DIDWebProvider());
    }

    private static void register(DIDProvider provider) {
        providers.put(provider.getName(), provider);
    }

    /**
     * Get the DID Provider for the given method name.
     * Defaults to "web" if name is null or empty.
     *
     * @param method DID method name (e.g., "web", "key", "jwk")
     * @return DIDProvider instance
     * @throws IllegalArgumentException if method is unknown
     */
    public static DIDProvider getProvider(String method) {
        if (StringUtils.isBlank(method) || "web".equals(method)) {
            return providers.get("web");
        }
        
        throw new IllegalArgumentException("Unsupported DID method: " + method);
    }
}
