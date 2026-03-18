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

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for DIDProviderFactory.
 */
public class DIDProviderFactoryTest {

    /**
     * Tests getting default web provider.
     */
    @Test
    public void testGetWebProvider() {
        DIDProvider provider1 = DIDProviderFactory.getProvider(null);
        DIDProvider provider2 = DIDProviderFactory.getProvider("web");

        Assert.assertNotNull(provider1);
        Assert.assertNotNull(provider2);
        Assert.assertEquals(provider1.getName(), "web");
        Assert.assertEquals(provider2.getName(), "web");
    }

    /**
     * Tests unknown provider behavior.
     */
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetUnknownProvider() {
        DIDProviderFactory.getProvider("unknown");
    }
}
