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

package org.wso2.carbon.identity.openid4vc.presentation.did.util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;

/**
 * Unit tests for Base58 utility.
 */
public class Base58Test {

    /**
     * Tests Base58 encode with null and empty inputs.
     */
    @Test
    public void testEncodeNullAndEmpty() {
        Assert.assertEquals(Base58.encode(null), "");
        Assert.assertEquals(Base58.encode(new byte[0]), "");
    }

    /**
     * Tests Base58 encode with known values.
     */
    @Test
    public void testEncodeKnownValues() {
        Assert.assertEquals(Base58.encode("Hello World".getBytes(StandardCharsets.UTF_8)), "JxF12TrwUP45BMd");
        Assert.assertEquals(Base58.encode(new byte[] { 0, 0, 1, 2, 3 }), "11Ldp");
    }

    /**
     * Tests Base58 encode determinism.
     */
    @Test
    public void testEncodeDeterministic() {
        byte[] input = "sample-data".getBytes(StandardCharsets.UTF_8);
        String encoded1 = Base58.encode(input);
        String encoded2 = Base58.encode(input);

        Assert.assertEquals(encoded1, encoded2);
        Assert.assertNotEquals(encoded1, "sample-data");
    }
}
