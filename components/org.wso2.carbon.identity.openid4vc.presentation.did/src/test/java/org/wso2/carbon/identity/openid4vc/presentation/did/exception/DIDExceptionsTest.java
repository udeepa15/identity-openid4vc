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

package org.wso2.carbon.identity.openid4vc.presentation.did.exception;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for DID exceptions.
 */
public class DIDExceptionsTest {

    /**
     * Tests DIDDocumentException constructor.
     */
    @Test
    public void testDIDDocumentException() {
        RuntimeException cause = new RuntimeException("cause");
        DIDDocumentException exception = new DIDDocumentException("message", cause);

        Assert.assertEquals(exception.getMessage(), "message");
        Assert.assertEquals(exception.getCause(), cause);
    }

    /**
     * Tests DIDResolutionException constructors and extracted method.
     */
    @Test
    public void testDIDResolutionExceptionConstructors() {
        DIDResolutionException exception = new DIDResolutionException("did:web:example.com", "failed",
                new RuntimeException("cause"));

        Assert.assertEquals(exception.getDid(), "did:web:example.com");
        Assert.assertEquals(exception.getMethod(), "web");
        Assert.assertEquals(exception.getMessage(), "failed");
    }

    /**
     * Tests DIDResolutionException static factory methods.
     */
    @Test
    public void testDIDResolutionExceptionFactoryMethods() {
        DIDResolutionException unsupported = DIDResolutionException.unsupportedMethod("did:foo:123", "foo");
        DIDResolutionException network = DIDResolutionException.networkError("did:web:example.com",
                new RuntimeException("io"));
        DIDResolutionException invalidDoc = DIDResolutionException.invalidDocument("did:web:example.com",
                "missing id");
        DIDResolutionException notFound = DIDResolutionException.keyNotFound("did:web:example.com", null);
        DIDResolutionException invalidFormat = DIDResolutionException.invalidFormat("bad-did");

        Assert.assertTrue(unsupported.getMessage().contains("Unsupported DID method"));
        Assert.assertTrue(network.getMessage().contains("Network error while resolving DID"));
        Assert.assertTrue(invalidDoc.getMessage().contains("Invalid DID document"));
        Assert.assertTrue(notFound.getMessage().contains("default key"));
        Assert.assertTrue(invalidFormat.getMessage().contains("Invalid DID format"));
    }
}
