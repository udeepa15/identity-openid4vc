/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.jwt.ExtendedJWKSValidator;

import java.io.IOException;

import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class HttpClientAndJWKSValidatorTest {

    @Test
    public void testHttpClientUtilRejectsMalformedAndUnsupportedUrls() {

        assertThrows(IOException.class, () -> HttpClientUtil.fetchContent("::::", null));
        assertThrows(IOException.class, () -> HttpClientUtil.fetchContent("ftp://example.com/file", null));
        assertThrows(IOException.class, () -> HttpClientUtil.fetchContent("http:///path-only", null));
    }

    @Test
    public void testHttpClientFetchJsonInvalidUrl() {

        assertThrows(IOException.class, () -> HttpClientUtil.fetchJson("::::"));
    }

    @Test
    public void testExtendedJWKSValidatorInvalidInputsThrowCredentialVerificationException() {

        ExtendedJWKSValidator validator = new ExtendedJWKSValidator();

        try {
            validator.validateSignature("a.b.c", "::::", "RS256");
            fail("Expected CredentialVerificationException for invalid JWKS URI");
        } catch (CredentialVerificationException ex1) {
            assertTrue(ex1.getMessage().contains("Signature verification failed"));
        }

        try {
            validator.validateSignature("a.b.c", "https://example.com/jwks", "INVALID_ALG");
            fail("Expected CredentialVerificationException for invalid algorithm");
        } catch (CredentialVerificationException ex2) {
            assertTrue(ex2.getMessage().contains("Signature verification failed"));
        }

        try {
            validator.validateSignature(null, "::::", "RS256");
            fail("Expected CredentialVerificationException for null JWT input");
        } catch (CredentialVerificationException ex3) {
            assertTrue(ex3.getMessage().contains("Signature verification failed"));
        }
    }
}
