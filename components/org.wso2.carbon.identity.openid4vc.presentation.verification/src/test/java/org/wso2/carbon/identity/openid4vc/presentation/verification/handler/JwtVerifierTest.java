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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handler;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

public class JwtVerifierTest {

    private JwtVerifier jwtVerifier;

    @BeforeMethod
    public void setUp() {
        jwtVerifier = new JwtVerifier();
    }

    @Test
    public void testCanHandle() {
        assertTrue(jwtVerifier.canHandle(Constants.JWT_VC_FORMAT));
        assertFalse(jwtVerifier.canHandle(Constants.VC_SD_JWT_FORMAT));
    }

    @Test
    public void testHandleInvalidJwtThrowsParseError() {
        PresentationSubmission submission = new PresentationSubmission();
        assertThrows(VerificationClientException.class, () -> 
            jwtVerifier.handle(submission, 1, "invalid-jwt"));
        
        try {
            jwtVerifier.handle(submission, 1, "invalid-jwt");
        } catch (Exception e) {
            assertTrue(e instanceof VerificationClientException);
            assertEquals(((VerificationClientException) e).getErrorCode(), VerificationErrorCode.PARSE_ERROR);
        }
    }
}
