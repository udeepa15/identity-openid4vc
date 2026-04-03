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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

/**
 * Constants and general constraints for the OpenID4VC verification component.
 */
public class VerificationConstants {

    private VerificationConstants() {
    }

    /**
     * Presentation submission field names.
     */
    public static final String VP_TOKEN = "vp_token";
    public static final String PRESENTATION_SUBMISSION = "presentation_submission";

    /**
     * Supported VP formats.
     */
    public static final String FORMAT_JWT = "jwt_vc";
    public static final String FORMAT_SD_JWT = "vc+sd-jwt";

    /**
     * Standard JWT claim names.
     */
    public static final String CLAIM_ISS = "iss";
    public static final String CLAIM_SUB = "sub";
    public static final String CLAIM_IAT = "iat";
    public static final String CLAIM_EXP = "exp";
    public static final String CLAIM_CNF = "cnf";

    /**
     * SD-JWT specific claim names.
     */
    public static final String CLAIM_SD = "_sd";
    public static final String CLAIM_SD_ALG = "_sd_alg";

    /**
     * DID prefixes.
     */
    public static final String DID_PREFIX = "did:";
    public static final String DID_WEB_PREFIX = "did:web:";

    /**
     * Protocol prefixes.
     */
    public static final String HTTP_PREFIX = "http";

    /**
     * Error message templates and constraints.
     */
    public static final String ERROR_INVALID_VP_TOKEN = "VP token is missing or empty.";
}
