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

    /**
     * Creates a constants holder instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only {@code public static final} constants.</p>
     */
    private VerificationConstants() {
    }

    /**
     * DID prefixes.
     */
    public static final String DID_PREFIX = "did:";
    

    /**
     * Protocol prefixes.
     */
    public static final String HTTP_PREFIX = "http";
    public static final String HTTPS_PREFIX = "https";

    /**
     * Error message templates and constraints.
     */
    public static final String ERROR_INVALID_VP_TOKEN = "VP token is missing or empty.";
}
