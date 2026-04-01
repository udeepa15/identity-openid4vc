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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

/**
 * Base exception type for presentation authenticator failures.
 */
public class VPAuthenticatorException extends Exception {

    private final VPAuthenticatorErrorCode errorCode;
    private final String description;

    public VPAuthenticatorException(final String message) {

        super(message);
        this.errorCode = null;
        this.description = null;
    }

    public VPAuthenticatorException(final String message, final Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = null;
    }

    public VPAuthenticatorException(final VPAuthenticatorErrorCode errorCode, final String message) {

        super(message);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    public VPAuthenticatorException(final VPAuthenticatorErrorCode errorCode, final String message,
                                    final Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = errorCode != null ? errorCode.getDescription() : null;
    }

    public VPAuthenticatorException(final VPAuthenticatorErrorCode errorCode, final String message,
                                    final String description) {

        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    public VPAuthenticatorException(final VPAuthenticatorErrorCode errorCode, final String message,
                                    final String description, final Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    public VPAuthenticatorErrorCode getErrorCode() {

        return errorCode;
    }

    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    public String getOAuth2ErrorCode() {

        return errorCode != null ? errorCode.getOAuth2ErrorCode() : null;
    }

    public String getDescription() {

        return description;
    }
}
