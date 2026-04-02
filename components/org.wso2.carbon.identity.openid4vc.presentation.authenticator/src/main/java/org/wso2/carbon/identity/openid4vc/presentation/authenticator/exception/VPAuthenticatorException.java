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

    /**
     * VP authenticator error code.
     */
    private final VPAuthenticatorErrorCode errorCode;

    /**
     * VP authenticator error description.
     */
    private final String description;

    /**
     * Constructor with message.
     *
     * @param message Error message.
     */
    public VPAuthenticatorException(final String message) {

        super(message);
        this.errorCode = null;
        this.description = null;
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message.
     * @param cause   Throwable cause.
     */
    public VPAuthenticatorException(
            final String message,
            final Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = null;
    }

    /**
     * Constructor with error code and message.
     *
     * @param errorCodeParam VPAuthenticatorErrorCode.
     * @param message        Error message.
     */
    public VPAuthenticatorException(
            final VPAuthenticatorErrorCode errorCodeParam,
            final String message) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null
                ? errorCodeParam.getDescription() : null;
    }

    /**
     * Constructor with error code, message and cause.
     *
     * @param errorCodeParam VPAuthenticatorErrorCode.
     * @param message        Error message.
     * @param cause          Throwable cause.
     */
    public VPAuthenticatorException(
            final VPAuthenticatorErrorCode errorCodeParam,
            final String message,
            final Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null
                ? errorCodeParam.getDescription() : null;
    }

    /**
     * Constructor with error code, message and description.
     *
     * @param errorCodeParam   VPAuthenticatorErrorCode.
     * @param message          Error message.
     * @param descriptionParam Error description.
     */
    public VPAuthenticatorException(
            final VPAuthenticatorErrorCode errorCodeParam,
            final String message,
            final String descriptionParam) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    /**
     * Constructor with error code, message, description and cause.
     *
     * @param errorCodeParam   VPAuthenticatorErrorCode.
     * @param message          Error message.
     * @param descriptionParam Error description.
     * @param cause            Throwable cause.
     */
    public VPAuthenticatorException(
            final VPAuthenticatorErrorCode errorCodeParam,
            final String message,
            final String descriptionParam,
            final Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    /**
     * Get error code.
     *
     * @return VPAuthenticatorErrorCode.
     */
    public VPAuthenticatorErrorCode getErrorCode() {

        return errorCode;
    }

    /**
     * Get error code.
     *
     * @return Error code.
     */
    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    /**
     * Get OAuth2 error code.
     *
     * @return OAuth2 error code.
     */
    public String getOAuth2ErrorCode() {

        return errorCode != null ? errorCode.getOAuth2ErrorCode() : null;
    }

    /**
     * Get error description.
     *
     * @return Error description.
     */
    public String getDescription() {

        return description;
    }
}
