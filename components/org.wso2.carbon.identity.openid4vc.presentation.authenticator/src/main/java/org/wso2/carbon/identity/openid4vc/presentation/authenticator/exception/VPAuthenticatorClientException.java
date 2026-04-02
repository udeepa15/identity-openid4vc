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
 * Exception type for client-side presentation authenticator errors.
 */
public class VPAuthenticatorClientException extends VPAuthenticatorException {

    /**
     * Constructor with message.
     *
     * @param message Error message.
     */
    public VPAuthenticatorClientException(final String message) {

        super(message);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message.
     * @param cause   Throwable cause.
     */
    public VPAuthenticatorClientException(
            final String message,
            final Throwable cause) {

        super(message, cause);
    }

    /**
     * Constructor with error code and message.
     *
     * @param errorCode VPAuthenticatorErrorCode.
     * @param message   Error message.
     */
    public VPAuthenticatorClientException(
            final VPAuthenticatorErrorCode errorCode,
            final String message) {

        super(errorCode, message);
    }

    /**
     * Constructor with error code, message and cause.
     *
     * @param errorCode VPAuthenticatorErrorCode.
     * @param message   Error message.
     * @param cause     Throwable cause.
     */
    public VPAuthenticatorClientException(
            final VPAuthenticatorErrorCode errorCode,
            final String message,
            final Throwable cause) {

        super(errorCode, message, cause);
    }

    /**
     * Constructor with error code, message and description.
     *
     * @param errorCode   VPAuthenticatorErrorCode.
     * @param message     Error message.
     * @param description Error description.
     */
    public VPAuthenticatorClientException(
            final VPAuthenticatorErrorCode errorCode,
            final String message,
            final String description) {

        super(errorCode, message, description);
    }

    /**
     * Constructor with error code, message, description and cause.
     *
     * @param errorCode   VPAuthenticatorErrorCode.
     * @param message     Error message.
     * @param description Error description.
     * @param cause       Throwable cause.
     */
    public VPAuthenticatorClientException(
            final VPAuthenticatorErrorCode errorCode,
            final String message,
            final String description,
            final Throwable cause) {

        super(errorCode, message, description, cause);
    }
}
