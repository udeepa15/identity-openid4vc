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

package org.wso2.carbon.identity.openid4vc.presentation.verification.exception;

/**
 * Exception type for server-side failures in credential verification.
 *
 * <p>Represents a 5xx-class error where the server encountered an unexpected condition.
 * Every instance must carry a {@link VerificationErrorCode}.</p>
 */
public class VerificationServerException extends VerificationException {

    /**
     * Creates a new server exception with the given error code and a short message.
     *
     * @param errorCode The structured error code (must not be null).
     * @param message   A concise, developer-facing message.
     */
    public VerificationServerException(VerificationErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    /**
     * Creates a new server exception with the given error code, message, and root cause.
     *
     * @param errorCode The structured error code (must not be null).
     * @param message   A concise, developer-facing message.
     * @param cause     The underlying exception.
     */
    public VerificationServerException(VerificationErrorCode errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }

    /**
     * Creates a new server exception with the given error code, message, and a custom description.
     *
     * @param errorCode   The structured error code (must not be null).
     * @param message     A concise, developer-facing message.
     * @param description A detailed, user-facing description that overrides the code's default.
     */
    public VerificationServerException(VerificationErrorCode errorCode, String message, String description) {

        super(errorCode, message, description);
    }

    /**
     * Creates a new server exception with the given error code, message, custom description, and root cause.
     *
     * @param errorCode   The structured error code (must not be null).
     * @param message     A concise, developer-facing message.
     * @param description A detailed, user-facing description that overrides the code's default.
     * @param cause       The underlying exception.
     */
    public VerificationServerException(VerificationErrorCode errorCode, String message, String description,
                                       Throwable cause) {

        super(errorCode, message, description, cause);
    }
}
