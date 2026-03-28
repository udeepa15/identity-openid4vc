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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Exception thrown when a VP submission fails basic validation in the authenticator.
 */
public class VPSubmissionValidationException extends VPException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new VPSubmissionValidationException with the specified record.
     *
     * @param message The detail message.
     */
    public VPSubmissionValidationException(String message) {
        super(message);
    }

    /**
     * Constructs a new VPSubmissionValidationException with the specified record and cause.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public VPSubmissionValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
