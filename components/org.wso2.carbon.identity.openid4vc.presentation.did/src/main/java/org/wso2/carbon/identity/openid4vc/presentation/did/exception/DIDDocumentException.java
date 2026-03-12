/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

/**
 * Exception thrown when DID document operations fail.
 * Extends VPException to maintain consistent exception hierarchy and support error codes.
 */
public class DIDDocumentException extends VPException {

    /**
     * Constructor with message and cause.s
     *
     * @param message Error message
     * @param cause   Underlying cause
     */
    public DIDDocumentException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
