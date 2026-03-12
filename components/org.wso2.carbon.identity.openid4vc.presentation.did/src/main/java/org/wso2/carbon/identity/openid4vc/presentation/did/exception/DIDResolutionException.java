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
 * Exception thrown when DID resolution fails.
 */
public class DIDResolutionException extends VPException {

    /**
     * Default error code.
     */
    private static final String DEFAULT_ERROR_CODE = "DID_RESOLUTION_FAILED";

    /**
     * The DID that failed resolution.
     */
    private String did;

    /**
     * The DID method.
     */
    private String method;

    /**
     * Constructor with message.
     *
     * @param message Error message
     */
    public DIDResolutionException(final String message) {
        super(DEFAULT_ERROR_CODE, message);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message Error message
     * @param cause   Underlying cause
     */
    public DIDResolutionException(final String message, final Throwable cause) {
        super(DEFAULT_ERROR_CODE, message, cause);
    }

    /**
     * Constructor with DID, message, and cause.
     *
     * @param didValue The DID that failed resolution
     * @param message  Error message
     * @param cause    Underlying cause
     */
    public DIDResolutionException(final String didValue, final String message,
            final Throwable cause) {
        super(DEFAULT_ERROR_CODE, message, cause);
        this.did = didValue;
        extractMethod(didValue);
    }

    /**
     * Constructor with error code, DID, and message.
     *
     * @param errorCode Error code
     * @param didValue  The DID that failed resolution
     * @param message   Error message
     */
    public DIDResolutionException(final String errorCode, final String didValue,
            final String message) {
        super(errorCode, message);
        this.did = didValue;
        extractMethod(didValue);
    }

    /**
     * Extract the DID method from the DID string.
     *
     * @param didValue The DID string
     */
    private void extractMethod(final String didValue) {
        if (didValue != null && didValue.startsWith("did:")) {
            String[] parts = didValue.split(":");
            if (parts.length >= 2) {
                this.method = parts[1];
            }
        }
    }

    /**
     * Get the DID that failed resolution.
     *
     * @return The DID
     */
    public String getDid() {
        return did;
    }

    /**
     * Get the DID method.
     *
     * @return The method (e.g., "web", "jwk", "key")
     */
    public String getMethod() {
        return method;
    }

    /**
     * Create an exception for unsupported DID method.
     *
     * @param didValue The DID
     * @param method   The unsupported method
     * @return DIDResolutionException
     */
    public static DIDResolutionException unsupportedMethod(
            final String didValue, final String method) {
        return new DIDResolutionException("UNSUPPORTED_DID_METHOD", didValue,
                "Unsupported DID method: " + method);
    }

    /**
     * Create an exception for network errors during resolution.
     *
     * @param didValue The DID
     * @param cause    The underlying cause
     * @return DIDResolutionException
     */
    public static DIDResolutionException networkError(final String didValue,
            final Throwable cause) {
        return new DIDResolutionException(didValue,
                "Network error while resolving DID: " + didValue, cause);
    }

    /**
     * Create an exception for invalid DID document.
     *
     * @param didValue The DID
     * @param message  Details about the invalid document
     * @return DIDResolutionException
     */
    public static DIDResolutionException invalidDocument(final String didValue,
            final String message) {
        return new DIDResolutionException("INVALID_DID_DOCUMENT", didValue,
                "Invalid DID document for " + didValue + ": " + message);
    }

    /**
     * Create an exception for key not found.
     *
     * @param didValue The DID
     * @param keyId    The key ID that was not found
     * @return DIDResolutionException
     */
    public static DIDResolutionException keyNotFound(final String didValue,
            final String keyId) {
        return new DIDResolutionException("KEY_NOT_FOUND", didValue,
                "Key not found in DID document: "
                        + (keyId != null ? keyId : "default key"));
    }

    /**
     * Create an exception for invalid DID format.
     *
     * @param didValue The invalid DID
     * @return DIDResolutionException
     */
    public static DIDResolutionException invalidFormat(final String didValue) {
        return new DIDResolutionException("INVALID_DID_FORMAT", didValue,
                "Invalid DID format: " + didValue);
    }
}
