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
 * Error codes for presentation authenticator client/server exception handling.
 */
public enum VPAuthenticatorErrorCode {

    /**
     * Invalid request error.
     */
    INVALID_REQUEST("VPA-40001", "invalid_request",
            "Invalid request.", "Invalid or malformed request."),

    /**
     * VP request not found error.
     */
    VP_REQUEST_NOT_FOUND("VPA-40401", "vp_request_not_found",
            "VP request was not found.", "The VP request was not found."),

    /**
     * VP request expired error.
     */
    VP_REQUEST_EXPIRED("VPA-41001", "vp_request_expired",
            "VP request has expired.", "The VP request has expired."),

    /**
     * Internal server error.
     */
    INTERNAL_SERVER_ERROR("VPA-50001", "server_error",
            "Internal server error.", "An internal server error occurred."),

    /**
     * Unsupported DID method error.
     */
    UNSUPPORTED_DID_METHOD("VPA-40002", "unsupported_did_method",
            "Unsupported DID method.", "The requested DID method is not supported."),

    /**
     * Invalid presentation definition error.
     */
    INVALID_PRESENTATION_DEFINITION("VPA-40003", "invalid_presentation_definition",
            "Invalid presentation definition.", "The presentation definition is invalid or missing."),

    /**
     * Client metadata error.
     */
    CLIENT_METADATA_ERROR("VPA-40004", "invalid_client_metadata",
            "Invalid client metadata.", "The client metadata is invalid or malformed."),

    /**
     * VP verification failed error.
     */
    VERIFICATION_FAILED("VPA-40101", "verification_failed",
            "VP verification failed.", "The verifiable presentation verification failed."),

    /**
     * Signing error.
     */
    SIGNING_ERROR("VPA-50002", "signing_error",
            "Error occurred during signing.", "An error occurred while signing the request object."),

    /**
     * DID resolution failure error.
     */
    DID_RESOLUTION_FAILED("VPA-50003", "did_resolution_failed",
            "DID resolution failed.", "Failed to resolve the verifier's DID.");

    /**
     * Internal error code.
     */
    private final String code;
    /**
     * OAuth2 error code.
     */
    private final String oauth2ErrorCode;
    /**
     * Error message.
     */
    private final String message;
    /**
     * Error description.
     */
    private final String description;

    /**
     * Constructor for VPAuthenticatorErrorCode.
     *
     * @param errorCode        Error code.
     * @param oauth2Code       OAuth2 error code.
     * @param errorMsg         Error message.
     * @param errorDescription Error description.
     */
    VPAuthenticatorErrorCode(final String errorCode,
                             final String oauth2Code,
                             final String errorMsg,
                             final String errorDescription) {

        this.code = errorCode;
        this.oauth2ErrorCode = oauth2Code;
        this.message = errorMsg;
        this.description = errorDescription;
    }

    /**
     * Get error code.
     *
     * @return Error code.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get OAuth2 error code.
     *
     * @return OAuth2 error code.
     */
    public String getOAuth2ErrorCode() {

        return oauth2ErrorCode;
    }

    /**
     * Get error message.
     *
     * @return Error message.
     */
    public String getMessage() {

        return message;
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
