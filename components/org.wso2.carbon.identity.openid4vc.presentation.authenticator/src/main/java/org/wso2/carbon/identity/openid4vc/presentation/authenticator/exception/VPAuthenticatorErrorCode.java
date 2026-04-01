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

    INVALID_REQUEST("VPA-40001", "invalid_request", "Invalid request.",
            "Invalid or malformed request."),
    VP_REQUEST_NOT_FOUND("VPA-40401", "vp_request_not_found", "VP request was not found.",
            "The VP request was not found."),
    VP_REQUEST_EXPIRED("VPA-41001", "vp_request_expired", "VP request has expired.",
            "The VP request has expired."),
    INTERNAL_SERVER_ERROR("VPA-50001", "server_error", "Internal server error.",
            "An internal server error occurred.");

    private final String code;
    private final String oauth2ErrorCode;
    private final String message;
    private final String description;

    VPAuthenticatorErrorCode(final String code, final String oauth2ErrorCode,
                             final String message, final String description) {

        this.code = code;
        this.oauth2ErrorCode = oauth2ErrorCode;
        this.message = message;
        this.description = description;
    }

    public String getCode() {

        return code;
    }

    public String getOAuth2ErrorCode() {

        return oauth2ErrorCode;
    }

    public String getMessage() {

        return message;
    }

    public String getDescription() {

        return description;
    }
}
