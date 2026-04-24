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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

/**
 * Constants related to the OpenID for Verifiable Presentations (OpenID4VP) authenticator.
 */
public class Constraints {

    /**
     * Authenticator configuration properties.
     */
    public static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    /**
     * Request parameter names.
     */
    public static final String PARAM_VP_REQUEST_ID = "vp_request_id";
    public static final String PARAM_STATUS = "status";
    public static final String PARAM_POLL = "poll";
    public static final String PARAM_SESSION_DATA_KEY = "sessionDataKey";
    public static final String PARAM_CLIENT_ID = "clientId";
    public static final String PARAM_REQUEST_URI = "requestUri";
    public static final String PARAM_TENANT_DOMAIN = "tenantDomain";

    /**
     * Session data and UI attribute keys.
     */
    public static final String CONTEXT_VP_CONTEXT = "VPContext";
    public static final String CONTEXT_VP_MAPPED_ID = "VP_REQUEST_ID";

    /**
     * Configuration property names and defaults.
     */
    public static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    public static final String PROP_RESPONSE_MODE = "ResponseMode";
    public static final String PROP_TIMEOUT_SECONDS = "TimeoutSeconds";
    public static final String PROP_CLIENT_ID = "ClientId";
    public static final String PROP_SUBJECT_CLAIM = "SubjectClaim";
    public static final String DEFAULT_DID_METHOD_WEB = "web";
    public static final String DID_WEB_PREFIX = "did:web:";
    public static final String URL_SCHEME_REGEX = "^https?://";
    public static final String TRAILING_SLASH_REGEX = "/$";

    /**
     * Endpoint and pattern constants.
     */
    public static final String WALLET_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";
    public static final String REQUEST_URI_ENDPOINT = "/oid4vp/v1/vp-request/";
    public static final String RESPONSE_URI_ENDPOINT = "/oid4vp/v1/response";
    public static final String RESPONSE_STATUS = "status";
    public static final String RESPONSE_REQUEST_ID = "requestId";
    public static final String RESPONSE_ERROR = "error";
    public static final String RESPONSE_ERROR_DESCRIPTION = "error_description";
    public static final String RESPONSE_ERROR_CODE = "error_code";
    public static final String RESPONSE_STATUS_SUCCESS = "success";
    public static final String RESPONSE_CONTENT_TYPE_CHARSET_UTF_8 = ";charset=UTF-8";
    public static final String RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    public static final String RESPONSE_HEADER_VALUE_NOSNIFF = "nosniff";

    /**
     * JWT Claims and metadata constants.
     */
    public static final String CLAIM_PRESENTATION_DEFINITION = "presentation_definition";
    public static final String CLAIM_CLIENT_METADATA = "client_metadata";
    public static final String CLAIM_CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String CLAIM_VC = "vc";
    public static final String METADATA_CLIENT_NAME = "client_name";
    public static final String METADATA_VP_FORMATS = "vp_formats";
    public static final String FORMAT_VC_SD_JWT = "vc+sd-jwt";
    public static final String METADATA_SD_JWT_ALG_VALUES = "sd-jwt_alg_values";
    public static final String METADATA_KB_JWT_ALG_VALUES = "kb-jwt_alg_values";
    public static final String JOSE_TYPE_OAUTH_AUTHZ_REQ = "oauth-authz-req+jwt";
    public static final String ALG_RS256 = "RS256";
    public static final String ALG_EDDSA = "EdDSA";

    /**
     * Authentication status values.
     */
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_FAILED = "failed";
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_CANCELLED = "cancelled";

    /**
     * Display order and boundary constants.
     */
    public static final int DISPLAY_ORDER_3 = 3;
    public static final int DISPLAY_ORDER_4 = 4;
    public static final int DISPLAY_ORDER_5 = 5;

    public static final int SUPER_TENANT_ID_PLACEHOLDER = -1234;
    public static final String SUPER_TENANT_DOMAIN = "carbon.super";
    public static final String TENANT_PATH_PREFIX = "/t/";
    public static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private Constraints() {

    }
}
