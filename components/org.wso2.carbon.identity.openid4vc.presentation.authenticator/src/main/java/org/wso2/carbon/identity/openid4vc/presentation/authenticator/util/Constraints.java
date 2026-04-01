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
 * Constants related to OpenID4VP Authenticator.
 */
public class Constraints {

    // Authenticator configuration properties
    public static final String AUTHENTICATOR_NAME = "OpenID4VPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    // Request parameter names
    public static final String PARAM_VP_REQUEST_ID = "vp_request_id";
    public static final String PARAM_STATUS = "status";
    public static final String PARAM_POLL = "poll";

    // Session data keys
    public static final String SESSION_VP_REQUEST_ID = "openid4vp_request_id";
    public static final String SESSION_TRANSACTION_ID = "openid4vp_transaction_id";
    public static final String UI_SESSION_DATA_KEY = "openid4vp_ui_session_data_key";
    public static final String UI_REQUEST_ID = "openid4vp_ui_request_id";
    public static final String UI_TRANSACTION_ID = "openid4vp_ui_transaction_id";
    public static final String UI_REQUEST_URI = "openid4vp_ui_request_uri";
    public static final String UI_QR_CONTENT = "openid4vp_ui_qr_content";

    // Configuration property keys
    public static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    public static final String PROP_RESPONSE_MODE = "ResponseMode";
    public static final String PROP_TIMEOUT_SECONDS = "TimeoutSeconds";
    public static final String PROP_CLIENT_ID = "ClientId";
    public static final String PROP_SUBJECT_CLAIM = "SubjectClaim";
    public static final String PROP_DID_METHOD = "DIDMethod";
    public static final String DEFAULT_DID_METHOD_WEB = "web";
    
    public static final String DEFAULT_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";
    public static final String ALPHANUM_PATTERN = "^[a-zA-Z0-9_.-]+$";
    public static final int DEFAULT_TENANT_ID = -1234;
    public static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    public static final int DISPLAY_ORDER_3 = 3;
    public static final int DISPLAY_ORDER_4 = 4;
    public static final int DISPLAY_ORDER_5 = 5;
    
    public static final int SUPER_TENANT_ID_PLACEHOLDER = -1234;

    private Constraints() {
    }
}
