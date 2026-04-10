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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.CONTEXT_VP_REQUEST;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.DEFAULT_VP_REQUEST_EXPIRY_MS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request operations.
 *
 * <p>Endpoints:</p>
 * <ul>
 *     <li>GET /api/identity/oid4vp/v1/vp-request/{requestId} - Get authorization request JWT.</li>
 *     <li>GET /api/identity/oid4vp/v1/vp-request/{requestId}/status - Get request status (with polling).</li>
 * </ul>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/oid4vp/v1/vp-request/*",
        "osgi.http.whiteboard.servlet.name=OpenID4VPRequest",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPRequestServlet extends HttpServlet {

    private static final String OID4VP_REQUEST_ID_SUFFIX = ",OID4VP";

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Gson instance for JSON operations.
     */
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    /**
     * Default tenant ID to use when tenant domain cannot be resolved.
     */
    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * Pattern to validate tenant domain names.
     */
    private static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    /**
     * Initialize the servlet.
     *
     * @throws ServletException If an error occurs during initialization.
     */
    @Override
    public void init() throws ServletException {

        super.init();
    }

    /**
     * Handle GET requests to retrieve a request JWT or its status.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @throws ServletException If an error occurs in the servlet.
     * @throws IOException      If an I/O error occurs.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request ID is required in path."));
            return;
        }

        // Parse path: /{requestId} or /{requestId}/status.
        String[] pathParts = pathInfo.split("/");

        if (pathParts.length < 2) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Invalid path format."));
            return;
        }

        String requestId = removeOid4vpSuffix(pathParts[1]);
        boolean isStatusRequest = pathParts.length >= 3 && "status".equals(pathParts[2]);

        try {
            AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
            if (context == null) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.EXPIRED.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                                    "VP request not found: " + requestId));
                }
                return;
            }

            VPRequestContext vpContext = null;
            Object vpRequestContextObj = context.getProperty(CONTEXT_VP_REQUEST);
            if (vpRequestContextObj instanceof VPRequestContext) {
                vpContext = (VPRequestContext) vpRequestContextObj;
            }

            if (vpContext == null) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "VP request context is missing for request: " + requestId);
            }

            VPRequestStatus status = vpContext.getRequestStatus();

            // 1. Check if the context vpstatus is failed or verified or vp_submitted.
            if (status == VPRequestStatus.FAILED || status == VPRequestStatus.VERIFIED ||
                    status == VPRequestStatus.VP_SUBMITTED) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                return;
            }

            // 2. If the status is active then check the context expiry time.
            if (status == VPRequestStatus.ACTIVE) {
                if (isRequestExpired(vpContext)) {
                    // if expired change the context status to Expired also response status as expired.
                    vpContext.setRequestStatus(VPRequestStatus.EXPIRED);
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.EXPIRED.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                    return;
                }

                // if not expired then check whther the request is a status request or an authorization request.
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.ACTIVE.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    handleRequestJwtRequest(response, vpContext, requestId);
                }
                return;
            }

            // 3. Apart from status being active and not expired, all other times send an error or status accordingly.
            if (isStatusRequest) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
            } else {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                        "VP request is not active: " + status);
            }

        } catch (VPAuthenticatorClientException e) {
            if (VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED.getCode().equals(e.getCode())) {
                sendErrorResponse(response, HttpServletResponse.SC_GONE, e);
            } else {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, e);
            }
        } catch (VPAuthenticatorException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (RuntimeException | IOException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Internal server error.", e));
        }
    }

    /**
     * Handle request JWT retrieval (for request_uri flow).
     *
     * @param response  HTTP response.
     * @param requestId Request ID.
     * @throws VPAuthenticatorException If a VP authenticator error occurs.
     * @throws IOException              If an I/O error occurs.
     */
    private void handleRequestJwtRequest(HttpServletResponse response, VPRequestContext vpContext,
                                         String requestId) throws VPAuthenticatorException, IOException {

        String requestJwt = vpContext.getRequestJwt();

        if (StringUtils.isBlank(requestJwt)) {
            throw new VPAuthenticatorServerException(
                VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                "Request JWT is missing for request: " + requestId);
        }

        response.setContentType("application/oauth-authz-req+jwt");
        response.setStatus(HttpServletResponse.SC_OK);
        writeResponse(response, requestJwt);
    }

    /**
     * Write string content to the response output stream.
     *
     * @param response HTTP response.
     * @param content  Content to write.
     * @throws IOException If an I/O error occurs.
     */
    private void writeResponse(HttpServletResponse response, String content) throws IOException {

        response.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        response.getOutputStream().flush();
    }

    /**
     * Check if the VP request has expired based on the 60-second active window.
     *
     * @param vpRequestContext VP request context.
     * @return True if expired, false otherwise.
     */
    private boolean isRequestExpired(VPRequestContext vpRequestContext) {

        if (vpRequestContext == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        return (currentTime - vpRequestContext.getCreatedAt()) > DEFAULT_VP_REQUEST_EXPIRY_MS;
    }

    /**
     * Send JSON response.
     *
     * @param response   HTTP response.
     * @param statusCode HTTP status code.
     * @param data       Data to send.
     * @throws IOException If an I/O error occurs.
     */
    private void sendJsonResponse(HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");

        writeResponse(response, gson.toJson(data));
    }

    /**
     * Send error response formatted as JSON.
     *
     * @param response   HTTP response.
     * @param statusCode HTTP status code.
     * @param exception  Exception containing error information.
     * @throws IOException If an I/O error occurs.
     */
    private void sendErrorResponse(final HttpServletResponse response, final int statusCode,
            final VPAuthenticatorException exception)
            throws IOException {

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", exception.getOAuth2ErrorCode());
        errorObj.addProperty("error_description", Encode.forJava(exception.getMessage()));
        errorObj.addProperty("error_code", exception.getCode());
        sendJsonResponse(response, statusCode, errorObj);
    }

    /**
     * Remove the OID4VP request-id suffix used in wallet request URIs before cache lookup.
     *
     * @param requestId Raw request ID from request path.
     * @return Normalized request ID without OID4VP suffix.
     */
    private String removeOid4vpSuffix(String requestId) {

        if (StringUtils.isBlank(requestId)) {
            return requestId;
        }
        if (requestId.endsWith(OID4VP_REQUEST_ID_SUFFIX)) {
            return requestId.substring(0, requestId.length() - OID4VP_REQUEST_ID_SUFFIX.length());
        }
        return requestId;
    }

}
