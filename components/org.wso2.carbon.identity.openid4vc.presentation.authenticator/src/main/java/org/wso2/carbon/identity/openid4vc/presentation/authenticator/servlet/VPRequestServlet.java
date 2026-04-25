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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.JOSE_TYPE_OAUTH_AUTHZ_REQ;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_STATUS;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request operations.
 *
 * <p>Endpoints:</p>
 * <ul>
 *     <li>GET /oid4vp/v1/vp-request/{requestId} - Get authorization request JWT.</li>
 *     <li>GET /oid4vp/v1/vp-request/{requestId}/status - Get request status (with polling).</li>
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

        String requestId = pathParts[1];
        boolean isStatusRequest = pathParts.length >= 3 && "status".equals(pathParts[2]);

        try {
            VPContext vpContext = getVPContextByRequestId(requestId);
            if (vpContext == null) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.FAILED.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                                    "VP request not found: " + requestId));
                }
                return;
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

            if (status == VPRequestStatus.ACTIVE) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPRequestStatus.ACTIVE.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    handleRequestJwtRequest(response, requestId);
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
    private void handleRequestJwtRequest(HttpServletResponse response,
                                         String requestId) throws VPAuthenticatorException, IOException {

        String requestJwt = VPServiceDataHolder.getVPRequestService().generateRequestJwt(requestId);

        if (StringUtils.isBlank(requestJwt)) {
            throw new VPAuthenticatorServerException(
                VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                "Failed to generate request JWT for request: " + requestId);
        }

        response.setContentType(JOSE_TYPE_OAUTH_AUTHZ_REQ);
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
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);

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
        errorObj.addProperty(RESPONSE_ERROR, exception.getOAuth2ErrorCode());
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION, Encode.forJava(exception.getMessage()));
        errorObj.addProperty(RESPONSE_ERROR_CODE, exception.getCode());
         sendJsonResponse(response, statusCode, errorObj);
     }

    private VPContext getVPContextByRequestId(String requestId) {

        AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(requestId);
        if (context == null) {
            return null;
        }

        Object vpContextObj = context.getProperty(Constraints.CONTEXT_VP_CONTEXT);
        if (vpContextObj instanceof VPContext) {
            return (VPContext) vpContextObj;
        }

        return null;
    }
 }
