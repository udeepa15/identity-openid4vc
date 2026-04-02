/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request
 * operations.
 * 
 * Endpoints:
 * - GET /api/identity/openid4vp/v1/vp-request/{requestId} - Get authorization
 * request JWT
 * - GET /api/identity/openid4vp/v1/vp-request/{requestId}/status - Get request
 * status (with polling)
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/openid4vp/v1/vp-request/*",
        "osgi.http.whiteboard.servlet.name=OpenID4VPRequest",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPRequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final long DEFAULT_POLL_TIMEOUT_MS = 60000; // 1 minute
    private static final int DEFAULT_TENANT_ID = -1234; // Super tenant
    private static final String TENANT_DOMAIN_PATTERN = "^[a-zA-Z0-9._-]+$";

    private transient VPRequestService vpRequestService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.vpRequestService = new VPRequestServiceImpl();
    }



    /**
     * Handle GET requests - Get request JWT or status.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request ID is required in path"));
            return;
        }

        // Parse path: /{requestId} or /{requestId}/status
        String[] pathParts = pathInfo.split("/");

        if (pathParts.length < 2) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Invalid path format"));
            return;
        }

        String requestId = pathParts[1];
        int tenantId = getTenantId(request);

        try {
            // Check if status endpoint
            if (pathParts.length >= 3 && "status".equals(pathParts[2])) {
                handleStatusRequest(request, response, requestId, tenantId);
            } else {
                handleRequestJwtRequest(response, requestId, tenantId);
            }
        } catch (VPAuthenticatorClientException e) {
            if (VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED.getCode().equals(e.getCode())) {
                sendErrorResponse(response, HttpServletResponse.SC_GONE, e);
            } else {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, e);
            }
        } catch (VPAuthenticatorException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Internal server error", e));
        }
    }

    /**
     * Handle request JWT retrieval (for request_uri flow).
     */
    private void handleRequestJwtRequest(HttpServletResponse response, String requestId,
            int tenantId) throws VPAuthenticatorException, IOException {

        String requestJwt = vpRequestService.getRequestJwt(requestId, tenantId);

        // For now, return as JSON. In production, this should return JWT format
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");

        writeResponse(response, requestJwt);
    }

    private void writeResponse(HttpServletResponse response, String content) throws IOException {
        response.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        response.getOutputStream().flush();
    }

    /**
     * Handle status polling request.
     *
     * @param request   HTTP request
     * @param response  HTTP response
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @throws VPAuthenticatorException If error occurs
     * @throws IOException              If error occurs
     */
    private void handleStatusRequest(HttpServletRequest request,
                                     HttpServletResponse response,
                                     String requestId, int tenantId)
            throws VPAuthenticatorException, IOException {

        // Get timeout parameter for long polling
        String timeoutParam = getParameter(request, "timeout");
        long timeout = DEFAULT_POLL_TIMEOUT_MS;
        if (StringUtils.isNotBlank(timeoutParam)
                && timeoutParam.matches("^[0-9]+$")) {
            try {
                timeout = Math.min(Long.parseLong(timeoutParam),
                        DEFAULT_POLL_TIMEOUT_MS);
            } catch (NumberFormatException e) {
                // Use default
            }
        }

        // Get request by ID to check status
        // Note: For true long-polling, this should use async servlets with
        // DeferredResult
        VPRequest statusDTO = pollForStatus(requestId, tenantId, timeout);

        sendJsonResponse(response, HttpServletResponse.SC_OK, statusDTO);
    }

    /**
     * Poll for status with timeout.
     * Note: This is a simplified polling implementation. For production,
     * consider using async servlets with DeferredResult pattern.
     * Uses LongPollingManager to handle status checks via both cache and
     * database.
     *
     * @param requestId Request ID
     * @param tenantId  Tenant ID
     * @param timeout   Polling timeout
     * @return VPRequestDTO with status
     * @throws VPAuthenticatorException If error occurs
     */
    private VPRequest pollForStatus(final String requestId,
                                    final int tenantId,
                                    final long timeout)
            throws VPAuthenticatorException {

        LongPollingManager pollingManager = LongPollingManager.getInstance();
        PollingResult result = pollingManager.waitForStatusChange(requestId, timeout, tenantId);

        VPRequest.Builder builder = new VPRequest.Builder()
                .requestId(requestId);

        org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult.ResultStatus status =
                result.getResultStatus();

        if (status == PollingResult.ResultStatus.SUBMITTED
                || status == PollingResult.ResultStatus.SUBMITTED_WITH_ERROR) {
            String statusStr = result.getStatus();
            if (VPRequestStatus.COMPLETED.name().equals(statusStr)) {
                builder.status(VPRequestStatus.COMPLETED);
            } else {
                builder.status(VPRequestStatus.VP_SUBMITTED);
            }
        } else if (status == PollingResult.ResultStatus.EXPIRED) {
            builder.status(VPRequestStatus.EXPIRED);
        } else {
            builder.status(VPRequestStatus.ACTIVE);
        }

        return builder.build();
    }

    /**
     * Send JSON response.
     */
    private void sendJsonResponse(HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");

        writeResponse(response, gson.toJson(data));
    }

    /**
     * Send error response.
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

    private int getTenantId(HttpServletRequest request) {

        String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
        if (StringUtils.isBlank(tenantDomain)) {
            Object tenantDomainAttribute = request.getAttribute("tenantDomain");
            tenantDomain = tenantDomainAttribute instanceof String ? (String) tenantDomainAttribute : null;
        }

        if (StringUtils.isNotBlank(tenantDomain)
                && tenantDomain.matches(TENANT_DOMAIN_PATTERN)) {
            try {
                return org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);
            } catch (Exception e) {
                // Ignore.
            }
        }

        return DEFAULT_TENANT_ID;
    }

    /**
     * Read and sanitize a request parameter.
     *
     * @param request HTTP request.
     * @param name    Parameter name.
     * @return Sanitized parameter value, or null.
     */
    private String getParameter(final HttpServletRequest request, final String name) {

        if (request == null || StringUtils.isBlank(name)) {
            return null;
        }

        String value = request.getParameter(name);
        if (StringUtils.isBlank(value)) {
            return null;
        }

        return Encode.forJava(sanitizeParam(value));
    }

    /**
     * Strip CRLF/control characters from request parameter input.
     *
     * @param value Request parameter value.
     * @return Sanitized parameter value.
     */
    private String sanitizeParam(final String value) {

        if (value == null) {
            return null;
        }
        return value.replace('\r', '_').replace('\n', '_').replaceAll("[\\p{Cntrl}]", "");
    }
}
