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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.ErrorDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request
 * operations.
 * 
 * Endpoints:
 * - POST /api/identity/openid4vp/v1/vp-request - Create a new VP authorization
 * request
 * - GET /api/identity/openid4vp/v1/vp-request/{requestId} - Get authorization
 * request JWT
 * - GET /api/identity/openid4vp/v1/vp-request/{requestId}/status - Get request
 * status (with polling)
 */
public class VPRequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final long DEFAULT_POLL_TIMEOUT_MS = 60000; // 1 minute
    private static final int DEFAULT_TENANT_ID = -1234; // Super tenant

    private transient VPRequestService vpRequestService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.vpRequestService = new VPRequestServiceImpl();
    }

    /**
     * Handle POST requests - Create VP authorization request.
     */
    @Override

    @SuppressFBWarnings({ "SERVLET_HEADER", "SERVLET_PARAMETER", "XSS_SERVLET" })
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Read request body
            String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);

            if (StringUtils.isBlank(requestBody)) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "Request body is required");
                return;
            }

            // Parse request DTO
            VPRequestCreateDTO createDTO;
            try {
                createDTO = gson.fromJson(requestBody, VPRequestCreateDTO.class);
            } catch (com.google.gson.JsonSyntaxException e) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "Invalid JSON format: " + e.getMessage());
                return;
            }

            // Validate required fields
            if (StringUtils.isBlank(createDTO.getClientId())) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        ErrorDTO.ErrorCode.INVALID_REQUEST, "client_id is required");
                return;
            }

            // Get tenant ID from request context (simplified for now)
            int tenantId = getTenantId(request);

            // Create VP request
            VPRequestResponseDTO responseDTO = vpRequestService.createVPRequest(createDTO, tenantId);

            // Send success response
            sendJsonResponse(response, HttpServletResponse.SC_CREATED, responseDTO);

        } catch (VPException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle GET requests - Get request JWT or status.
     */
    @Override

    @SuppressFBWarnings({ "SERVLET_HEADER", "SERVLET_PARAMETER", "XSS_SERVLET" })
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Request ID is required in path");
            return;
        }

        // Parse path: /{requestId} or /{requestId}/status
        String[] pathParts = pathInfo.split("/");

        if (pathParts.length < 2) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Invalid path format");
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
        } catch (VPRequestNotFoundException e) {
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.VP_REQUEST_NOT_FOUND, e.getMessage());
        } catch (VPRequestExpiredException e) {
            sendErrorResponse(response, HttpServletResponse.SC_GONE,
                    ErrorDTO.ErrorCode.VP_REQUEST_EXPIRED, e.getMessage());
        } catch (VPException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle request JWT retrieval (for request_uri flow).
     */
    private void handleRequestJwtRequest(HttpServletResponse response, String requestId,
            int tenantId) throws VPException, IOException {

        String requestJwt = vpRequestService.getRequestJwt(requestId, tenantId);

        // For now, return as JSON. In production, this should return JWT format
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, requestJwt);
        }
    }

    @SuppressFBWarnings("XSS_SERVLET")
    private void writeResponse(PrintWriter writer, String content) {
        writer.write(content);
    }

    /**
     * Handle status polling request.
     */
    @SuppressFBWarnings("SERVLET_PARAMETER")
    private void handleStatusRequest(HttpServletRequest request, HttpServletResponse response,
            String requestId, int tenantId) throws VPException, IOException {

        // Get timeout parameter for long polling
        @SuppressFBWarnings("SERVLET_PARAMETER")
        String timeoutParam = request.getParameter("timeout");
        long timeout = DEFAULT_POLL_TIMEOUT_MS;
        if (StringUtils.isNotBlank(timeoutParam)) {
            try {
                timeout = Math.min(Long.parseLong(timeoutParam), DEFAULT_POLL_TIMEOUT_MS);
            } catch (NumberFormatException e) {
                // Use default
            }
        }

        // Get request by ID to check status
        // Note: For true long-polling, this should use async servlets with
        // DeferredResult
        VPRequestStatusDTO statusDTO = pollForStatus(requestId, tenantId, timeout);

        sendJsonResponse(response, HttpServletResponse.SC_OK, statusDTO);
    }

    /**
     * Poll for status with timeout.
     * Note: This is a simplified polling implementation. For production,
     * consider using async servlets with DeferredResult pattern.
     * Uses LongPollingManager to handle status checks via both cache and database.
     *
     * @param requestId Request ID
     * @param tenantId Tenant ID
     * @param timeout Polling timeout
     * @return VPRequestStatusDTO with status
     * @throws VPException If error occurs
     */
    private VPRequestStatusDTO pollForStatus(final String requestId, final int tenantId, final long timeout)
            throws VPException {

        LongPollingManager pollingManager = LongPollingManager.getInstance();
        PollingResult result = pollingManager.waitForStatusChange(requestId, timeout, tenantId);

        VPRequestStatusDTO statusDTO = new VPRequestStatusDTO();
        statusDTO.setRequestId(requestId);

        org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult.ResultStatus status =
                result.getResultStatus();

        if (status == PollingResult.ResultStatus.SUBMITTED
                || status == PollingResult.ResultStatus.SUBMITTED_WITH_ERROR) {
            // Determine likely status from result string or default to VP_SUBMITTED
            // LongPollingManager returns SUBMITTED for both VP_SUBMITTED and COMPLETED
            String statusStr = result.getStatus();
            if (VPRequestStatus.COMPLETED.name().equals(statusStr)) {
                statusDTO.setStatus(VPRequestStatus.COMPLETED);
            } else {
                statusDTO.setStatus(VPRequestStatus.VP_SUBMITTED);
            }
        } else if (status == PollingResult.ResultStatus.EXPIRED) {
            statusDTO.setStatus(VPRequestStatus.EXPIRED);
        } else {
            statusDTO.setStatus(VPRequestStatus.ACTIVE);
        }

        return statusDTO;
    }

    /**
     * Send JSON response.
     */
    private void sendJsonResponse(HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, gson.toJson(data));
        }
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode,
            ErrorDTO.ErrorCode errorCode, String message)
            throws IOException {

        ErrorDTO errorDTO = new ErrorDTO(errorCode, message, null);
        sendJsonResponse(response, statusCode, errorDTO);
    }

    /**
     * Get tenant ID from request.
     * In production, this should extract from authentication context.
     */
    @SuppressFBWarnings("SERVLET_HEADER")
    private int getTenantId(HttpServletRequest request) {
        return org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil.getTenantId(request);
    }
}
