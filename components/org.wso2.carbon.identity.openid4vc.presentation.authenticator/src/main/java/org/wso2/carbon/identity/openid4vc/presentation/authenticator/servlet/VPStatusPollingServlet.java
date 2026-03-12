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
import com.google.gson.JsonObject;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPStatusResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for VP request status polling with long polling support.
 * 
 * Endpoint: GET /vp-request/{requestId}/status
 * 
 * Query Parameters:
 * - timeout: Long polling timeout in seconds (optional, default: 60, max: 120)
 * 
 * Supports both synchronous and asynchronous (long polling) modes.
 */
public class VPStatusPollingServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    /**
     * Default tenant ID.
     */
    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * Default polling timeout in seconds.
     */
    private static final long DEFAULT_TIMEOUT_SECONDS = 5L;

    /**
     * Maximum polling timeout in seconds.
     */
    private static final long MAX_TIMEOUT_SECONDS = 120L;

    /**
     * Parameter name for timeout.
     */
    private static final String PARAM_TIMEOUT = "timeout";

    /**
     * Parameter name for long polling enablement.
     */
    private static final String PARAM_LONG_POLL = "long_poll";

    /**
     * Long polling manager instance.
     */
    private transient LongPollingManager pollingManager;

    @Override
    public void init() throws ServletException {

        super.init();
        this.pollingManager = LongPollingManager.getInstance();
    }

    /**
     * Handle GET requests for status polling.
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @throws ServletException If servlet error occurs
     * @throws IOException      If I/O error occurs
     */
    @Override
    @SuppressFBWarnings({ "SERVLET_HEADER", "SERVLET_PARAMETER", "XSS_SERVLET" })
    protected void doGet(final HttpServletRequest request,
            final HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON
                + "; charset=UTF-8");

        try {
            // Extract request ID from path
            String requestId = extractRequestId(request);

            if (StringUtils.isBlank(requestId)) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        OpenID4VPConstants.ErrorCodes.INVALID_REQUEST,
                        "Missing request ID");
                return;
            }

            // Check if long polling is enabled
            boolean enableLongPoll = ServletUtil.isLongPollingEnabled(request);

            // Get timeout parameter
            long timeoutSeconds = ServletUtil.getTimeoutSeconds(request);
            long timeoutMs = timeoutSeconds * 1000L;

            // Get tenant ID
            int tenantId = ServletUtil.getTenantId(request);

            if (enableLongPoll) {
                // Use async processing for long polling
                handleLongPoll(request, response, requestId, timeoutMs, tenantId);
            } else {
                // Immediate status check
                handleImmediateStatus(response, requestId, tenantId);
            }

        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    OpenID4VPConstants.ErrorCodes.SERVER_ERROR,
                    "Internal server error");
        }
    }

    /**
     * Handle long polling request.
     */
    private void handleLongPoll(final HttpServletRequest request,
            final HttpServletResponse response,
            final String requestId,
            final long timeoutMs,
            final int tenantId) throws IOException {

        // Use synchronous long polling (blocks the thread)
        // This approach works with Servlet 2.x and 3.x
        PollingResult result = pollingManager.waitForStatusChange(
                requestId, timeoutMs, tenantId);

        // Build and send response
        VPStatusResponseDTO statusDTO = buildStatusResponse(result, requestId);
        sendSuccessResponse(response, statusDTO);
    }

    /**
     * Handle immediate status check.
     */
    private void handleImmediateStatus(final HttpServletResponse response,
            final String requestId,
            final int tenantId) throws IOException {

        PollingResult result = pollingManager.checkCurrentStatus(requestId, tenantId);
        VPStatusResponseDTO statusDTO = buildStatusResponse(result, requestId);
        sendSuccessResponse(response, statusDTO);
    }

    /**
     * Build status response from polling result.
     */
    private VPStatusResponseDTO buildStatusResponse(final PollingResult result,
            final String requestId) {

        VPStatusResponseDTO.Builder builder = new VPStatusResponseDTO.Builder()
                .requestId(requestId);

        switch (result.getResultStatus()) {
            case SUBMITTED:
                builder.status("VP_SUBMITTED")
                        .tokenReceived(true)
                        .expired(false);
                break;

            case SUBMITTED_WITH_ERROR:
                builder.status("VP_SUBMITTED")
                        .tokenReceived(true)
                        .expired(false)
                        .error("wallet_error")
                        .errorDescription("Wallet returned an error");
                break;

            case EXPIRED:
                builder.status("EXPIRED")
                        .tokenReceived(false)
                        .expired(true);
                break;

            case NOT_FOUND:
                builder.status("NOT_FOUND")
                        .tokenReceived(false)
                        .expired(false)
                        .error("not_found")
                        .errorDescription("Request not found");
                break;

            case TIMEOUT:

            case ERROR:
                builder.status("ERROR")
                        .tokenReceived(false)
                        .error("error")
                        .errorDescription(result.getErrorMessage());
                break;

            case WAITING:
            default:
                builder.status("ACTIVE")
                        .tokenReceived(false)
                        .expired(false);
                break;
        }

        return builder.build();
    }

    /**
     * Extract request ID from path.
     * Expected path: /vp-request/{requestId}/status
     */
    @SuppressFBWarnings("SERVLET_PARAMETER")
    private String extractRequestId(final HttpServletRequest request) {

        String pathInfo = request.getPathInfo();
        if (StringUtils.isBlank(pathInfo)) {
            @SuppressFBWarnings("SERVLET_PARAMETER")
            String requestId = request.getParameter("request_id");
            return requestId;
        }

        // Remove leading slash
        if (pathInfo.startsWith("/")) {
            pathInfo = pathInfo.substring(1);
        }

        // Remove trailing /status if present
        if (pathInfo.endsWith("/status")) {
            pathInfo = pathInfo.substring(0, pathInfo.length() - 7);
        }

        // The remaining should be the request ID
        if (!pathInfo.isEmpty() && !pathInfo.contains("/")) {
            return pathInfo;
        }

        // Fallback to query parameter
        return request.getParameter("request_id");
    }

    /**
     * Send success response.
     */
    private void sendSuccessResponse(final HttpServletResponse response,
            final VPStatusResponseDTO statusDTO)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(statusDTO.toJson()));
        }
    }

    @SuppressFBWarnings("XSS_SERVLET")
    private void writeResponse(PrintWriter writer, String content) {
        writer.write(content);
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(final HttpServletResponse response,
            final int statusCode,
            final String errorCode,
            final String errorDescription)
            throws IOException {

        response.setStatus(statusCode);

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty("error", errorCode);
        if (StringUtils.isNotBlank(errorDescription)) {
            errorObj.addProperty("error_description", errorDescription);
        }

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(errorObj));
        }
    }
}
