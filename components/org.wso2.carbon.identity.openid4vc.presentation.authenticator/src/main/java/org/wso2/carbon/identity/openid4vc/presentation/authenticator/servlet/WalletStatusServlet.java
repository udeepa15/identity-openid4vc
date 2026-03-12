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

import com.google.gson.JsonObject;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.PollingResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to check if VP token has been received for polling from the login
 * page.
 * Supports both immediate status check and long polling.
 */
public class WalletStatusServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_TIMEOUT = "timeout";
    private static final String PARAM_LONG_POLL = "long_poll";

    // Log prefix for easy filtering

    /**
     * Default tenant ID.
     */
    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * Default long polling timeout in seconds.
     */
    private static final long DEFAULT_TIMEOUT_SECONDS = 60L;

    /**
     * Maximum timeout in seconds.
     */
    private static final long MAX_TIMEOUT_SECONDS = 120L;

    /**
     * Long polling manager.
     */
    private transient LongPollingManager pollingManager;

    @Override
    public void init() throws ServletException {

        super.init();
        this.pollingManager = LongPollingManager.getInstance();
    }

    @Override
    @SuppressFBWarnings({ "SERVLET_PARAMETER", "XSS_SERVLET" })
    protected void doGet(final HttpServletRequest request,
            final HttpServletResponse response) throws IOException {

        response.setContentType(CONTENT_TYPE_JSON + "; charset=UTF-8");

        try {
            String state = request.getParameter(PARAM_STATE);

            if (StringUtils.isBlank(state)) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "Missing required parameter: state");
                return;
            }

            // Check if long polling is requested
            boolean enableLongPoll = ServletUtil.isLongPollingEnabled(request);

            if (enableLongPoll) {
                // Use long polling
                handleLongPoll(request, response, state);
            } else {
                // Immediate status check
                handleImmediateStatus(response, state);
            }

        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
    }

    /**
     * Handle immediate status check (existing behavior).
     */
    private void handleImmediateStatus(final HttpServletResponse response,
            final String state) throws IOException {

        // Check if token exists in cache (without removing it)
        boolean tokenReceived = WalletDataCache.getInstance().hasToken(state);

        // Also check submission cache
        if (!tokenReceived) {
            tokenReceived = WalletDataCache.getInstance().hasSubmission(state);
        }

        // DB FALLBACK: If not in cache, check the database status
        // The 'state' parameter corresponds to the Request ID
        if (!tokenReceived) {
            try {
                VPRequestService requestService = VPServiceDataHolder.getInstance().getVPRequestService();
                if (requestService != null) {

                    VPRequest vpRequest = requestService.getVPRequestById(state, DEFAULT_TENANT_ID);
                    if (vpRequest != null) {

                        if (vpRequest.getStatus() == VPRequestStatus.VP_SUBMITTED ||
                                vpRequest.getStatus() == VPRequestStatus.COMPLETED) {
                            tokenReceived = true;

                        }

                    }
                }
            } catch (VPException | RuntimeException e) {
                // Log but don't fail the request, just treat as not received
            }
        }

        sendStatusResponse(response, tokenReceived, "ACTIVE");
    }

    /**
     * Handle long polling request.
     */
    private void handleLongPoll(final HttpServletRequest request,
            final HttpServletResponse response,
            final String state) throws IOException {

        long timeoutSeconds = ServletUtil.getTimeoutSeconds(request);
        long timeoutMs = timeoutSeconds * 1000L;
        int tenantId = ServletUtil.getTenantId(request);

        // Use synchronous long poll (blocking)
        handleSyncLongPoll(response, state, timeoutMs, tenantId);
    }

    /**
     * Handle synchronous long polling.
     */
    private void handleSyncLongPoll(final HttpServletResponse response,
            final String state,
            final long timeoutMs,
            final int tenantId) throws IOException {

        // Wait for status change
        PollingResult result = pollingManager.waitForStatusChange(state, timeoutMs, tenantId);

        // Send response based on result
        sendPollingResultResponse(response, result);
    }

    /**
     * Send response based on polling result.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendPollingResultResponse(final HttpServletResponse response,
            final PollingResult result) throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "success");

        boolean tokenReceived = result.isTokenReceived();
        String statusStr = result.getStatus() != null ? result.getStatus() : "ACTIVE";

        jsonResponse.addProperty("tokenReceived", tokenReceived);
        jsonResponse.addProperty("vpStatus", statusStr);

        if (result.isExpired()) {
            jsonResponse.addProperty("expired", true);
        }

        if (result.isTimeout()) {
            jsonResponse.addProperty("timeout", true);
        }

        if (result.hasWalletError()) {
            jsonResponse.addProperty("walletError", true);
        }

        try (PrintWriter out = response.getWriter()) {
            out.print(jsonResponse.toString());
            out.flush();
        }
    }

    /**
     * Send status response.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendStatusResponse(final HttpServletResponse response,
            final boolean tokenReceived,
            final String vpStatus)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "success");
        jsonResponse.addProperty("tokenReceived", tokenReceived);
        jsonResponse.addProperty("vpStatus", vpStatus);

        try (PrintWriter out = response.getWriter()) {
            writeResponse(out, jsonResponse.toString());
            out.flush();
        }
    }

    /**
     * Send error JSON response.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendErrorResponse(final HttpServletResponse response,
            final int statusCode,
            final String message)
            throws IOException {

        response.setStatus(statusCode);

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("status", "error");
        jsonResponse.addProperty("message", message);

        try (PrintWriter out = response.getWriter()) {
            writeResponse(out, jsonResponse.toString());
            out.flush();
        }
    }

    @SuppressFBWarnings("XSS_SERVLET")
    private void writeResponse(PrintWriter writer, String content) {
        writer.print(content);
    }
}
