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
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.ErrorDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestExpiredException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPRequestNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for handling OpenID4VP request_uri endpoint.
 * 
 * This endpoint is called by wallet applications to retrieve the authorization
 * request
 * object (containing the presentation definition) when using the request_uri
 * flow.
 * 
 * According to OpenID4VP spec, this endpoint must return the authorization
 * request
 * as a JWT or JSON object.
 * 
 * Path: /openid4vp/v1/request-uri/{requestId}
 * Method: GET
 * Response: application/jwt or application/json
 */
public class RequestUriServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final int DEFAULT_TENANT_ID = -1234; // Super tenant

    private transient VPRequestService vpRequestService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.vpRequestService = new VPRequestServiceImpl();
    }

    /**
     * Handle GET requests to retrieve the authorization request object.
     * 
     * Path pattern: /request-uri/{requestId}
     * 
     * According to OpenID4VP spec
     * (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html):
     * - The response MUST be an authorization request object
     * - Can be returned as JWT (application/oauth-authz-req+jwt) or JSON
     * (application/json)
     * - Must include presentation_definition or presentation_definition_uri
     */
    @Override
    @SuppressFBWarnings({ "XSS_SERVLET", "SERVLET_HEADER", "SERVLET_PARAMETER", "SERVLET_CONTENT_TYPE" })
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        // Validate path
        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Request ID is required in path");
            return;
        }

        // Extract request ID from path: /{requestId}
        String requestId = pathInfo.substring(1); // Remove leading slash

        if (StringUtils.isBlank(requestId)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Request ID cannot be empty");
            return;
        }

        // Get tenant ID from request context
        int tenantId = getTenantId(request);

        try {

            // Get the request JWT/object from service
            String authzRequest = vpRequestService.getRequestJwt(requestId, tenantId);

            if (StringUtils.isBlank(authzRequest)) {
                sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        ErrorDTO.ErrorCode.INTERNAL_ERROR, "Failed to generate authorization request");
                return;
            }

            // According to OpenID4VP spec, return the authorization request
            // Content-Type should be:
            // - application/oauth-authz-req+jwt if JWT format
            // - application/json if JSON format

            // Check if it's a JWT (starts with "eyJ")
            if (authzRequest.startsWith("eyJ")) {
                response.setContentType("application/oauth-authz-req+jwt");
            } else {
                response.setContentType("application/json");
            }

            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");

            try (PrintWriter writer = response.getWriter()) {
                writer.write(authzRequest);
            }

        } catch (VPRequestNotFoundException e) {
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.VP_REQUEST_NOT_FOUND, "Request not found or has been consumed");
        } catch (VPRequestExpiredException e) {
            sendErrorResponse(response, HttpServletResponse.SC_GONE,
                    ErrorDTO.ErrorCode.VP_REQUEST_EXPIRED, "Request has expired");
        } catch (VPException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Get tenant ID from request context.
     */
    private int getTenantId(HttpServletRequest request) {
        return org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil.getTenantId(request);
    }

    /**
     * Send error response as JSON.
     */
    /**
     * Send error response as JSON.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendErrorResponse(HttpServletResponse response, int statusCode,
            ErrorDTO.ErrorCode errorCode, String errorDescription)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setError(errorCode.getError());
        errorDTO.setErrorDescription(errorDescription);

        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(errorDTO));
        }

    }
}
