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
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl.VCVerificationServiceImpl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for Verifiable Credential verification endpoints.
 * 
 * Endpoints:
 * - POST /vc-verification - Verify a single Verifiable Credential
 * - POST /vp-verification - Verify a Verifiable Presentation (VP token)
 * 
 * Content-Types supported:
 * - application/vc+ld+json (JSON-LD VC)
 * - application/jwt or application/vc+jwt (JWT VC)
 * - application/vc+sd-jwt (SD-JWT VC)
 * - application/json (auto-detect format)
 */

@SuppressFBWarnings({ "MSF_MUTABLE_SERVLET_FIELD", "MTIA_SUSPECT_SERVLET_INSTANCE_FIELD" })
public class VCVerificationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private static final String CONTENT_TYPE_JSON = "application/json";

    private transient VCVerificationService verificationService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.verificationService = new VCVerificationServiceImpl();
    }

    /**
     * Set the verification service (for testing).
     *
     * @param verificationService The verification service
     */
    public void setVerificationService(VCVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @Override
    @SuppressFBWarnings({ "RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE", "SERVLET_CONTENT_TYPE" })
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        if (pathInfo == null) {
            pathInfo = request.getServletPath();
        }

        try {
            // Read request body
            String requestBody = readRequestBody(request);
            if (requestBody == null || requestBody.trim().isEmpty()) {
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "invalid_request", "Request body is empty");
                return;
            }

            // Get content type
            String contentType = request.getContentType();
            if (contentType == null) {
                contentType = CONTENT_TYPE_JSON;
            }

            // Route to appropriate handler
            if (pathInfo != null && pathInfo.contains("vp-verification")) {
                handleVPVerification(request, response, requestBody, contentType);
            } else {
                handleVCVerification(request, response, requestBody, contentType);
            }

        } catch (Exception e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "server_error", "Internal server error: " + e.getMessage());
        }
    }

    /**
     * Handle single VC verification.
     */
    private void handleVCVerification(HttpServletRequest request, HttpServletResponse response,
            String requestBody, String contentType)
            throws IOException {

        try {
            // Check if content type is supported
            if (!verificationService.isContentTypeSupported(contentType)) {
                sendErrorResponse(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
                        "unsupported_media_type",
                        "Content-Type not supported. Supported types: " +
                                String.join(", ", verificationService.getSupportedContentTypes()));
                return;
            }

            // Verify the credential
            VCVerificationResultDTO result = verificationService.verify(requestBody, contentType);

            // Send response
            sendVerificationResponse(response, result);

        } catch (CredentialVerificationException e) {
            VCVerificationResultDTO result = new VCVerificationResultDTO(
                    0, e.getVerificationStatus() != null ? e.getVerificationStatus() : VCVerificationStatus.INVALID,
                    e.getMessage());
            sendVerificationResponse(response, result);
        }
    }

    /**
     * Handle VP (Verifiable Presentation) verification.
     */
    private void handleVPVerification(HttpServletRequest request, HttpServletResponse response,
            String requestBody, String contentType)
            throws IOException {

        try {
            // VP verification
            List<VCVerificationResultDTO> results = verificationService.verifyVPToken(requestBody);

            // Send response
            sendVPVerificationResponse(response, results);

        } catch (CredentialVerificationException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "verification_failed", e.getMessage());
        }
    }

    /**
     * Send VC verification response.
     */
    private void sendVerificationResponse(HttpServletResponse response,
            VCVerificationResultDTO result)
            throws IOException {

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("verificationStatus", result.getVerificationStatus());

        if (result.isSuccess()) {
            if (result.getCredentialType() != null) {
                jsonResponse.addProperty("credentialType", result.getCredentialType());
            }
            if (result.getIssuer() != null) {
                jsonResponse.addProperty("issuer", result.getIssuer());
            }
        } else {
            if (result.getError() != null) {
                jsonResponse.addProperty("error", result.getError());
            }
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(jsonResponse));
        }
    }

    /**
     * Send response safely.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void writeResponse(PrintWriter writer, String content) {
        writer.print(content);
    }

    /**
     * Send VP verification response (multiple credentials).
     */
    private void sendVPVerificationResponse(HttpServletResponse response,
            List<VCVerificationResultDTO> results)
            throws IOException {

        JsonObject jsonResponse = new JsonObject();

        // Determine overall status
        boolean allSuccess = true;
        for (VCVerificationResultDTO result : results) {
            if (!result.isSuccess()) {
                allSuccess = false;
                break;
            }
        }

        jsonResponse.addProperty("overallStatus", allSuccess ? "SUCCESS" : "FAILED");
        jsonResponse.addProperty("credentialCount", results.size());

        // Add individual results
        com.google.gson.JsonArray vcResults = new com.google.gson.JsonArray();
        for (VCVerificationResultDTO result : results) {
            JsonObject vcResult = new JsonObject();
            vcResult.addProperty("vcIndex", result.getVcIndex());
            vcResult.addProperty("verificationStatus", result.getVerificationStatus());

            if (result.isSuccess()) {
                if (result.getCredentialType() != null) {
                    vcResult.addProperty("credentialType", result.getCredentialType());
                }
                if (result.getIssuer() != null) {
                    vcResult.addProperty("issuer", result.getIssuer());
                }
            } else {
                if (result.getError() != null) {
                    vcResult.addProperty("error", result.getError());
                }
            }

            vcResults.add(vcResult);
        }
        jsonResponse.add("vcVerificationResults", vcResults);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(jsonResponse));
        }
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletResponse response, int status,
            String error, String errorDescription)
            throws IOException {

        JsonObject jsonResponse = new JsonObject();
        jsonResponse.addProperty("error", error);
        jsonResponse.addProperty("error_description", errorDescription);

        response.setStatus(status);
        response.setContentType(CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(jsonResponse));
        }
    }

    /**
     * Read the request body.
     */
    private String readRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        // GET /vc-verification/supported-formats - List supported formats
        if (pathInfo != null && pathInfo.contains("supported-formats")) {
            handleGetSupportedFormats(response);
            return;
        }

        // GET not supported for verification
        sendErrorResponse(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                "method_not_allowed", "Use POST method for verification");
    }

    /**
     * Handle GET request for supported formats.
     */
    private void handleGetSupportedFormats(HttpServletResponse response) throws IOException {
        JsonObject jsonResponse = new JsonObject();

        com.google.gson.JsonArray formats = new com.google.gson.JsonArray();
        for (String format : verificationService.getSupportedContentTypes()) {
            formats.add(format);
        }
        jsonResponse.add("supportedContentTypes", formats);

        com.google.gson.JsonArray vcFormats = new com.google.gson.JsonArray();
        vcFormats.add(OpenID4VPConstants.VCFormats.JWT_VC);
        vcFormats.add(OpenID4VPConstants.VCFormats.JWT_VC_JSON);
        vcFormats.add(OpenID4VPConstants.VCFormats.LDP_VC);
        vcFormats.add(OpenID4VPConstants.VCFormats.VC_SD_JWT);
        jsonResponse.add("supportedVCFormats", vcFormats);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(CONTENT_TYPE_JSON + ";charset=UTF-8");

        try (PrintWriter writer = response.getWriter()) {
            writeResponse(writer, GSON.toJson(jsonResponse));
        }
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // CORS preflight handling
        response.setHeader("Allow", "POST, GET, OPTIONS");
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
