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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.CORSUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.impl.PresentationDefinitionServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for managing Presentation Definitions and Application Mappings.
 *
 * Presentation Definition Endpoints:
 * - GET /openid4vp/v1/presentation-definitions - List all definitions
 * - GET /openid4vp/v1/presentation-definitions/{id} - Get specific definition
 * - POST /openid4vp/v1/presentation-definitions - Create new definition
 * - PUT /openid4vp/v1/presentation-definitions/{id} - Update definition
 * - DELETE /openid4vp/v1/presentation-definitions/{id} - Delete definition
 *
 * Application Mapping Endpoints:
 * - GET /openid4vp/v1/presentation-definitions/mapping/{applicationId} - Get
 * mapping for application
 * - POST /openid4vp/v1/presentation-definitions/mapping - Create/update
 * application mapping
 * - DELETE /openid4vp/v1/presentation-definitions/mapping/{applicationId} -
 * Delete application mapping
 */
public class VPDefinitionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private static final int DEFAULT_TENANT_ID = -1234;

    private transient PresentationDefinitionService presentationDefinitionService;
    @Override
    public void init() throws ServletException {
        super.init();
        this.presentationDefinitionService = new PresentationDefinitionServiceImpl();
    }

    /**
     * Handle GET requests - List or get presentation definitions, or get
     * application mappings.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();
        if (pathInfo == null) {
            pathInfo = "";
        }
        int tenantId = getTenantId(request);

        try {
            if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
                // List all definitions

                handleListDefinitions(request, response, tenantId);
            } else {
                String[] parts = pathInfo.split("/");
                if (parts.length >= 3 && "claims".equals(parts[2])) {
                    String definitionId = parts[1];
                    handleGetClaims(request, response, definitionId, tenantId);
                } else {
                    // Get specific definition
                    String definitionId = pathInfo.substring(1);
                    if (definitionId.contains("/")) {
                        definitionId = definitionId.split("/")[0];
                    }

                    handleGetDefinition(request, response, definitionId, tenantId);
                }
            }
        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle POST requests - Create new presentation definition.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);
            PresentationDefinitionRequest createRequest = gson.fromJson(requestBody,
                    PresentationDefinitionRequest.class);

            int tenantId = getTenantId(request);


            // Build definition (requestedCredentials are empty for this legacy path — callers
            // should use the /api/server/v1/vp/template endpoint to set credentials properly)
            PresentationDefinition definition = new PresentationDefinition.Builder()
                    .name(createRequest.getName())
                    .description(createRequest.getDescription())
                    .tenantId(tenantId)
                    .build();

            // Create
            PresentationDefinition created = presentationDefinitionService
                    .createPresentationDefinition(definition, tenantId);

            // Send response
            sendJsonResponse(request, response, HttpServletResponse.SC_CREATED, toResponseDTO(created));

        } catch (VPException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle PUT requests - Update presentation definition.
     */
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, "Definition ID is required");
            return;
        }

        String definitionId = pathInfo.substring(1);
        if (definitionId.contains("/")) {
            definitionId = definitionId.split("/")[0];
        }

        try {
            String requestBody = IOUtils.toString(request.getInputStream(), StandardCharsets.UTF_8);

            PresentationDefinitionRequest updateRequest = gson.fromJson(requestBody,
                    PresentationDefinitionRequest.class);

            int tenantId = getTenantId(request);

            // Build updated definition
            PresentationDefinition definition = new PresentationDefinition.Builder()
                    .definitionId(definitionId)
                    .name(updateRequest.getName())
                    .description(updateRequest.getDescription())
                    .tenantId(tenantId)
                    .build();

            // Update
            PresentationDefinition updated = presentationDefinitionService
                    .updatePresentationDefinition(definition, tenantId);

            // Send response
            sendJsonResponse(request, response, HttpServletResponse.SC_OK, toResponseDTO(updated));

        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorDTO.ErrorCode.INTERNAL_ERROR, "Internal server error");
        }
    }

    /**
     * Handle DELETE requests - Disabled.
     * Definitions are deleted automatically when a Digital Credentials connection is deleted.
     */
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        sendErrorResponse(request, response, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                ErrorDTO.ErrorCode.INVALID_REQUEST,
                "Definitions are deleted automatically when connections are deleted.");
    }

    /**
     * Handle list all definitions.
     */
    private void handleListDefinitions(HttpServletRequest request, HttpServletResponse response, int tenantId)
            throws VPException, IOException {

        List<PresentationDefinition> definitions = presentationDefinitionService
                .getAllPresentationDefinitions(tenantId);

        List<PresentationDefinitionResponseDTO> responseDTOs = definitions.stream()
                .map(this::toResponseDTO)
                .collect(java.util.stream.Collectors.toList());

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, responseDTOs);
    }

    /**
     * Handle get specific definition.
     */
    private void handleGetDefinition(HttpServletRequest request, HttpServletResponse response, String definitionId,
            int tenantId) throws VPException, IOException {

        PresentationDefinition definition = presentationDefinitionService.getPresentationDefinitionById(definitionId,
                tenantId);

        sendJsonResponse(request, response, HttpServletResponse.SC_OK, toResponseDTO(definition));
    }

    /**
     * Handle get claims from presentation definition.
     */
    private void handleGetClaims(HttpServletRequest request, HttpServletResponse response, String definitionId,
                                 int tenantId) throws IOException {

        try {
            List<PresentationDefinitionService.InputDescriptorClaimsDTO> claims = presentationDefinitionService
                    .getClaimsFromPresentationDefinition(definitionId, tenantId);
            sendJsonResponse(request, response, HttpServletResponse.SC_OK, claims);
        } catch (PresentationDefinitionNotFoundException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND,
                    ErrorDTO.ErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, e.getMessage());
        } catch (VPException e) {
            sendErrorResponse(request, response, HttpServletResponse.SC_BAD_REQUEST,
                    ErrorDTO.ErrorCode.INVALID_REQUEST, e.getMessage());
        }
    }


    /**
     * Convert model to response DTO.
     */
    private PresentationDefinitionResponseDTO toResponseDTO(PresentationDefinition definition) {
        PresentationDefinitionResponseDTO dto = new PresentationDefinitionResponseDTO();
        dto.setDefinitionId(definition.getDefinitionId());
        dto.setName(definition.getName());
        dto.setDescription(definition.getDescription());
        String pdJson = PresentationDefinitionUtil.buildDefinitionJson(definition);
        if (org.apache.commons.lang.StringUtils.isNotBlank(pdJson) && !"{}".equals(pdJson)) {
            try {
                dto.setDefinition(gson.fromJson(pdJson, Object.class));
            } catch (Exception e) {
                dto.setDefinition(pdJson);
            }
        }
        return dto;
    }

    /**
     * Handle OPTIONS requests for CORS preflight.
     */
    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        CORSUtil.handlePreflight(request, response);
    }

    /**
     * Send JSON response.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendJsonResponse(HttpServletRequest request, HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + ";charset=UTF-8");
        CORSUtil.addCORSHeaders(request, response);

        try (PrintWriter writer = response.getWriter()) {
            writer.write(gson.toJson(data));
        }
    }

    /**
     * Send error response.
     */
    @SuppressFBWarnings("XSS_SERVLET")
    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response, int statusCode,
            ErrorDTO.ErrorCode errorCode, String message)
            throws IOException {

        ErrorDTO errorDTO = new ErrorDTO(errorCode, message, null);
        sendJsonResponse(request, response, statusCode, errorDTO);
    }

    /**
     * Get tenant ID from request.
     */
    @SuppressFBWarnings("SERVLET_HEADER")
    private int getTenantId(HttpServletRequest request) {
        return org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletUtil.getTenantId(request);
    }

    /**
     * Request DTO for creating/updating presentation definitions.
     */
    @SuppressFBWarnings({"URF_UNREAD_FIELD", "UWF_UNWRITTEN_FIELD"})
    private static class PresentationDefinitionRequest {

        private String definitionId;
        private String name;
        private String description;
        private String definitionJson;
        private Object definition;

        public String getDefinitionId() {
            return definitionId;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }

        public String getDefinitionJson() {
            return definitionJson;
        }

        public Object getDefinition() {
            return definition;
        }
    }

    /**
     * Response DTO for presentation definitions.
     * Fields are accessed by Gson via reflection during JSON serialization;
     * SpotBugs URF_UNREAD_FIELD / UWF_UNWRITTEN_FIELD warnings are suppressed accordingly.
     */
    @SuppressFBWarnings({"URF_UNREAD_FIELD", "UWF_UNWRITTEN_FIELD"})
    private static class PresentationDefinitionResponseDTO {

        private String definitionId;
        private String name;
        private String description;
        private Object definition;

        public void setDefinitionId(String definitionId) {
            this.definitionId = definitionId;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public void setDefinition(Object definition) {
            this.definition = definition;
        }
    }
}
