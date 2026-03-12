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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.CORSUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDDocumentServiceImpl;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet handling the /.well-known/did.json endpoint.
 * Serves the DID Document for WSO2 Identity Server using did:web method.
 * 
 * Endpoint:
 * - GET /.well-known/did.json - Returns the DID Document
 * 
 * The DID will be: did:web:{domain} where domain is extracted from the request.
 * For example:
 * - https://example.com/.well-known/did.json → did:web:example.com
 * - https://localhost:9443/.well-known/did.json → did:web:localhost%3A9443
 */
public class WellKnownDIDServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final int DEFAULT_TENANT_ID = -1234; // Super tenant

    private transient DIDDocumentService didDocumentService;

    @Override
    public void init() throws ServletException {
        super.init();
        this.didDocumentService = new DIDDocumentServiceImpl();
    }

    /**
     * Handle GET requests - Return DID Document.
     */

    @Override
    @SuppressFBWarnings("XSS_SERVLET")
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Get tenant domain and ID from context
            String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
            int tenantId = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);

            // Dynamically construct domain with path for this tenant
            String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil
                    .getTenantAwareBaseUrl(tenantDomain);
            String domain = baseUrl.replace("https://", "").replace("http://", "");
            if (domain.endsWith("/")) {
                domain = domain.substring(0, domain.length() - 1);
            }

            // Generate DID document
            String didDocument = didDocumentService.getDIDDocument(domain, tenantId);

            // Send response
            response.setContentType("application/did+json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);

            // Add CORS headers
            CORSUtil.addCORSHeaders(request, response);

            PrintWriter out = response.getWriter();
            writeResponse(out, didDocument);
            out.flush();

        } catch (DIDDocumentException e) {

            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to generate DID document: " + e.getMessage());
        } catch (RuntimeException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
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
     * Extract domain from the configuration.
     * Returns the host and port if present.
     *
     * @return Domain string (e.g., "example.com" or "localhost:9443")
     * @deprecated Use context-aware tenant domains.
     */
    @Deprecated
    private String extractDomain() {
        String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil.getBaseUrl();
        // Remove protocol
        return baseUrl.replace("https://", "").replace("http://", "");
    }

    /**
     * Send error response.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message)
            throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(statusCode);

        JsonObject errorJson = new JsonObject();
        errorJson.addProperty("error", message);

        PrintWriter out = response.getWriter();
        writeResponse(out, errorJson.toString());
        out.flush();
    }

    @SuppressFBWarnings("XSS_SERVLET")
    private void writeResponse(PrintWriter writer, String content) {
        writer.print(content);
    }
}
