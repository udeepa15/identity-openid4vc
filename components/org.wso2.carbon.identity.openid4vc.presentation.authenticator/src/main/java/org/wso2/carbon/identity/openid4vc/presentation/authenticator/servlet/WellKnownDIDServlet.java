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

import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDDocumentException;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDDocumentServiceImpl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
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
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/.well-known/did.json",
        "osgi.http.whiteboard.servlet.name=OpenID4VPWellKnownDID",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class WellKnownDIDServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(WellKnownDIDServlet.class);
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
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Get tenant domain and ID from context
            String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
            if (org.apache.commons.lang.StringUtils.isBlank(tenantDomain)) {
                tenantDomain = org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
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
            addCORSHeaders(request, response);

            writeResponse(response, didDocument);

        } catch (DIDDocumentException e) {
            LOG.error("Failed to generate DID document.", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to generate DID document: " + e.getMessage());
        } catch (Throwable e) {
            LOG.error("Internal server error while serving DID document.", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
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

        writeResponse(response, errorJson.toString());
    }

    private void addCORSHeaders(HttpServletRequest request, HttpServletResponse response) {

        // Deny by default: do not add CORS allow headers unless an explicit, reviewed
        // endpoint-specific policy is implemented by the caller.
    }

    private void writeResponse(HttpServletResponse response, String content) throws IOException {
        byte[] payload = content.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(payload.length);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }
}
