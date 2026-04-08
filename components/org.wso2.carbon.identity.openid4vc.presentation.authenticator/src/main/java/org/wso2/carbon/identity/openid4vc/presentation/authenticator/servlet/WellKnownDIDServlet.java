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

import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDServerException;
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
 *
 * <p>Serves the DID Document for WSO2 Identity Server using did:web method.
 * The DID will be: did:web:{domain} where domain is extracted from the request.
 * For example:</p>
 * <ul>
 *     <li>https://example.com/.well-known/did.json → did:web:example.com</li>
 *     <li>https://localhost:9443/.well-known/did.json → did:web:localhost%3A9443</li>
 * </ul>
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

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Logger for the WellKnownDIDServlet class.
     */
    private static final Log LOG = LogFactory.getLog(WellKnownDIDServlet.class);

    /**
     * Default tenant ID to use when tenant domain cannot be resolved.
     */
    private static final int DEFAULT_TENANT_ID = -1234;

    /**
     * Service instance for DID document operations.
     */
    private transient DIDDocumentService didDocumentService;

    /**
     * Initialize the servlet and the DID document service.
     *
     * @throws ServletException If an error occurs during initialization.
     */
    @Override
    public void init() throws ServletException {

        super.init();
        this.didDocumentService = new DIDDocumentServiceImpl();
    }

    /**
     * Handle GET requests to retrieve the DID document.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @throws ServletException If an error occurs in the servlet.
     * @throws IOException      If an I/O error occurs.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            // Get tenant domain and ID from context.
            String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantDomainFromContext();
            if (org.apache.commons.lang.StringUtils.isBlank(tenantDomain)) {
                tenantDomain = org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = org.wso2.carbon.identity.core.util.IdentityTenantUtil.getTenantId(tenantDomain);

            // Dynamically construct domain with path for this tenant.
            String baseUrl = org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil
                    .getTenantAwareBaseUrl(tenantDomain);
            String domain = baseUrl.replace("https://", "").replace("http://", "");
            if (domain.endsWith("/")) {
                domain = domain.substring(0, domain.length() - 1);
            }

            // Generate DID document.
            String didDocument = didDocumentService.getDIDDocument(domain, tenantId);

            // Send response.
            response.setContentType("application/did+json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);

            // Add CORS headers.
            addCORSHeaders(request, response);

            writeResponse(response, didDocument);

        } catch (DIDServerException e) {
            // Extract the newly added DIDErrorCode details for better logging
            String errorCode = e.getCode() != null ? e.getCode() : "UNKNOWN_DID_ERROR";
            String errorDesc = e.getDescription() != null ? e.getDescription() : "No description available";

            LOG.error(String.format("Failed to generate DID document. [ErrorCode: %s, Description: %s]",
                    errorCode, errorDesc), e);

            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.DID_RESOLUTION_FAILED,
                            "Failed to generate DID document: " + e.getMessage(), e));
        } catch (Throwable e) {
            LOG.error("Internal server error while serving DID document.", e);
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error", e));
        }
    }

    /**
     * Send error response formatted as JSON.
     *
     * @param response   HTTP response.
     * @param statusCode HTTP status code.
     * @param exception  Exception containing error information.
     * @throws IOException If an I/O error occurs.
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode,
                                   VPAuthenticatorException exception)
            throws IOException {

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(statusCode);

        JsonObject errorJson = new JsonObject();
        errorJson.addProperty("error", exception.getOAuth2ErrorCode());
        errorJson.addProperty("error_description", exception.getMessage());
        errorJson.addProperty("error_code", exception.getCode());

        writeResponse(response, errorJson.toString());
    }

    /**
     * Add CORS headers to the response.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     */
    private void addCORSHeaders(HttpServletRequest request, HttpServletResponse response) {

        // Deny by default: do not add CORS allow headers unless an explicit, reviewed
        // endpoint-specific policy is implemented by the caller.
    }

    /**
     * Write string content to the response output stream.
     *
     * @param response HTTP response.
     * @param content  Content to write.
     * @throws IOException If an I/O error occurs.
     */
    private void writeResponse(HttpServletResponse response, String content) throws IOException {

        byte[] payload = content.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(payload.length);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }
}
