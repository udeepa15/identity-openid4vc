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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.util.OpenID4VPUtil;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDServerException;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDDocumentServiceImpl;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.SUPER_TENANT_ID_PLACEHOLDER;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constraints.TENANT_DOMAIN_PATTERN;

/**
 * Servlet handling the did.json endpoint for both super tenant and sub-tenants.
 *
 * <p>Serves the DID Document for WSO2 Identity Server using did:web method.
 * For example:</p>
 * <ul>
 * <li>Super Tenant: https://example.com/.well-known/did.json → did:web:example.com</li>
 * <li>Sub Tenant: https://example.com/t/wallet-test/did.json → did:web:example.com:t:wallet-test</li>
 * </ul>
 */
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=/.well-known/did.json",
                "osgi.http.whiteboard.servlet.pattern=/did.json",
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
            // 1. Resolve the Tenant Domain
            String tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();

            // Failsafe: Extract tenant from URI if context is empty (common for unauthenticated OSGi endpoints)
            String requestURI = request.getRequestURI();
            if ((StringUtils.isBlank(tenantDomain) || !tenantDomain.matches(TENANT_DOMAIN_PATTERN))
                    && requestURI.startsWith("/t/")) {
                String[] parts = requestURI.split("/");
                if (parts.length > 2) {
                    tenantDomain = parts[2];
                }
            }

            if (StringUtils.isBlank(tenantDomain) || !tenantDomain.matches(TENANT_DOMAIN_PATTERN)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }

            // 2. Resolve the Tenant ID
            int tenantId;
            try {
                tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            } catch (RuntimeException ex) {
                LOG.debug("Falling back to super tenant ID placeholder for tenant domain: " + tenantDomain, ex);
                tenantId = SUPER_TENANT_ID_PLACEHOLDER;
            }

            // 3. Dynamically construct domain with path for this tenant.
            String baseUrl = OpenID4VPUtil.getTenantAwareBaseUrl(tenantDomain);
            String domain = baseUrl.replace("https://", "").replace("http://", "");
            if (domain.endsWith("/")) {
                domain = domain.substring(0, domain.length() - 1);
            }

            // W3C specs require colons (:) instead of slashes (/) for did:web paths.
            // Example: "example.com/t/wallet-test" becomes "example.com:t:wallet-test"
            domain = domain.replace("/", ":");

            // 5. Generate DID document.
            // Force tenant flow so KeyStoreManager loads the correct tenant's EdDSA keys
            org.wso2.carbon.context.PrivilegedCarbonContext.startTenantFlow();
            try {
                org.wso2.carbon.context.PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .setTenantDomain(tenantDomain, true);

                String didDocument = didDocumentService.getDIDDocument(domain, tenantId);

                // Send response.
                response.setContentType("application/did+json;charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_OK);

                // Add CORS headers.
                addCORSHeaders(request, response);

                writeResponse(response, didDocument);
            } finally {
                org.wso2.carbon.context.PrivilegedCarbonContext.endTenantFlow();
            }

        } catch (DIDServerException e) {
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

        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setStatus(statusCode);

        JsonObject errorJson = new JsonObject();
        errorJson.addProperty(RESPONSE_ERROR, exception.getOAuth2ErrorCode());
        errorJson.addProperty(RESPONSE_ERROR_DESCRIPTION, exception.getMessage());
        errorJson.addProperty(RESPONSE_ERROR_CODE, exception.getCode());

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
