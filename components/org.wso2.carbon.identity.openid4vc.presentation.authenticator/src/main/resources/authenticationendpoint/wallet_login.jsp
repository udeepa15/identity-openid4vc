<%--
  ~ Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
  ~
  ~ WSO2 LLC. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="java.io.File" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="layout" uri="org.wso2.identity.apps.taglibs.layout.controller" %>
<%@ include file="includes/localize.jsp" %>
<jsp:directive.include file="includes/init-url.jsp"/>

<%-- Branding Preferences --%>
<jsp:directive.include file="includes/branding-preferences.jsp"/>

<%
    String sessionDataKey = request.getParameter("sessionDataKey");
    String clientId = request.getParameter("clientId");
    String requestUri = request.getParameter("requestUri");

    if (sessionDataKey == null) {
        Object v = request.getAttribute("openid4vp_ui_session_data_key");
        sessionDataKey = v instanceof String ? (String) v : null;
    }

    if (sessionDataKey == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_session_data_key");
        sessionDataKey = v instanceof String ? (String) v : null;
    }

%>

<html lang="en-US">
    <head>
        <%-- header --%>
        <%
            File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
            if (headerFile.exists()) {
        %>
        <jsp:include page="extensions/header.jsp"/>
        <% } else { %>
        <jsp:include page="includes/header.jsp"/>
        <% } %>

        <%-- analytics --%>
        <%
            File analyticsFile = new File(getServletContext().getRealPath("extensions/analytics.jsp"));
            if (analyticsFile.exists()) {
        %>
            <jsp:include page="extensions/analytics.jsp"/>
        <% } else { %>
            <jsp:include page="includes/analytics.jsp"/>
        <% } %>

        <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>

        <style>
            #qrcode {
                margin: 0 auto;
                width: 250px;
                height: 250px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            #qrcode canvas,
            #qrcode img {
                border-radius: 8px;
            }
            .wallet-spinner {
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid #ddd;
                border-top-color: #ff7300;
                border-radius: 50%;
                animation: wallet-spin 1s linear infinite;
                vertical-align: middle;
                margin-right: 8px;
            }
            @keyframes wallet-spin {
                to { transform: rotate(360deg); }
            }
            .wallet-steps {
                text-align: left;
                padding-left: 20px;
            }
            .wallet-steps li {
                margin-bottom: 8px;
                color: #444;
                font-size: 13px;
            }
            @media (max-width: 480px) {
                #qrcode {
                    width: 200px;
                    height: 200px;
                }
            }
        </style>
    </head>

    <body class="login-portal layout totp-portal-layout">
        <layout:main layoutName="<%= layout %>" layoutFileRelativePath="<%= layoutFileRelativePath %>" data="<%= layoutData %>" >
            <layout:component componentName="ProductHeader">
                <%-- product-title --%>
                <%
                    File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                    if (productTitleFile.exists()) {
                %>
                    <jsp:include page="extensions/product-title.jsp"/>
                <% } else { %>
                    <jsp:include page="includes/product-title.jsp"/>
                <% } %>
            </layout:component>
            <layout:component componentName="MainSection">
                <div class="ui segment">
                    <%-- page content --%>
                    <h3 class="ui header text-center">
                        Sign in with Digital Wallet
                    </h3>
                    <p class="text-center" style="color: #666; font-size: 14px;">
                        Scan the QR code below with your digital wallet to verify your identity
                    </p>
                    <div class="ui divider hidden"></div>

                    <div class="segment-form">
                        <%-- QR Code --%>
                        <div class="field text-center">
                            <div id="qrcode"></div>
                        </div>

                        <%-- Status --%>
                        <div class="ui divider hidden"></div>
                        <div class="text-center" id="statusContainer">
                            <div id="status">
                                <span class="wallet-spinner"></span>
                                <span id="statusText">Waiting for wallet...</span>
                            </div>
                        </div>

                        <div class="ui divider hidden"></div>

                        <%-- Instructions --%>
                        <div class="ui info message">
                            <div class="header" style="font-size: 14px; margin-bottom: 10px;">
                                How to sign in
                            </div>
                            <ol class="wallet-steps">
                                <li>Open your digital wallet app (Inji, etc.)</li>
                                <li>Scan the QR code above</li>
                                <li>Review the credential request</li>
                                <li>Approve to share your credentials</li>
                            </ol>
                        </div>

                        <div class="ui divider hidden"></div>

                        <%-- Deep link for mobile --%>
                        <div class="text-center">
                            <p style="color: #888; font-size: 13px; margin-bottom: 10px;">
                                Or tap below if you're on mobile:
                            </p>
                            <a id="walletLink" href="#" class="ui primary fluid large button">
                                Open in Wallet
                            </a>
                        </div>

                        <%-- Error container --%>
                        <div id="errorContainer" class="ui negative message" style="display: none;">
                            <div class="header">Authentication Failed</div>
                            <p id="errorMessage">An error occurred during verification.</p>
                        </div>
                    </div>
                </div>
            </layout:component>
            <layout:component componentName="ProductFooter">
                <%-- product-footer --%>
                <%
                    File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
                    if (productFooterFile.exists()) {
                %>
                    <jsp:include page="extensions/product-footer.jsp"/>
                <% } else { %>
                    <jsp:include page="includes/product-footer.jsp"/>
                <% } %>
            </layout:component>
            <layout:dynamicComponent filePathStoringVariableName="pathOfDynamicComponent">
                <jsp:include page="${pathOfDynamicComponent}" />
            </layout:dynamicComponent>
        </layout:main>

        <%-- footer --%>
        <%
            File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
            if (footerFile.exists()) {
        %>
            <jsp:include page="extensions/footer.jsp"/>
        <% } else { %>
            <jsp:include page="includes/footer.jsp"/>
        <% } %>

        <form id="authForm" style="display: none;" method="POST" action="<%=commonauthURL%>">
            <input type="hidden" name="sessionDataKey"
                value='<%=Encode.forHtmlAttribute(sessionDataKey != null ? sessionDataKey : "")%>'>
            <input type="hidden" name="status" id="authStatus" value="">
            <input type="hidden" name="vp_request_id" id="authRequestId" value="">
        </form>

        <script type="text/javascript">
            // Configuration
            var CONFIG = {
                sessionDataKey: '<%=sessionDataKey != null ? Encode.forJavaScript(sessionDataKey) : ""%>',
                clientId: '<%=clientId != null ? Encode.forJavaScript(clientId) : ""%>',
                requestUri: '<%=requestUri != null ? Encode.forJavaScript(requestUri) : ""%>',
                pollInterval: 5000,
                pollEndpoint: '/oid4vp/v1/vp-request/<%=Encode.forUriComponent(sessionDataKey != null ? sessionDataKey : "")%>/status'
            };

            var pollTimer = null;
            var submitted = false;

            function logDebugDetails(stage, details) {
                console.log('[OpenID4VP][wallet_login.jsp][' + stage + ']', details || {});
            }

            // Keep JS QR bootstrap aligned with QRCodeUtil.generateRequestUriQRContent.
            function buildRequestUriQRContent(requestUri, clientId) {
                if (!requestUri) {
                    return '';
                }

                var content = 'openid4vp://authorize?';
                if (clientId) {
                    content += 'client_id=' + encodeURIComponent(clientId) + '&';
                }
                content += 'request_uri=' + encodeURIComponent(requestUri);
                return content;
            }

            // Initialize QR code
            function initQRCode() {
                var qrContainer = document.getElementById('qrcode');
                if (!qrContainer || !CONFIG.qrContent) return;

                new QRCode(qrContainer, {
                    text: CONFIG.qrContent,
                    width: 250,
                    height: 250,
                    colorDark: '#000000',
                    colorLight: '#ffffff',
                    correctLevel: QRCode.CorrectLevel.M
                });
            }

            // Set up deep link
            function initDeepLink() {
                var walletLink = document.getElementById('walletLink');
                if (walletLink && CONFIG.qrContent) {
                    walletLink.href = CONFIG.qrContent;
                }
            }

            // Update status display
            function updateStatus(status, message) {
                var statusDiv = document.getElementById('status');

                if (status === 'pending') {
                    statusDiv.innerHTML = '<span class="wallet-spinner"></span><span>' + message + '</span>';
                } else if (status === 'success') {
                    statusDiv.innerHTML =
                        '<i class="check circle icon" style="color: #28a745;"></i>' +
                        '<span style="color: #28a745;">' + message + '</span>';
                } else if (status === 'error') {
                    statusDiv.innerHTML =
                        '<i class="times circle icon" style="color: #dc3545;"></i>' +
                        '<span style="color: #dc3545;">' + message + '</span>';
                }
            }

            // Poll for VP status
            function pollStatus() {
                logDebugDetails('poll-request', {
                    endpoint: CONFIG.pollEndpoint,
                    sessionDataKey: CONFIG.sessionDataKey
                });

                fetch(CONFIG.pollEndpoint, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    logDebugDetails('poll-response', data);

                    var status = data.status ? data.status.toUpperCase() : '';

                    if (status === 'ACTIVE') {
                        updateStatus('pending', 'Waiting for wallet...');
                    } else if (status === 'VP_SUBMITTED' || status === 'VERIFIED' || status === 'SUCCESS') {
                        handleSuccess();
                    } else if (status === 'FAILED') {
                        handleError('Verification failed');
                    } else if (status === 'EXPIRED') {
                        handleExpired();
                    } else if (status === 'NOT_FOUND' || status === 'ERROR' || status === '') {
                        handleError(data.message || 'Verification failed');
                    } else {
                        handleError('Unexpected status received: ' + status);
                    }
                })
                .catch(function(error) {
                    logDebugDetails('poll-error', { message: error && error.message ? error.message : error });
                    // Continue polling despite errors
                });
            }

            // Handle successful verification
            function handleSuccess() {
                if (submitted) return;
                submitted = true;
                clearInterval(pollTimer);
                pollTimer = null;

                updateStatus('success', 'Credentials verified! Logging you in...');

                // Submit form to complete authentication
                setTimeout(function() {
                    document.getElementById('authStatus').value = 'success';
                    logDebugDetails('auth-submit', {
                        action: document.getElementById('authForm').action,
                        sessionDataKey: CONFIG.sessionDataKey,
                        status: 'success',
                        vpRequestId: document.getElementById('authRequestId').value
                    });
                    document.getElementById('authForm').submit();
                }, 1000);
            }

            // Handle error and keep polling active for possible subsequent valid submission.
            function handleError(message) {
                updateStatus('error', 'Verification failed');

                var errorContainer = document.getElementById('errorContainer');
                var errorMessage = document.getElementById('errorMessage');

                errorMessage.textContent = message;
                errorContainer.style.display = 'block';
            }

            // Handle expired request
            function handleExpired() {
                clearInterval(pollTimer);
                pollTimer = null;

                updateStatus('error', 'Request expired');

                var errorContainer = document.getElementById('errorContainer');
                var errorMessage = document.getElementById('errorMessage');

                errorMessage.textContent = 'The QR code has expired.';
                errorContainer.style.display = 'block';
            }

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                CONFIG.qrContent = buildRequestUriQRContent(CONFIG.requestUri, CONFIG.clientId);

                logDebugDetails('init-config', {
                    sessionDataKey: CONFIG.sessionDataKey,
                    clientId: CONFIG.clientId,
                    requestUri: CONFIG.requestUri,
                    qrContent: CONFIG.qrContent,
                    pollEndpoint: CONFIG.pollEndpoint,
                    pollInterval: CONFIG.pollInterval
                });

                if (CONFIG.qrContent) {
                    initQRCode();
                    initDeepLink();
                } else {
                    handleError('Missing request details for wallet QR generation.');
                }

                // Start polling
                pollTimer = setInterval(pollStatus, CONFIG.pollInterval);
            });
        </script>
    </body>
</html>
