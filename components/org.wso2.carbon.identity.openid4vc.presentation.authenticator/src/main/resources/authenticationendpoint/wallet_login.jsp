<%--
  ~ Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.net.URLDecoder" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<%
    String sessionDataKey = request.getParameter("sessionDataKey");
    String requestId = request.getParameter("requestId");
    String transactionId = request.getParameter("transactionId");
    String requestUri = request.getParameter("requestUri");
    String qrContent = request.getParameter("qrContent");

    if (sessionDataKey == null) {
        Object v = request.getAttribute("openid4vp_ui_session_data_key");
        sessionDataKey = v instanceof String ? (String) v : null;
    }
    if (requestId == null) {
        Object v = request.getAttribute("openid4vp_ui_request_id");
        requestId = v instanceof String ? (String) v : null;
    }
    if (transactionId == null) {
        Object v = request.getAttribute("openid4vp_ui_transaction_id");
        transactionId = v instanceof String ? (String) v : null;
    }
    if (requestUri == null) {
        Object v = request.getAttribute("openid4vp_ui_request_uri");
        requestUri = v instanceof String ? (String) v : null;
    }
    if (qrContent == null) {
        Object v = request.getAttribute("openid4vp_ui_qr_content");
        qrContent = v instanceof String ? (String) v : null;
    }

    if (sessionDataKey == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_session_data_key");
        sessionDataKey = v instanceof String ? (String) v : null;
    }
    if (requestId == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_request_id");
        requestId = v instanceof String ? (String) v : null;
    }
    if (transactionId == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_transaction_id");
        transactionId = v instanceof String ? (String) v : null;
    }
    if (requestUri == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_request_uri");
        requestUri = v instanceof String ? (String) v : null;
    }
    if (qrContent == null) {
        Object v = request.getSession().getAttribute("openid4vp_ui_qr_content");
        qrContent = v instanceof String ? (String) v : null;
    }
    
    // Decode URL-encoded parameters
    if (requestUri != null) {
        requestUri = URLDecoder.decode(requestUri, "UTF-8");
    }
    if (qrContent != null) {
        qrContent = URLDecoder.decode(qrContent, "UTF-8");
    }
    
    // Set page attributes
    request.setAttribute("sessionDataKey", sessionDataKey);
    request.setAttribute("requestId", requestId);
    request.setAttribute("transactionId", transactionId);
    request.setAttribute("requestUri", requestUri);
    request.setAttribute("qrContent", qrContent);
%>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wallet Login - OpenID4VP</title>
    
    <!-- QRCode.js library -->
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            text-align: center;
        }
        
        .logo {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-left: auto;
            margin-right: auto;
        }
        
        .logo svg {
            width: 50px;
            height: 50px;
            fill: white;
        }
        
        h1 {
            color: #1a1a2e;
            font-size: 24px;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        
        .qr-container {
            background: #f8f9fa;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            position: relative;
        }
        
        #qrcode {
            margin: 0 auto;
            width: 250px;
            height: 250px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        #qrcode canvas {
            border-radius: 8px;
        }
        
        .status-container {
            margin-top: 20px;
        }
        
        .status {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            font-size: 14px;
            color: #666;
        }
        
        .status.success {
            color: #28a745;
        }
        
        .status.error {
            color: #dc3545;
        }
        
        .spinner {
            width: 20px;
            height: 20px;
            border: 2px solid #ddd;
            border-top-color: #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .check-icon, .error-icon {
            width: 20px;
            height: 20px;
        }
        
        .instructions {
            background: #f0f4ff;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .instructions h3 {
            color: #667eea;
            font-size: 14px;
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .steps {
            text-align: left;
            font-size: 13px;
            color: #444;
        }
        
        .steps li {
            margin-bottom: 10px;
            padding-left: 10px;
            list-style-position: inside;
        }
        
        .deep-link {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }
        
        .deep-link a {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .deep-link a:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }
        
        .deep-link p {
            color: #888;
            font-size: 12px;
            margin-bottom: 10px;
        }
        
        .timer {
            font-size: 12px;
            color: #888;
            margin-top: 15px;
        }
        
        .timer.warning {
            color: #f0ad4e;
        }
        
        .timer.danger {
            color: #dc3545;
        }
        
        .error-container {
            display: none;
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .error-container.show {
            display: block;
        }
        
        .error-container h3 {
            color: #dc3545;
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        .error-container p {
            color: #666;
            font-size: 13px;
        }
        
        .retry-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 14px;
            cursor: pointer;
            margin-top: 15px;
            transition: background 0.2s;
        }
        
        .retry-btn:hover {
            background: #c82333;
        }
        
        .hidden-form {
            display: none;
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            
            #qrcode {
                width: 200px;
                height: 200px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M21 18v1c0 1.1-.9 2-2 2H5c-1.11 0-2-.9-2-2V5c0-1.1.89-2 2-2h14c1.1 0 2 .9 2 2v1h-9c-1.11 0-2 .9-2 2v8c0 1.1.89 2 2 2h9zm-9-2h10V8H12v8zm4-2.5c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5z"/>
            </svg>
        </div>
        
        <h1>Sign in with Wallet</h1>
        <p class="subtitle">Scan the QR code below with your digital wallet to verify your identity</p>
        
        <div class="qr-container">
            <div id="qrcode"></div>
            
            <div class="status-container">
                <div id="status" class="status">
                    <div class="spinner"></div>
                    <span id="statusText">Waiting for wallet...</span>
                </div>
            </div>
            
            <div id="timer" class="timer">Expires in 5:00</div>
        </div>
        
        <div class="instructions">
            <h3>How to sign in</h3>
            <ol class="steps">
                <li>Open your digital wallet app (Inji, etc.)</li>
                <li>Scan the QR code above</li>
                <li>Review the credential request</li>
                <li>Approve to share your credentials</li>
            </ol>
        </div>
        
        <div class="deep-link">
            <p>Or tap below if you're on mobile:</p>
            <a id="walletLink" href="#">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M21 18v1c0 1.1-.9 2-2 2H5c-1.11 0-2-.9-2-2V5c0-1.1.89-2 2-2h14c1.1 0 2 .9 2 2v1h-9c-1.11 0-2 .9-2 2v8c0 1.1.89 2 2 2h9z"/>
                </svg>
                Open in Wallet
            </a>
        </div>
        
        <div id="errorContainer" class="error-container">
            <h3>Authentication Failed</h3>
            <p id="errorMessage">An error occurred during verification.</p>
            <button class="retry-btn" onclick="location.reload()">Try Again</button>
        </div>
    </div>
    
    <!-- Hidden form for authentication callback -->
    <form id="authForm" class="hidden-form" method="POST" action="../commonauth">
        <input type="hidden" name="sessionDataKey" value="${sessionDataKey}">
        <input type="hidden" name="vp_request_id" value="${requestId}">
        <input type="hidden" name="transaction_id" value="${transactionId}">
        <input type="hidden" name="status" id="authStatus" value="">
    </form>
    
    <script>
        // Configuration
        const CONFIG = {
            sessionDataKey: '${sessionDataKey}',
            requestId: '${requestId}',
            transactionId: '${transactionId}',
            requestUri: '${requestUri}',
            qrContent: '${qrContent}',
            pollInterval: 2000,
            timeout: 300, // 5 minutes in seconds
            pollEndpoint: '/openid4vp/v1/vp-request/${requestId}/status'
        };
        
        let timeRemaining = CONFIG.timeout;
        let pollTimer = null;
        let countdownTimer = null;
        let submitted = false;
        
        // Initialize QR code
        function initQRCode() {
            const qrContainer = document.getElementById('qrcode');
            if (!qrContainer || !CONFIG.qrContent) return;
            
            new QRCode(qrContainer, {
                text: CONFIG.qrContent,
                width: 250,
                height: 250,
                colorDark: '#1a1a2e',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.M
            });
        }
        
        // Set up deep link
        function initDeepLink() {
            const walletLink = document.getElementById('walletLink');
            if (walletLink && CONFIG.qrContent) {
                walletLink.href = CONFIG.qrContent;
            }
        }
        
        // Update status display
        function updateStatus(status, message) {
            const statusDiv = document.getElementById('status');
            const statusText = document.getElementById('statusText');
            
            statusDiv.className = 'status';
            
            if (status === 'pending') {
                statusDiv.innerHTML = '<div class="spinner"></div><span>' + message + '</span>';
            } else if (status === 'success') {
                statusDiv.classList.add('success');
                statusDiv.innerHTML = '<svg class="check-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg><span>' + message + '</span>';
            } else if (status === 'error') {
                statusDiv.classList.add('error');
                statusDiv.innerHTML = '<svg class="error-icon" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg><span>' + message + '</span>';
            }
        }
        
        // Update countdown timer
        function updateTimer() {
            const timerDiv = document.getElementById('timer');
            const minutes = Math.floor(timeRemaining / 60);
            const seconds = timeRemaining % 60;
            
            timerDiv.textContent = 'Expires in ' + minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
            
            if (timeRemaining <= 60) {
                timerDiv.className = 'timer danger';
            } else if (timeRemaining <= 120) {
                timerDiv.className = 'timer warning';
            }
            
            timeRemaining--;
            
            if (timeRemaining < 0) {
                handleExpired();
            }
        }
        
        // Poll for VP status
        function pollStatus() {
            fetch(CONFIG.pollEndpoint, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                console.log('Poll response:', data);
                
                const s = data.status ? data.status.toUpperCase() : '';
                if (s === 'VP_SUBMITTED' || s === 'COMPLETED' || s === 'VERIFIED' || s === 'SUBMITTED') {
                    handleSuccess();
                } else if (s === 'FAILED') {
                    handleError(data.error || data.message || 'Verification failed');
                } else if (s === 'EXPIRED') {
                    handleExpired();
                } else {
                    // Still pending, continue polling
                    updateStatus('pending', 'Waiting for wallet...');
                }
            })
            .catch(error => {
                console.error('Poll error:', error);
                // Continue polling despite errors
            });
        }
        
        // Handle successful verification
        function handleSuccess() {
            if (submitted) return;
            submitted = true;
            clearInterval(pollTimer);
            clearInterval(countdownTimer);
            pollTimer = null;
            countdownTimer = null;
            
            updateStatus('success', 'Credentials verified successfully!');
            
            // Submit form to complete authentication
            setTimeout(() => {
                document.getElementById('authStatus').value = 'success';
                document.getElementById('authForm').submit();
            }, 1500);
        }
        
        // Handle error
        function handleError(message) {
            clearInterval(pollTimer);
            clearInterval(countdownTimer);
            
            updateStatus('error', 'Verification failed');
            
            const errorContainer = document.getElementById('errorContainer');
            const errorMessage = document.getElementById('errorMessage');
            
            errorMessage.textContent = message;
            errorContainer.classList.add('show');
        }
        
        // Handle expired request
        function handleExpired() {
            clearInterval(pollTimer);
            clearInterval(countdownTimer);
            
            updateStatus('error', 'Request expired');
            document.getElementById('timer').textContent = 'Expired';
            
            const errorContainer = document.getElementById('errorContainer');
            const errorMessage = document.getElementById('errorMessage');
            
            errorMessage.textContent = 'The QR code has expired. Please try again.';
            errorContainer.classList.add('show');
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            initQRCode();
            initDeepLink();
            
            // Start countdown
            countdownTimer = setInterval(updateTimer, 1000);
            updateTimer();
            
            // Start polling
            pollTimer = setInterval(pollStatus, CONFIG.pollInterval);
            
            // Initial poll
            setTimeout(pollStatus, 1000);
        });
    </script>
</body>
</html>
