package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.AuthorizationDetailsDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.QRCodeUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.SecurityUtils;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPVerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VCVerificationService;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class OpenID4VPAuthenticatorTest {

    private OpenID4VPAuthenticator authenticator;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationContext context;

    @Mock
    private VPServiceDataHolder vpServiceDataHolder;

    @Mock
    private VPRequestService vpRequestService;

    @Mock
    private PresentationDefinitionService presentationDefinitionService;

    @Mock
    private VPStatusListenerCache vpStatusListenerCache;

    @Mock
    private WalletDataCache walletDataCache;

    @Mock
    private VCVerificationService vcVerificationService;

    private MockedStatic<VPServiceDataHolder> mockedVPServiceDataHolder;
    private MockedStatic<VPStatusListenerCache> mockedVPStatusListenerCache;
    private MockedStatic<WalletDataCache> mockedWalletDataCache;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<QRCodeUtil> mockedQRCodeUtil;
    private MockedStatic<SecurityUtils> mockedSecurityUtils;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        authenticator = new OpenID4VPAuthenticator();

        mockedVPServiceDataHolder = Mockito.mockStatic(VPServiceDataHolder.class);
        mockedVPServiceDataHolder.when(VPServiceDataHolder::getInstance).thenReturn(vpServiceDataHolder);
        when(vpServiceDataHolder.getVPRequestService()).thenReturn(vpRequestService);
        when(vpServiceDataHolder.getPresentationDefinitionService()).thenReturn(presentationDefinitionService);
        when(vpServiceDataHolder.getVCVerificationService()).thenReturn(vcVerificationService);

        mockedVPStatusListenerCache = Mockito.mockStatic(VPStatusListenerCache.class);
        mockedVPStatusListenerCache.when(VPStatusListenerCache::getInstance).thenReturn(vpStatusListenerCache);

        mockedWalletDataCache = Mockito.mockStatic(WalletDataCache.class);
        mockedWalletDataCache.when(WalletDataCache::getInstance).thenReturn(walletDataCache);

        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
        mockedIdentityUtil.when(() -> IdentityUtil.getProperty("OpenID4VP.LoginPage"))
                .thenReturn("/authenticationendpoint/wallet_login.jsp");
        
        mockedQRCodeUtil = Mockito.mockStatic(QRCodeUtil.class);
        mockedQRCodeUtil.when(() -> QRCodeUtil.generateRequestUriQRContent(anyString(), anyString()))
                .thenReturn("dummy-qr-content");

        mockedSecurityUtils = Mockito.mockStatic(SecurityUtils.class);
        mockedSecurityUtils.when(() -> SecurityUtils.isSafeRedirectUri(anyString())).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {
        if (mockedVPServiceDataHolder != null) {
            mockedVPServiceDataHolder.close();
        }
        if (mockedVPStatusListenerCache != null) {
            mockedVPStatusListenerCache.close();
        }
        if (mockedWalletDataCache != null) {
            mockedWalletDataCache.close();
        }
        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
        if (mockedQRCodeUtil != null) {
            mockedQRCodeUtil.close();
        }
        if (mockedSecurityUtils != null) {
            mockedSecurityUtils.close();
        }
    }

    @Test
    public void testGetName() {
        assertEquals(authenticator.getName(), "OpenID4VPAuthenticator");
    }

    @Test
    public void testGetFriendlyName() {
        assertEquals(authenticator.getFriendlyName(), "Wallet (OpenID4VP)");
    }

    @Test
    public void testInitiateAuthenticationRequest() throws Exception {
        Map<String, String> authProperties = new HashMap<>();
        authProperties.put("ClientId", "dummy-client");
        authProperties.put("DIDMethod", "web");
        authProperties.put("presentationDefinitionId", "dummy-pd-id");
        
        when(context.getAuthenticatorProperties()).thenReturn(authProperties);
        when(context.getContextIdentifier()).thenReturn("dummy-txn-id");
        when(context.getTenantDomain()).thenReturn("carbon.super");

        VPRequestResponseDTO mockResponseDTO = new VPRequestResponseDTO();
        mockResponseDTO.setRequestId("req-123");
        mockResponseDTO.setTransactionId("dummy-txn-id");
        mockResponseDTO.setRequestUri("urn:ietf:params:oauth:request_uri:req-123");
        
        AuthorizationDetailsDTO authDetails = new AuthorizationDetailsDTO();
        authDetails.setClientId("dummy-client");
        mockResponseDTO.setAuthorizationDetails(authDetails);

        when(vpRequestService.createVPRequest(any(), anyInt())).thenReturn(mockResponseDTO);
        doNothing().when(response).sendRedirect(anyString());

        authenticator.initiateAuthenticationRequest(request, response, context);

        verify(context).setProperty("openid4vp_request_id", "req-123");
        verify(context).setProperty("openid4vp_transaction_id", "dummy-txn-id");
        verify(vpStatusListenerCache).registerListener(anyString(), anyString(), any());
        verify(response).sendRedirect(anyString());
    }

    private void mockIdpClaimConfig() {
        ExternalIdPConfig externalIdPConfig = Mockito.mock(ExternalIdPConfig.class);
        IdentityProvider idp = Mockito.mock(IdentityProvider.class);
        ClaimConfig claimConfig = Mockito.mock(ClaimConfig.class);

        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(idp);
        when(idp.getClaimConfig()).thenReturn(claimConfig);
        when(claimConfig.getUserClaimURI()).thenReturn("http://wso2.org/claims/emailaddress");

        ClaimMapping claimMapping = Mockito.mock(ClaimMapping.class);
        org.wso2.carbon.identity.application.common.model.Claim localClaim = 
        Mockito.mock(org.wso2.carbon.identity.application.common.model.Claim.class);
        org.wso2.carbon.identity.application.common.model.Claim remoteClaim = 
        Mockito.mock(org.wso2.carbon.identity.application.common.model.Claim.class);
        when(claimMapping.getLocalClaim()).thenReturn(localClaim);
        when(claimMapping.getRemoteClaim()).thenReturn(remoteClaim);
        when(localClaim.getClaimUri()).thenReturn("http://wso2.org/claims/emailaddress");
        when(remoteClaim.getClaimUri()).thenReturn("email");

        when(externalIdPConfig.getClaimMappings()).thenReturn(new ClaimMapping[]{claimMapping});
        when(externalIdPConfig.getIdPName()).thenReturn("dummy-idp");
    }

    @Test
    public void testProcessAuthenticationResponseSdJwt() throws Exception {
        mockIdpClaimConfig();
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(context.getTenantDomain()).thenReturn("carbon.super");

        when(request.getParameter("status")).thenReturn("success");

        VPSubmission mockSubmission = new VPSubmission();
        String presentationSubmissionJson = "{\"descriptor_map\":[{\"format\":\"vc+sd-jwt\"}]}";
        mockSubmission.setPresentationSubmission(presentationSubmissionJson);
        mockSubmission.setVpToken("dummy-vp-token");

        // mock authenticator's internal wallet data cache retrieval
        when(walletDataCache.getSubmission("req-123")).thenReturn(mockSubmission);

        VPRequest mockRequest = new VPRequest.Builder()
                .requestId("req-123")
                .nonce("dummy-nonce")
                .clientId("dummy-client")
                .presentationDefinitionId("def-123")
                .build();
        when(vpRequestService.getVPRequestById(anyString(), anyInt())).thenReturn(mockRequest);

        PresentationDefinition mockDef = new PresentationDefinition.Builder()
                .definitionId("def-123")
                .requestedCredentials(java.util.Collections.emptyList())
                .build();
        when(presentationDefinitionService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(mockDef);

        Map<String, Object> verifiedClaims = new HashMap<>();
        verifiedClaims.put("email", "testuser@example.com");
        VPVerificationResponseDTO verificationResult =
                VPVerificationResponseDTO.success(verifiedClaims, "vc+sd-jwt", "dummy-nonce", "dummy-client");
        when(vcVerificationService.verifyPresentation(
                anyString(), anyString(), any(), anyInt()))
                .thenReturn(verificationResult);

        authenticator.process(request, response, context);

        verify(context).setSubject(any());
    }

    @Test
    public void testProcessAuthenticationResponseLdpVp() throws Exception {
        mockIdpClaimConfig();
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(context.getTenantDomain()).thenReturn("carbon.super");

        when(request.getParameter("status")).thenReturn("success");

        VPSubmission mockSubmission = new VPSubmission();
        String presentationSubmissionJson = "{\"descriptor_map\":[{\"format\":\"ldp_vp\"}]}";
        mockSubmission.setPresentationSubmission(presentationSubmissionJson);
        // Provide a valid JSON string as vpToken for ldp_vp
        mockSubmission.setVpToken("{\"verifiableCredential\":" +
                "[{\"credentialSubject\":{\"email\":\"testuser@example.com\"}}]}");

        when(walletDataCache.getSubmission("req-123")).thenReturn(mockSubmission);

        VPRequest mockRequest = new VPRequest.Builder()
                .requestId("req-123")
                .nonce("dummy-nonce")
                .clientId("dummy-client")
                .presentationDefinitionId("def-123")
                .build();
        when(vpRequestService.getVPRequestById(anyString(), anyInt())).thenReturn(mockRequest);

        PresentationDefinition mockDef = new PresentationDefinition.Builder()
                .definitionId("def-123")
                .requestedCredentials(java.util.Collections.emptyList())
                .build();
        when(presentationDefinitionService.getPresentationDefinitionById(anyString(), anyInt())).thenReturn(mockDef);

        Map<String, Object> verifiedClaims = new HashMap<>();
        verifiedClaims.put("email", "testuser@example.com");
        VPVerificationResponseDTO verificationResult =
                VPVerificationResponseDTO.success(verifiedClaims, "ldp_vp", "dummy-nonce", "dummy-client");
        when(vcVerificationService.verifyPresentation(
                anyString(), anyString(), any(), anyInt()))
                .thenReturn(verificationResult);

        authenticator.process(request, response, context);

        verify(context).setSubject(any());
    }

    @Test(expectedExceptions =
            org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseWithoutVPToken() throws Exception {
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(request.getParameter("status")).thenReturn("success");

        VPSubmission mockSubmission = new VPSubmission();
        mockSubmission.setPresentationSubmission("{}");
        // No VP Token
        when(walletDataCache.getSubmission("req-123")).thenReturn(mockSubmission);

        authenticator.process(request, response, context);
    }

    @Test(expectedExceptions =
            org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseWithExpiredRequest() throws Exception {
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(context.getTenantDomain()).thenReturn("carbon.super");

        when(request.getParameter("status")).thenReturn("success");

        VPSubmission mockSubmission = new VPSubmission();
        String presentationSubmissionJson = "{\"descriptor_map\":[{\"format\":\"vc+sd-jwt\"}]}";
        mockSubmission.setPresentationSubmission(presentationSubmissionJson);
        mockSubmission.setVpToken("dummy-vp-token");

        when(walletDataCache.getSubmission("req-123")).thenReturn(mockSubmission);

        when(vpRequestService.getVPRequestById(anyString(), anyInt()))
                .thenThrow(
                        new org.wso2.carbon.identity.openid4vc.presentation.authenticator
                                .exception.VPRequestExpiredException("Error", 1600000000000L));

        authenticator.process(request, response, context);
    }

    @Test
    public void testProcessHandlePollRequestPending() throws Exception {
        when(request.getParameter("poll")).thenReturn("true");
        when(request.getParameter("sessionDataKey")).thenReturn("req-123");
        
        java.io.PrintWriter mockPrintWriter = org.mockito.Mockito.mock(java.io.PrintWriter.class);
        when(response.getWriter()).thenReturn(mockPrintWriter);
        
        VPSubmission mockSubmission = new VPSubmission();
        mockSubmission.setRequestId("req-123");
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(context.getTenantDomain()).thenReturn("carbon.super");
        
        VPRequest mockRequest = new VPRequest.Builder()
                .requestId("req-123")
                .status(VPRequestStatus.ACTIVE)
                .build();
        when(vpRequestService.getVPRequestById(anyString(), anyInt())).thenReturn(mockRequest);
        
        AuthenticatorFlowStatus status = 
                authenticator.process(request, response, context);
        
        assertEquals(status, 
                AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessHandlePollRequestCompleted() throws Exception {
        when(request.getParameter("poll")).thenReturn("true");
        when(request.getParameter("sessionDataKey")).thenReturn("req-123");
        
        java.io.PrintWriter mockPrintWriter = org.mockito.Mockito.mock(java.io.PrintWriter.class);
        when(response.getWriter()).thenReturn(mockPrintWriter);
        
        when(context.getProperty("openid4vp_request_id")).thenReturn("req-123");
        when(context.getTenantDomain()).thenReturn("carbon.super");
        
        VPRequest mockRequest = new VPRequest.Builder()
                .requestId("req-123")
                .status(VPRequestStatus.COMPLETED)
                .build();
        when(vpRequestService.getVPRequestById(anyString(), anyInt())).thenReturn(mockRequest);
        
        AuthenticatorFlowStatus status = 
                authenticator.process(request, response, context);
        
        assertEquals(status, 
                AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(expectedExceptions = 
            org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException.class)
    public void testProcessHandleStatusCallbackFailed() throws Exception {
        when(request.getParameter("status")).thenReturn("failed");
        authenticator.process(request, response, context);
    }
}
