package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;

/**
 * Test class for VPRequestServiceImpl.
 */
public class VPRequestServiceImplTest {

    @Mock
    private VPRequestDAO vpRequestDAO;

    @Mock
    private PresentationDefinitionService presentationDefinitionService;

    @Mock
    private DIDProviderFactory didProviderFactory;

    @Mock
    private DIDProvider didProvider;

    private VPRequestServiceImpl vpRequestService;
    private MockedStatic<IdentityUtil> identityUtilMockedStatic;

    private static final int TENANT_ID = -1234;
    private static final String REQUEST_ID = "req-123";
    private static final String TRANSACTION_ID = "txn-123";
    private static final String CLIENT_ID = "client-123";
    private static final String DEFINITION_ID = "def-123";
    private static final String DEFINITION_JSON = "{\"id\":\"def-123\",\"input_descriptors\":[{\"id\":\"desc-1\","
            + "\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"]}]}}]}";

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        identityUtilMockedStatic = Mockito.mockStatic(IdentityUtil.class);
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(any())).thenReturn("http://localhost:8080");

        vpRequestService = new VPRequestServiceImpl(vpRequestDAO, presentationDefinitionService, 
                "http://localhost:8080");

        // Inject Mock PresentationDefinitionService into DataHolder
        VPServiceDataHolder.setPresentationDefinitionService(presentationDefinitionService);
    }

    @AfterMethod
    public void tearDown() {
        identityUtilMockedStatic.close();
    }

    @Test
    public void testCreateVPRequest() throws Exception {
        VPRequest createRequest = new VPRequest.Builder()
                .clientId(CLIENT_ID)
                .presentationDefinitionId(DEFINITION_ID)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .didMethod("web")
                .build();

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .requestedCredentials(java.util.Collections.emptyList())
                .build();

        when(presentationDefinitionService.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(definition);
        doNothing().when(vpRequestDAO).createVPRequest(any(VPRequest.class));

        JWSSigner mockSigner = Mockito.mock(JWSSigner.class);
        when(mockSigner.supportedJWSAlgorithms())
                .thenReturn(new java.util.HashSet<>(java.util.Collections.singletonList(JWSAlgorithm.RS256)));
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL("dummy-signature"));

        try (MockedStatic<DIDProviderFactory> mockedFactory = Mockito.mockStatic(DIDProviderFactory.class)) {
            mockedFactory.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(didProvider);
            when(didProvider.getDID(Mockito.anyInt(), Mockito.any())).thenReturn("did:web:localhost");
            when(didProvider.getSigningKeyId(Mockito.anyInt(), Mockito.any()))
                    .thenReturn("did:web:localhost#owner");
            when(didProvider.getSigningAlgorithm()).thenReturn(JWSAlgorithm.RS256);
            when(didProvider.getSigner(Mockito.anyInt())).thenReturn(mockSigner);

            VPRequest response = vpRequestService.createVPRequest(createRequest, TENANT_ID);

            assertNotNull(response);
            assertNotNull(response.getRequestId());
            assertNotNull(response.getTransactionId());
            assertNotNull(response.getAuthorizationDetails());
        }
    }

    @Test
    public void testCreateVPRequestWithInlinePresentationDefinition() throws Exception {
        VPRequest createRequest = new VPRequest.Builder()
                .clientId(CLIENT_ID)
                .presentationDefinition(DEFINITION_JSON)
                .responseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST)
                .build();

        doNothing().when(vpRequestDAO).createVPRequest(any(VPRequest.class));

        JWSSigner mockSigner = Mockito.mock(JWSSigner.class);
        when(mockSigner.supportedJWSAlgorithms())
                .thenReturn(new java.util.HashSet<>(java.util.Collections.singletonList(JWSAlgorithm.RS256)));
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL("dummy-signature"));

        try (MockedStatic<DIDProviderFactory> mockedFactory = Mockito.mockStatic(DIDProviderFactory.class)) {
            mockedFactory.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(didProvider);
            when(didProvider.getDID(Mockito.anyInt(), Mockito.any())).thenReturn("did:web:localhost");
            when(didProvider.getSigningKeyId(Mockito.anyInt(), Mockito.any()))
                    .thenReturn("did:web:localhost#owner");
            when(didProvider.getSigningAlgorithm()).thenReturn(JWSAlgorithm.RS256);
            when(didProvider.getSigner(Mockito.anyInt())).thenReturn(mockSigner);

            VPRequest response = vpRequestService.createVPRequest(createRequest, TENANT_ID);

            assertNotNull(response);
            assertNotNull(response.getRequestId());
        }
    }

    @Test
    public void testCreateVPRequestMissingClientId() throws Exception {
        VPRequest createRequest = new VPRequest.Builder()
                .presentationDefinitionId(DEFINITION_ID)
                .build();

        assertThrows(VPAuthenticatorException.class, () -> vpRequestService.createVPRequest(createRequest, TENANT_ID));
    }

    @Test
    public void testCreateVPRequestMissingPresentationDefinition() throws Exception {
        VPRequest createRequest = new VPRequest.Builder()
                .clientId(CLIENT_ID)
                .build();

        assertThrows(VPAuthenticatorException.class, () -> vpRequestService.createVPRequest(createRequest, TENANT_ID));
    }

    @Test
    public void testGetVPRequestById() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .clientId(CLIENT_ID)
                .build();

        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);

        VPRequest result = vpRequestService.getVPRequestById(REQUEST_ID, TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getRequestId(), REQUEST_ID);
    }

    @Test
    public void testGetVPRequestByIdNotFound() throws Exception {
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(null);

        assertThrows(VPAuthenticatorClientException.class,
                () -> vpRequestService.getVPRequestById(REQUEST_ID, TENANT_ID));
    }

    @Test
    public void testGetVPRequestByTransactionId() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .transactionId(TRANSACTION_ID)
                .clientId(CLIENT_ID)
                .build();

        when(vpRequestDAO.getVPRequestByTransactionId(TRANSACTION_ID, TENANT_ID)).thenReturn(vpRequest);

        VPRequest result = vpRequestService.getVPRequestByTransactionId(TRANSACTION_ID, TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getTransactionId(), TRANSACTION_ID);
    }

    @Test
    public void testUpdateVPRequestStatus() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .clientId(CLIENT_ID)
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);
        doNothing().when(vpRequestDAO).updateVPRequestStatus(REQUEST_ID, VPRequestStatus.VP_SUBMITTED, TENANT_ID);

        vpRequestService.updateVPRequestStatus(REQUEST_ID, VPRequestStatus.VP_SUBMITTED, TENANT_ID);

        verify(vpRequestDAO, times(1)).updateVPRequestStatus(REQUEST_ID, VPRequestStatus.VP_SUBMITTED, TENANT_ID);
    }

    @Test
    public void testCreateVPRequestWithRequestedCredentials() throws Exception {
        // PD with requested_credentials instead of input_descriptors
        String pdWithReqCreds = "{\"id\":\"test-pd\",\"requested_credentials\":[{\"type\":"
                + "\"VerifiedEmployee\",\"purpose\":\"Verify employment\",\"requested_claims\":"
                + "[\"given_name\"]}]}";
        VPRequest createRequest = new VPRequest.Builder()
                .clientId(CLIENT_ID)
                .presentationDefinition(pdWithReqCreds)
                .build();

        doNothing().when(vpRequestDAO).createVPRequest(any(VPRequest.class));

        JWSSigner mockSigner = Mockito.mock(JWSSigner.class);
        when(mockSigner.supportedJWSAlgorithms())
                .thenReturn(new java.util.HashSet<>(java.util.Collections.singletonList(JWSAlgorithm.RS256)));
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL("dummy-signature"));

        try (MockedStatic<DIDProviderFactory> mockedFactory = Mockito.mockStatic(DIDProviderFactory.class)) {
            mockedFactory.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(didProvider);
            when(didProvider.getDID(Mockito.anyInt(), Mockito.any())).thenReturn("did:web:localhost");
            when(didProvider.getSigningKeyId(Mockito.anyInt(), Mockito.any()))
                    .thenReturn("did:web:localhost#owner");
            when(didProvider.getSigningAlgorithm()).thenReturn(JWSAlgorithm.RS256);
            when(didProvider.getSigner(Mockito.anyInt())).thenReturn(mockSigner);

            try (MockedStatic<PresentationDefinitionUtil> mockedPDUtil =
                         Mockito.mockStatic(PresentationDefinitionUtil.class)) {
                mockedPDUtil.when(() -> PresentationDefinitionUtil.
                        isValidPresentationDefinition(anyString())).thenReturn(true);
                mockedPDUtil.when(() -> PresentationDefinitionUtil.buildPresentationDefinition(anyString(), anyString(),
                        anyString(), any())).thenReturn("{\"pd\":\"mocked\"}");
                
                VPRequest response = vpRequestService.createVPRequest(createRequest, TENANT_ID);
                assertNotNull(response);
                assertNotNull(response.getRequestId());
            }
        }
    }

    @Test
    public void testCreateVPRequestWithInternalConfig() throws Exception {
        // PD with _internal config
        String pdWithInternal = "{\"id\":\"def-123\",\"_internal\":{\"signing_algorithm\":\"RS256\"},"
                + "\"input_descriptors\":[]}";
        VPRequest createRequest = new VPRequest.Builder()
                .clientId(CLIENT_ID)
                .presentationDefinition(pdWithInternal)
                .build();

        doNothing().when(vpRequestDAO).createVPRequest(any(VPRequest.class));

        JWSSigner mockSigner = Mockito.mock(JWSSigner.class);
        when(mockSigner.supportedJWSAlgorithms())
                .thenReturn(new java.util.HashSet<>(java.util.Collections.singletonList(JWSAlgorithm.RS256)));
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL("dummy-signature"));

        try (MockedStatic<DIDProviderFactory> mockedFactory = Mockito.mockStatic(DIDProviderFactory.class)) {
            mockedFactory.when(() -> DIDProviderFactory.getProvider("web")).thenReturn(didProvider);
            when(didProvider.getDID(Mockito.anyInt(), Mockito.any())).thenReturn("did:web:localhost");
            when(didProvider.getSigningKeyId(Mockito.anyInt(), Mockito.any()))
                    .thenReturn("did:web:localhost#owner");
            when(didProvider.getSigningAlgorithm()).thenReturn(JWSAlgorithm.RS256);
            when(didProvider.getSigner(Mockito.anyInt())).thenReturn(mockSigner);

            try (MockedStatic<PresentationDefinitionUtil> mockedPDUtil =
                         Mockito.mockStatic(PresentationDefinitionUtil.class)) {
                mockedPDUtil.when(() -> PresentationDefinitionUtil.
                isValidPresentationDefinition(anyString())).thenReturn(true);
                VPRequest response = vpRequestService.createVPRequest(createRequest, TENANT_ID);
                assertNotNull(response);
            }
        }
    }

    @Test
    public void testGetVPRequestByIdPopulateDefinition() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .clientId(CLIENT_ID)
                .presentationDefinitionId(DEFINITION_ID)
                .build();
        // presentationDefinition is null in model

        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);
        
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .requestedCredentials(java.util.Collections.emptyList())
                .build();
        when(presentationDefinitionService.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(definition);

        VPRequest result = vpRequestService.getVPRequestById(REQUEST_ID, TENANT_ID);
        assertNotNull(result.getPresentationDefinition());
    }

    @Test
    public void testGetVPRequestByTransactionIdPopulateDefinition() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .transactionId(TRANSACTION_ID)
                .clientId(CLIENT_ID)
                .presentationDefinitionId(DEFINITION_ID)
                .build();

        when(vpRequestDAO.getVPRequestByTransactionId(TRANSACTION_ID, TENANT_ID)).thenReturn(vpRequest);
        
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .requestedCredentials(java.util.Collections.emptyList())
                .build();
        when(presentationDefinitionService.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(definition);

        VPRequest result = vpRequestService.getVPRequestByTransactionId(TRANSACTION_ID, TENANT_ID);
        assertNotNull(result.getPresentationDefinition());
    }

    @Test
    public void testGetVPRequestStatus() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .transactionId(TRANSACTION_ID)
                .requestId(REQUEST_ID)
                .status(VPRequestStatus.ACTIVE)
                .build();
        when(vpRequestDAO.getVPRequestByTransactionId(TRANSACTION_ID, TENANT_ID)).thenReturn(vpRequest);

        VPRequest result = 
            vpRequestService.getVPRequestStatus(TRANSACTION_ID, TENANT_ID);
        assertEquals(result.getStatus(), VPRequestStatus.ACTIVE);
    }

    @Test
    public void testGetRequestUri() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder().requestId(REQUEST_ID).build();
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);
        
        String uri = vpRequestService.getRequestUri(REQUEST_ID, TENANT_ID);
        assertNotNull(uri);
    }

    @Test
    public void testGetRequestJwt() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 600000)
                .requestJwt("dummy-jwt")
                .build();
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);

        String jwt = vpRequestService.getRequestJwt(REQUEST_ID, TENANT_ID);
        assertEquals(jwt, "dummy-jwt");
    }

    @Test(expectedExceptions = VPAuthenticatorClientException.class)
    public void testGetRequestJwtInactive() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .status(VPRequestStatus.COMPLETED)
                .expiresAt(System.currentTimeMillis() + 600000)
                .build();
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);

        vpRequestService.getRequestJwt(REQUEST_ID, TENANT_ID);
    }


}
