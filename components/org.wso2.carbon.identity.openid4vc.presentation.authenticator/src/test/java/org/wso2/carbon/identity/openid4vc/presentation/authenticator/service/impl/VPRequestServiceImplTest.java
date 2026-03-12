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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestCreateDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dto.VPRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPServiceDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProvider;
import org.wso2.carbon.identity.openid4vc.presentation.did.provider.DIDProviderFactory;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;

import static org.mockito.ArgumentMatchers.any;
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
    private static final String DEFINITION_JSON = "{\"id\":\"def-123\",\"input_descriptors\":[{\"id\":\"desc-1\"," +
            "\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"]}]}}]}";

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        identityUtilMockedStatic = Mockito.mockStatic(IdentityUtil.class);
        identityUtilMockedStatic.when(() -> IdentityUtil.getProperty(any())).thenReturn("http://localhost:8080");

        vpRequestService = new VPRequestServiceImpl(vpRequestDAO, presentationDefinitionService, 
                "http://localhost:8080");

        // Inject Mock PresentationDefinitionService into DataHolder
        VPServiceDataHolder.getInstance().setPresentationDefinitionService(presentationDefinitionService);
    }

    @AfterMethod
    public void tearDown() {
        identityUtilMockedStatic.close();
    }

    @Test
    public void testCreateVPRequest() throws Exception {
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setPresentationDefinitionId(DEFINITION_ID);
        createDTO.setResponseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST);
        createDTO.setDidMethod("web");

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

            VPRequestResponseDTO responseDTO = vpRequestService.createVPRequest(createDTO, TENANT_ID);

            assertNotNull(responseDTO);
            assertNotNull(responseDTO.getRequestId());
            assertNotNull(responseDTO.getTransactionId());
            assertNotNull(responseDTO.getAuthorizationDetails());
        }
    }

    @Test
    public void testCreateVPRequestWithInlinePresentationDefinition() throws Exception {
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);
        createDTO.setPresentationDefinition(com.google.gson.JsonParser.parseString(DEFINITION_JSON).getAsJsonObject());
        createDTO.setResponseMode(OpenID4VPConstants.Protocol.RESPONSE_MODE_DIRECT_POST);

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

            VPRequestResponseDTO responseDTO = vpRequestService.createVPRequest(createDTO, TENANT_ID);

            assertNotNull(responseDTO);
            assertNotNull(responseDTO.getRequestId());
        }
    }

    @Test
    public void testCreateVPRequestMissingClientId() throws Exception {
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setPresentationDefinitionId(DEFINITION_ID);

        assertThrows(VPException.class, () -> vpRequestService.createVPRequest(createDTO, TENANT_ID));
    }

    @Test
    public void testCreateVPRequestMissingPresentationDefinition() throws Exception {
        VPRequestCreateDTO createDTO = new VPRequestCreateDTO();
        createDTO.setClientId(CLIENT_ID);

        assertThrows(VPException.class, () -> vpRequestService.createVPRequest(createDTO, TENANT_ID));
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

        assertThrows(VPException.class, () -> vpRequestService.getVPRequestById(REQUEST_ID, TENANT_ID));
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
    public void testDeleteVPRequest() throws Exception {
        VPRequest vpRequest = new VPRequest.Builder()
                .requestId(REQUEST_ID)
                .clientId(CLIENT_ID)
                .build();
        when(vpRequestDAO.getVPRequestById(REQUEST_ID, TENANT_ID)).thenReturn(vpRequest);
        doNothing().when(vpRequestDAO).deleteVPRequest(REQUEST_ID, TENANT_ID);

        vpRequestService.deleteVPRequest(REQUEST_ID, TENANT_ID);

        verify(vpRequestDAO, times(1)).deleteVPRequest(REQUEST_ID, TENANT_ID);
    }
}
