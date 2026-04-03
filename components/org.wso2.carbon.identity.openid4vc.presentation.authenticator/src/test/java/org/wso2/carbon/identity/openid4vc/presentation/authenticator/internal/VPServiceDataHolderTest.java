package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDDocumentService;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.user.core.service.RealmService;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class VPServiceDataHolderTest {

    @Mock
    private RealmService realmService;
    @Mock
    private VPRequestServiceImpl vpRequestService;
    @Mock
    private PresentationDefinitionService presentationDefinitionService;
    @Mock
    private VerificationService verificationService;
    @Mock
    private DIDDocumentService didDocumentService;
    @Mock
    private ApplicationManagementService applicationManagementService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetSetRealmService() {
        VPServiceDataHolder.setRealmService(realmService);
        assertEquals(VPServiceDataHolder.getRealmService(), realmService);
        VPServiceDataHolder.setRealmService(null);
        assertNull(VPServiceDataHolder.getRealmService());
    }

    @Test
    public void testGetSetVPRequestService() {
        VPServiceDataHolder.setVPRequestService(vpRequestService);
        assertEquals(VPServiceDataHolder.getVPRequestService(), vpRequestService);
        VPServiceDataHolder.setVPRequestService(null);
        assertNull(VPServiceDataHolder.getVPRequestService());
    }

    @Test
    public void testGetSetPresentationDefinitionService() {
        VPServiceDataHolder.setPresentationDefinitionService(presentationDefinitionService);
        assertEquals(VPServiceDataHolder.getPresentationDefinitionService(), presentationDefinitionService);
        VPServiceDataHolder.setPresentationDefinitionService(null);
        assertNull(VPServiceDataHolder.getPresentationDefinitionService());
    }

    @Test
    public void testGetSetVerificationService() {
        VPServiceDataHolder.setVerificationService(verificationService);
        assertEquals(VPServiceDataHolder.getVerificationService(), verificationService);
        
        // VerificationService is OSGi-injected, no lazy initialization in data holder
        VPServiceDataHolder.setVerificationService(null);
        assertNull(VPServiceDataHolder.getVerificationService());
    }

    @Test
    public void testGetSetDIDDocumentService() {
        VPServiceDataHolder.setDIDDocumentService(didDocumentService);
        assertEquals(VPServiceDataHolder.getDIDDocumentService(), didDocumentService);
        
        // Test lazy initialization if set to null
        VPServiceDataHolder.setDIDDocumentService(null);
        assertNotNull(VPServiceDataHolder.getDIDDocumentService());
    }

    @Test
    public void testGetSetApplicationManagementService() {
        VPServiceDataHolder.setApplicationManagementService(applicationManagementService);
        assertEquals(VPServiceDataHolder.getApplicationManagementService(), applicationManagementService);
        VPServiceDataHolder.setApplicationManagementService(null);
        assertNull(VPServiceDataHolder.getApplicationManagementService());
    }
}
