package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPRequestServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class VPServiceRegistrationComponentTest {

    private VPServiceRegistrationComponent component;

    @Mock
    private ComponentContext componentContext;

    @Mock
    private BundleContext bundleContext;

    @Mock
    private PresentationDefinitionService presentationDefinitionService;

    private MockedStatic<VPServiceDataHolder> mockedDataHolder;


    @BeforeMethod
    public void setUp() {
        System.setProperty("carbon.home", ".");
        MockitoAnnotations.openMocks(this);
        
        component = new VPServiceRegistrationComponent();
        when(componentContext.getBundleContext()).thenReturn(bundleContext);
        mockedDataHolder = Mockito.mockStatic(VPServiceDataHolder.class);
    }

    @AfterMethod
    public void tearDown() {
        if (mockedDataHolder != null) {
            mockedDataHolder.close();
        }
    }

    @Test
    public void testActivate() {
        component.activate(componentContext);

        // Verify service registrations
        verify(bundleContext, atLeastOnce())
            .registerService(eq(VPRequestServiceImpl.class.getName()), any(), any());
        verify(bundleContext, atLeastOnce())
            .registerService(eq(ApplicationAuthenticator.class.getName()), any(), any());
        
        // Verify data holder update
        mockedDataHolder.verify(() -> VPServiceDataHolder.setVPRequestService(any()), atLeastOnce());
    }

    @Test
    public void testDeactivate() {
        component.deactivate(componentContext);
        mockedDataHolder.verify(() -> VPServiceDataHolder.setVPRequestService(null));
    }

    @Test
    public void testSetPresentationDefinitionService() {
        mockedDataHolder.close(); // Need to use real static method for this test
        mockedDataHolder = null;
        
        component.setPresentationDefinitionService(presentationDefinitionService);
        assertNotNull(VPServiceDataHolder.getPresentationDefinitionService());
        
        component.unsetPresentationDefinitionService(presentationDefinitionService);
        assertNull(VPServiceDataHolder.getPresentationDefinitionService());
    }
}
