package org.wso2.carbon.identity.openid4vc.presentation.authenticator.status;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPStatusListenerCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling.LongPollingManager;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;

public class StatusNotificationServiceTest {

    private StatusNotificationService statusNotificationService;

    @Mock
    private VPStatusListenerCache statusListenerCache;

    @Mock
    private LongPollingManager longPollingManager;

    private MockedStatic<VPStatusListenerCache> mockedVPStatusListenerCache;
    private MockedStatic<LongPollingManager> mockedLongPollingManager;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        
        mockedVPStatusListenerCache = Mockito.mockStatic(VPStatusListenerCache.class);
        mockedVPStatusListenerCache.when(VPStatusListenerCache::getInstance).thenReturn(statusListenerCache);

        mockedLongPollingManager = Mockito.mockStatic(LongPollingManager.class);
        mockedLongPollingManager.when(LongPollingManager::getInstance).thenReturn(longPollingManager);

        statusNotificationService = StatusNotificationService.getInstance();
        
        // Inject mocks
        setPrivateField(statusNotificationService, "statusListenerCache", statusListenerCache);
        setPrivateField(statusNotificationService, "longPollingManager", longPollingManager);
    }

    @AfterMethod
    public void tearDown() {
        mockedVPStatusListenerCache.close();
        mockedLongPollingManager.close();
    }

    @Test
    public void testNotifyVPSubmitted() {
        VPSubmission submission = new VPSubmission.Builder()
                .requestId("req123")
                .vpToken("token")
                .build();
        
        statusNotificationService.notifyVPSubmitted("req123", submission);
        
        verify(statusListenerCache).notifyListeners("req123", "VP_SUBMITTED");
        verify(longPollingManager).notifySubmission("req123", "VP_SUBMITTED");
    }

    @Test
    public void testNotifySubmissionError() {
        statusNotificationService.notifySubmissionError("req123", "error_code", "description");
        
        verify(statusListenerCache).notifyListeners("req123", "VP_SUBMITTED_ERROR");
        verify(longPollingManager).notifySubmission("req123", "VP_SUBMITTED_ERROR");
    }

    @Test
    public void testNotifyRequestExpired() {
        statusNotificationService.notifyRequestExpired("req123");
        
        verify(statusListenerCache).notifyListeners("req123", "EXPIRED");
        verify(statusListenerCache).removeAllListeners("req123");
    }

    @Test
    public void testNotifyVerificationComplete() {
        VPSubmission submission = new VPSubmission();
        statusNotificationService.notifyVerificationComplete("req123", submission);
        
        verify(statusListenerCache).notifyListeners("req123", "COMPLETED");
        verify(statusListenerCache).removeAllListeners("req123");
    }

    @Test
    public void testListeners() {
        StatusNotificationService.StatusChangeListener listener =
                mock(StatusNotificationService.StatusChangeListener.class);
        statusNotificationService.registerStatusChangeListener(listener);
        assertEquals(statusNotificationService.getStatusChangeListenerCount(), 1);
        
        statusNotificationService.notifyRequestExpired("req123");
        verify(listener).onStatusChange(anyString(), Mockito.eq(VPRequestStatus.EXPIRED),
                Mockito.any());
        
        statusNotificationService.unregisterStatusChangeListener(listener);
        assertEquals(statusNotificationService.getStatusChangeListenerCount(), 0);
    }

    private void setPrivateField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
