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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.status;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.testng.Assert.assertEquals;

public class StatusNotificationServiceTest {

    private StatusNotificationService statusNotificationService;

    @BeforeMethod
    public void setUp() throws Exception {
        statusNotificationService = StatusNotificationService.getInstance();

        Field listenersField = statusNotificationService.getClass().getDeclaredField("statusChangeListeners");
        listenersField.setAccessible(true);
        ((java.util.List<?>) listenersField.get(statusNotificationService)).clear();
    }

    @AfterMethod
    public void tearDown() {
        // No-op.
    }

    @Test
    public void testNotifyVPSubmitted() {
        StatusNotificationService.StatusChangeListener listener =
            mock(StatusNotificationService.StatusChangeListener.class);
        statusNotificationService.registerStatusChangeListener(listener);

        VPSubmission submission = new VPSubmission.Builder()
                .requestId("req123")
                .vpToken("token")
                .build();

        statusNotificationService.notifyVPSubmitted("req123", submission);

        verify(listener).onStatusChange("req123", VPRequestStatus.VP_SUBMITTED, submission);
    }

    @Test
    public void testNotifySubmissionError() {
        StatusNotificationService.StatusChangeListener listener =
            mock(StatusNotificationService.StatusChangeListener.class);
        statusNotificationService.registerStatusChangeListener(listener);

        statusNotificationService.notifySubmissionError("req123", "error_code", "description");

        verify(listener).onStatusChange(Mockito.eq("req123"), Mockito.eq(VPRequestStatus.VP_SUBMITTED),
            Mockito.argThat(submission -> "error_code".equals(submission.getError())
                && "description".equals(submission.getErrorDescription())));
    }

    @Test
    public void testNotifyRequestExpired() {
        StatusNotificationService.StatusChangeListener listener =
            mock(StatusNotificationService.StatusChangeListener.class);
        statusNotificationService.registerStatusChangeListener(listener);

        statusNotificationService.notifyRequestExpired("req123");

        verify(listener).onStatusChange("req123", VPRequestStatus.EXPIRED, null);
    }

    @Test
    public void testNotifyVerificationComplete() {
        StatusNotificationService.StatusChangeListener listener =
            mock(StatusNotificationService.StatusChangeListener.class);
        statusNotificationService.registerStatusChangeListener(listener);

        VPSubmission submission = new VPSubmission();
        statusNotificationService.notifyVerificationComplete("req123", submission);

        verify(listener).onStatusChange("req123", VPRequestStatus.COMPLETED, submission);
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

        statusNotificationService.notifyRequestExpired("req124");
        verifyNoMoreInteractions(listener);
    }
}
