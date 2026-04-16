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

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.lang.reflect.Field;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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
        addStatusChangeListener(listener);

        statusNotificationService.notifyVPSubmitted("req123");

        verify(listener).onStatusChange("req123", VPRequestStatus.VP_SUBMITTED);
    }

    @SuppressWarnings("unchecked")
    private void addStatusChangeListener(final StatusNotificationService.StatusChangeListener listener) {

        try {
            Field listenersField = statusNotificationService.getClass().getDeclaredField("statusChangeListeners");
            listenersField.setAccessible(true);
            List<StatusNotificationService.StatusChangeListener> listeners =
                    (List<StatusNotificationService.StatusChangeListener>) 
                    listenersField.get(statusNotificationService);
            listeners.add(listener);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to add status change listener for test setup.", e);
        }
    }
}
