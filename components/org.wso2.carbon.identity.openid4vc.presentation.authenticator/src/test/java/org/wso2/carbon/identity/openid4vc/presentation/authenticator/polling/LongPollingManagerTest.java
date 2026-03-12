/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.WalletDataCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class LongPollingManagerTest {

    private LongPollingManager longPollingManager;

    @Mock
    private VPRequestDAO vpRequestDAO;

    @Mock
    private WalletDataCache walletDataCache;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        longPollingManager = LongPollingManager.getInstance();

        // Use reflection to inject mocks into singleton
        setPrivateField(longPollingManager, "vpRequestDAO", vpRequestDAO);
        setPrivateField(longPollingManager, "walletDataCache", walletDataCache);
    }

    @Test
    public void testCheckCurrentStatusSubmittedInCache() {
        when(walletDataCache.hasToken(anyString())).thenReturn(true);
        PollingResult result = longPollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), VPRequestStatus.VP_SUBMITTED.name());
        assertTrue(result.isComplete());
    }

    @Test
    public void testCheckCurrentStatusInDb() throws Exception {
        when(walletDataCache.hasToken(anyString())).thenReturn(false);
        when(walletDataCache.hasSubmission(anyString())).thenReturn(false);
        
        VPRequest request = new VPRequest.Builder()
                .status(VPRequestStatus.COMPLETED)
                .build();
        when(vpRequestDAO.getVPRequestById(anyString(), anyInt())).thenReturn(request);

        PollingResult result = longPollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), VPRequestStatus.COMPLETED.name());
        assertTrue(result.isComplete());
    }

    @Test
    public void testCheckCurrentStatusExpired() throws Exception {
        when(walletDataCache.hasToken(anyString())).thenReturn(false);
        when(walletDataCache.hasSubmission(anyString())).thenReturn(false);
        
        VPRequest request = new VPRequest.Builder()
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() - 1000) // Past
                .build();
        when(vpRequestDAO.getVPRequestById(anyString(), anyInt())).thenReturn(request);

        PollingResult result = longPollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), "EXPIRED");
    }

    @Test
    public void testGetDefaultPollingTimeoutMs() {
        assertEquals(longPollingManager.getDefaultPollingTimeoutMs(), 5000L);
    }

    private void setPrivateField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
