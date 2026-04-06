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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.polling;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCacheByRequestId;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSubmissionRequestIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.lang.reflect.Field;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class LongPollingManagerTest {

    private PollingManager pollingManager;

    @Mock
    private VPRequestDAO vpRequestDAO;

    @Mock
    private VPSubmissionCacheByRequestId vpSubmissionCache;

    private MockedStatic<VPSubmissionCacheByRequestId> mockedCache;

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty("carbon.home", ".");
        MockitoAnnotations.openMocks(this);
        mockedCache = Mockito.mockStatic(VPSubmissionCacheByRequestId.class);
        mockedCache.when(VPSubmissionCacheByRequestId::getInstance).thenReturn(vpSubmissionCache);
        
        pollingManager = PollingManager.getInstance();

        // Use reflection to inject mocks into singleton
        setPrivateField(pollingManager, "vpRequestDAO", vpRequestDAO);
        setPrivateField(pollingManager, "vpSubmissionCache", vpSubmissionCache);
    }

    @AfterMethod
    public void tearDown() {
        if (mockedCache != null) {
            mockedCache.close();
        }
    }

    @Test
    public void testCheckCurrentStatusSubmittedInCache() {
        VPSubmissionCacheEntry mockEntry = Mockito.mock(VPSubmissionCacheEntry.class);
        when(vpSubmissionCache.getValueFromCache(any(VPSubmissionRequestIdCacheKey.class), anyInt()))
                .thenReturn(mockEntry);
        PollingResult result = pollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), VPRequestStatus.VP_SUBMITTED.name());
        assertEquals(result.getResultStatus(), PollingResult.ResultStatus.SUBMITTED);
    }

    @Test
    public void testCheckCurrentStatusInDb() throws Exception {
        when(vpSubmissionCache.getValueFromCache(any(VPSubmissionRequestIdCacheKey.class), anyInt()))
                .thenReturn(null);
        
        VPRequest request = new VPRequest.Builder()
                .status(VPRequestStatus.COMPLETED)
                .build();
        when(vpRequestDAO.getVPRequestById(anyString(), anyInt())).thenReturn(request);

        PollingResult result = pollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), VPRequestStatus.VP_SUBMITTED.name());
        assertEquals(result.getResultStatus(), PollingResult.ResultStatus.SUBMITTED);
    }

    @Test
    public void testCheckCurrentStatusExpired() throws Exception {
        when(vpSubmissionCache.getValueFromCache(any(VPSubmissionRequestIdCacheKey.class), anyInt()))
                .thenReturn(null);
        
        VPRequest request = new VPRequest.Builder()
                .status(VPRequestStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() - 1000) // Past
                .build();
        when(vpRequestDAO.getVPRequestById(anyString(), anyInt())).thenReturn(request);

        PollingResult result = pollingManager.checkCurrentStatus("test-id", 1);
        
        assertNotNull(result);
        assertEquals(result.getStatus(), "EXPIRED");
        assertEquals(result.getResultStatus(), PollingResult.ResultStatus.EXPIRED);
    }

    private void setPrivateField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
