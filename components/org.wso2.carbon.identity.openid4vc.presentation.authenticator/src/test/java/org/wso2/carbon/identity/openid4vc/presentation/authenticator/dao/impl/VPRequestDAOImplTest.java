/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheById;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheByTransactionId;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestTransactionIdCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.VPRequestDAO;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class VPRequestDAOImplTest {

    private VPRequestDAO vpRequestDAO;

    @Mock
    private VPRequestCacheById vpRequestCacheById;
    @Mock
    private VPRequestCacheByTransactionId vpRequestCacheByTransactionId;

    private MockedStatic<VPRequestCacheById> mockedCacheById;
    private MockedStatic<VPRequestCacheByTransactionId> mockedCacheByTransactionId;

    @BeforeMethod
    public void setUp() {
        System.setProperty("carbon.home", ".");
        MockitoAnnotations.openMocks(this);
        mockedCacheById = Mockito.mockStatic(VPRequestCacheById.class);
        mockedCacheById.when(VPRequestCacheById::getInstance).thenReturn(vpRequestCacheById);
        mockedCacheByTransactionId = Mockito.mockStatic(VPRequestCacheByTransactionId.class);
        mockedCacheByTransactionId.when(VPRequestCacheByTransactionId::getInstance)
                .thenReturn(vpRequestCacheByTransactionId);
        vpRequestDAO = new VPRequestDAO();
    }

    @AfterMethod
    public void tearDown() {
        if (mockedCacheById != null) {
            mockedCacheById.close();
        }
        if (mockedCacheByTransactionId != null) {
            mockedCacheByTransactionId.close();
        }
    }

    @Test
    public void testCreateVPRequest() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").transactionId("tx1").build();
        vpRequestDAO.createVPRequest(request);
        verify(vpRequestCacheById).addToCache(any(VPRequestIdCacheKey.class), 
                any(VPRequestCacheEntry.class), anyInt());
    }

    @Test
    public void testGetVPRequestById() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCacheById.getValueFromCache(any(VPRequestIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        VPRequest result = vpRequestDAO.getVPRequestById("req1", -1234);
        assertNotNull(result);
        assertEquals(result.getRequestId(), "req1");

        // Test cross-tenant
        result = vpRequestDAO.getVPRequestById("req1", 1);
        assertNull(result);
    }

    @Test
    public void testGetVPRequestByTransactionId() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").transactionId("tx1")
                .tenantId(-1234).build();
        when(vpRequestCacheByTransactionId.getValueFromCache(any(VPRequestTransactionIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        VPRequest result = vpRequestDAO.getVPRequestByTransactionId("tx1", -1234);
        assertNotNull(result);
        assertEquals(result.getTransactionId(), "tx1");

        // Test cross-tenant
        result = vpRequestDAO.getVPRequestByTransactionId("tx1", 1);
        assertNull(result);
    }

    @Test
    public void testGetRequestIdsByTransactionId() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").transactionId("tx1")
                .tenantId(-1234).build();
        when(vpRequestCacheByTransactionId.getValueFromCache(any(VPRequestTransactionIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        List<String> ids = vpRequestDAO.getRequestIdsByTransactionId("tx1", -1234);
        assertEquals(ids.size(), 1);
        assertEquals(ids.get(0), "req1");
    }

    @Test
    public void testUpdateVPRequestStatus() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .status(VPRequestStatus.ACTIVE).build();
        when(vpRequestCacheById.getValueFromCache(any(VPRequestIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        vpRequestDAO.updateVPRequestStatus("req1", VPRequestStatus.COMPLETED, -1234);
        assertEquals(request.getStatus(), VPRequestStatus.COMPLETED);
    }

    @Test
    public void testUpdateVPRequestJwt() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCacheById.getValueFromCache(any(VPRequestIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        vpRequestDAO.updateVPRequestJwt("req1", "new-jwt", -1234);
        assertEquals(request.getRequestJwt(), "new-jwt");
    }

    @Test
    public void testDeleteVPRequest() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCacheById.getValueFromCache(any(VPRequestIdCacheKey.class), 
                anyInt())).thenReturn(new VPRequestCacheEntry(request));

        vpRequestDAO.deleteVPRequest("req1", -1234);
        verify(vpRequestCacheById).clearCacheEntry(any(VPRequestIdCacheKey.class), 
                anyInt());
    }

    @Test
    public void testGetExpiredVPRequests() throws Exception {
        assertTrue(vpRequestDAO.getExpiredVPRequests(-1234).isEmpty());
    }

    @Test
    public void testMarkExpiredRequests() throws Exception {
        assertEquals(vpRequestDAO.markExpiredRequests(-1234), 0);
    }

    @Test
    public void testGetVPRequestsByStatus() throws Exception {
        assertTrue(vpRequestDAO.getVPRequestsByStatus(VPRequestStatus.ACTIVE, -1234).isEmpty());
    }
}
