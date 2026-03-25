package org.wso2.carbon.identity.openid4vc.presentation.authenticator.dao.impl;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPRequestCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequestStatus;

import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class VPRequestDAOImplTest {

    private VPRequestDAOImpl vpRequestDAO;

    @Mock
    private VPRequestCache vpRequestCache;

    private MockedStatic<VPRequestCache> mockedCache;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        mockedCache = Mockito.mockStatic(VPRequestCache.class);
        mockedCache.when(VPRequestCache::getInstance).thenReturn(vpRequestCache);
        vpRequestDAO = new VPRequestDAOImpl();
    }

    @AfterMethod
    public void tearDown() {
        mockedCache.close();
    }

    @Test
    public void testCreateVPRequest() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").build();
        vpRequestDAO.createVPRequest(request);
        verify(vpRequestCache).put(request);
    }

    @Test
    public void testGetVPRequestById() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCache.getByRequestId("req1")).thenReturn(request);

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
        when(vpRequestCache.getByTransactionId("tx1")).thenReturn(request);

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
        when(vpRequestCache.getByTransactionId("tx1")).thenReturn(request);

        List<String> ids = vpRequestDAO.getRequestIdsByTransactionId("tx1", -1234);
        assertEquals(ids.size(), 1);
        assertEquals(ids.get(0), "req1");
    }

    @Test
    public void testUpdateVPRequestStatus() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .status(VPRequestStatus.ACTIVE).build();
        when(vpRequestCache.getByRequestId("req1")).thenReturn(request);

        vpRequestDAO.updateVPRequestStatus("req1", VPRequestStatus.COMPLETED, -1234);
        assertEquals(request.getStatus(), VPRequestStatus.COMPLETED);
        verify(vpRequestCache).put(request);
    }

    @Test
    public void testUpdateVPRequestJwt() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCache.getByRequestId("req1")).thenReturn(request);

        vpRequestDAO.updateVPRequestJwt("req1", "new-jwt", -1234);
        assertEquals(request.getRequestJwt(), "new-jwt");
        verify(vpRequestCache).put(request);
    }

    @Test
    public void testDeleteVPRequest() throws Exception {
        VPRequest request = new VPRequest.Builder().requestId("req1").tenantId(-1234)
                .build();
        when(vpRequestCache.getByRequestId("req1")).thenReturn(request);

        vpRequestDAO.deleteVPRequest("req1", -1234);
        verify(vpRequestCache).remove("req1");
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
