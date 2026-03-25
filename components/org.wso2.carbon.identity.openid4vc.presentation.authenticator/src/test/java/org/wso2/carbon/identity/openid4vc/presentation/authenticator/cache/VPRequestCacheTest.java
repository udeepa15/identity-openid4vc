package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPRequest;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class VPRequestCacheTest {

    private VPRequestCache cache;

    @BeforeMethod
    public void setUp() {
        cache = VPRequestCache.getInstance();
        cache.clear();
    }

    @Test
    public void testPutAndGet() {
        VPRequest request = new VPRequest.Builder()
                .requestId("id1")
                .transactionId("tx1")
                .tenantId(-1234)
                .build();
        
        cache.put(request);
        
        VPRequest retrieved = cache.getByRequestId("id1");
        assertNotNull(retrieved);
        assertEquals(retrieved.getRequestId(), "id1");
        
        retrieved = cache.getByTransactionId("tx1");
        assertNotNull(retrieved);
        assertEquals(retrieved.getTransactionId(), "tx1");
    }

    @Test
    public void testRemove() {
        VPRequest request = new VPRequest.Builder()
                .requestId("id1")
                .transactionId("tx1")
                .build();
        
        cache.put(request);
        assertTrue(cache.contains("id1"));
        
        cache.remove("id1");
        assertFalse(cache.contains("id1"));
        assertNull(cache.getByTransactionId("tx1"));
    }

    @Test
    public void testCleanupAndEviction() throws Exception {
        // Fill cache up to limit
        for (int i = 0; i < 100; i++) {
            cache.put(new VPRequest.Builder().requestId("id" + i).build());
        }
        
        // Use reflection to call private cleanup
        java.lang.reflect.Method cleanup = VPRequestCache.class.getDeclaredMethod("cleanup");
        cleanup.setAccessible(true);
        cleanup.invoke(cache);
        
        // Use reflection to call private evictOldestEntries
        java.lang.reflect.Method evict = VPRequestCache.class.getDeclaredMethod("evictOldestEntries", int.class);
        evict.setAccessible(true);
        evict.invoke(cache, 10);
        
        assertTrue(cache.size() <= 90);
    }

    @Test
    public void testShutdown() {
        cache.shutdown();
        assertEquals(cache.size(), 0);
    }
}
