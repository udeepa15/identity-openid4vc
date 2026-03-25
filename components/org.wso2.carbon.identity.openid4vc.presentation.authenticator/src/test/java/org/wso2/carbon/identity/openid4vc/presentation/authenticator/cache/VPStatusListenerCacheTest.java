package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class VPStatusListenerCacheTest {

    private VPStatusListenerCache cache;

    @BeforeMethod
    public void setUp() {
        cache = VPStatusListenerCache.getInstance();
        // Since it's a singleton, we can't easily clear it without special methods, 
        // but we can register new listeners.
    }

    @Test
    public void testRegisterAndNotify() {
        AtomicReference<String> result = new AtomicReference<>();
        cache.registerListener("req1", "l1", new VPStatusListenerCache.StatusCallback() {
            @Override
            public void onStatusChange(String status) {
                result.set(status);
            }
            @Override
            public void onTimeout() {}
        });
        
        assertEquals(cache.getListenerCount("req1"), 1);
        assertTrue(cache.hasActiveListeners("req1"));
        
        cache.notifyListeners("req1", "COMPLETED");
        assertEquals(result.get(), "COMPLETED");
    }

    @Test
    public void testNotifyWithSubmission() {
        AtomicReference<VPSubmission> result = new AtomicReference<>();
        cache.registerListener("req2", "l2", new VPStatusListenerCache.StatusCallback() {
            @Override
            public void onStatusChange(String status) {}
            @Override
            public void onTimeout() {}
            @Override
            public void onSubmissionReceived(VPSubmission submission) {
                result.set(submission);
            }
        });
        
        VPSubmission submission = new VPSubmission();
        cache.notifyListenersWithSubmission("req2", submission);
        assertNotNull(result.get());
    }

    @Test
    public void testRemoveListener() {
        cache.registerListener("req3", "l3", null);
        assertEquals(cache.getListenerCount("req3"), 1);
        cache.removeListener("req3", "l3");
        assertEquals(cache.getListenerCount("req3"), 0);
    }

    @Test
    public void testStatusListenerTimeout() throws Exception {
        VPStatusListenerCache.StatusListener listener = new VPStatusListenerCache.StatusListener("l4", -100, null);
        assertTrue(listener.isTimedOut());
        listener.notifyTimeout();
        assertTrue(listener.isNotified());
    }
}
