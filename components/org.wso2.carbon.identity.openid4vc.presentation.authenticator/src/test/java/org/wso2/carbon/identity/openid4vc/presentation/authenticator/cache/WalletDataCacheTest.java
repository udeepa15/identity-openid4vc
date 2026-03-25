package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class WalletDataCacheTest {

    private WalletDataCache cache;

    @BeforeMethod
    public void setUp() {
        cache = WalletDataCache.getInstance();
    }

    @Test
    public void testTokenCache() {
        cache.storeToken("state1", "token1");
        assertTrue(cache.hasToken("state1"));
        assertEquals(cache.retrieveToken("state1"), "token1");
        assertFalse(cache.hasToken("state1")); // Single-use
    }

    @Test
    public void testSubmissionCache() {
        VPSubmission submission = new VPSubmission();
        cache.storeSubmission("req1", submission);
        assertTrue(cache.hasSubmission("req1"));
        assertNotNull(cache.getSubmission("req1"));
        assertEquals(cache.retrieveSubmission("req1"), submission);
        assertFalse(cache.hasSubmission("req1")); // Single-use
    }
}
