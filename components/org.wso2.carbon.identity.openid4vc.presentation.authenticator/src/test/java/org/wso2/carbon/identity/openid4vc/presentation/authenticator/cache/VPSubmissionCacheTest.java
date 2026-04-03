package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPSubmission;

import static org.testng.Assert.assertNotNull;

public class VPSubmissionCacheTest {

    private VPSubmissionCache cache;

    @BeforeMethod
    public void setUp() {
        cache = VPSubmissionCache.getInstance();
    }

    @Test
    public void testSubmissionCache() {
        VPSubmission submission = new VPSubmission();
        cache.storeSubmission("req1", submission);
        assertNotNull(cache.getSubmission("req1"));
        assertNotNull(cache.getSubmission("req1"));
    }
}
