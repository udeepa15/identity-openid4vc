package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class SecurityUtilsTest {

    @Test
    public void testGenerateNonce() {
        String nonce = SecurityUtils.generateNonce();
        assertNotNull(nonce);
        assertTrue(nonce.length() > 0);
    }

    @Test
    public void testGenerateNonceWithLength() {
        String nonce = SecurityUtils.generateNonce(16);
        assertNotNull(nonce);
    }

    @Test
    public void testGenerateState() {
        String state = SecurityUtils.generateState();
        assertNotNull(state);
    }

    @Test
    public void testIsValidUrl() {
        assertTrue(SecurityUtils.isValidUrl("https://example.com"));
        assertTrue(SecurityUtils.isValidUrl("http://localhost:8080"));
        assertFalse(SecurityUtils.isValidUrl("invalid-url"));
        assertFalse(SecurityUtils.isValidUrl(null));
        assertFalse(SecurityUtils.isValidUrl(""));
        assertFalse(SecurityUtils.isValidUrl("ftp://example.com"));
    }

    @Test
    public void testIsSafeRedirectUri() {
        assertTrue(SecurityUtils.isSafeRedirectUri("https://example.com/callback"));
        assertTrue(SecurityUtils.isSafeRedirectUri("http://localhost:9000/callback"));
        assertTrue(SecurityUtils.isSafeRedirectUri("/relative/path"));
        assertFalse(SecurityUtils.isSafeRedirectUri("http://malicious.com"));
        assertFalse(SecurityUtils.isSafeRedirectUri("https://example.com#fragment"));
        assertFalse(SecurityUtils.isSafeRedirectUri(null));
    }

    @Test
    public void testSanitizeForLogging() {
        assertEquals(SecurityUtils.sanitizeForLogging(null, 5), "[empty]");
        assertEquals(SecurityUtils.sanitizeForLogging("", 5), "[empty]");
        assertEquals(SecurityUtils.sanitizeForLogging("short", 5), "[masked]");
        String longStr = "123456789012345";
        String sanitized = SecurityUtils.sanitizeForLogging(longStr, 3);
        assertTrue(sanitized.startsWith("123"));
        assertTrue(sanitized.endsWith("345"));
        assertTrue(sanitized.contains("..."));
    }

    @Test
    public void testSha256() {
        String input = "test-input";
        String hash = SecurityUtils.sha256(input);
        assertNotNull(hash);
        assertEquals(hash.length(), 64); // SHA-256 hex is 64 chars
    }
}
