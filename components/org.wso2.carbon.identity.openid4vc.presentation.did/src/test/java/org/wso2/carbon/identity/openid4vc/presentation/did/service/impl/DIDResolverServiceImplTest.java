package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;

import java.security.PublicKey;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

/**
 * Unit tests for DIDResolverServiceImpl.
 */
public class DIDResolverServiceImplTest {

    private DIDResolverServiceImpl resolver;

    @BeforeClass
    public void setupSystemProperties() {
        System.setProperty("carbon.home", ".");
    }

    @BeforeMethod
    public void setUp() {
        resolver = new DIDResolverServiceImpl();
    }



    @Test
    public void testResolveDidWeb() throws Exception {
        String did = "did:web:example.com";
        String mockResponse = "{\"id\":\"did:web:example.com\",\"verificationMethod\":[{\"id\":\"" +
                "did:web:example.com#key-1\",\"type\":\"Ed25519VerificationKey2020\",\"controller\":\"" +
                "did:web:example.com\",\"publicKeyMultibase\":\"" +
                "z6MkpTHR8VNsBxYRrBcrSthuyT77S9J94DA8vyidbMHWf4id\"}]}";
        
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl(anyString());
        
        DIDDocument doc = spyResolver.resolve(did);
        Assert.assertNotNull(doc);
        Assert.assertEquals(doc.getId(), did);
        Assert.assertFalse(doc.getVerificationMethod().isEmpty());
    }

    @Test
    public void testResolveDidWebWithPath() throws Exception {
        String did = "did:web:example.com:user:alice";
        String mockResponse = "{\"id\":\"did:web:example.com:user:alice\"}";
        
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl("https://example.com/user/alice/did.json");
        
        DIDDocument doc = spyResolver.resolve(did);
        Assert.assertNotNull(doc);
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveInvalidDid() throws Exception {
        resolver.resolve("invalid-did");
    }

    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveUnsupportedMethod() throws Exception {
        resolver.resolve("did:unknown:123");
    }

    @Test
    public void testGetPublicKey() throws Exception {
        String did = "did:web:example.com";
        String mockResponse = "{\"id\":\"did:web:example.com\",\"verificationMethod\":[{\"id\":\"" +
                "did:web:example.com#key-1\",\"type\":\"Ed25519VerificationKey2020\",\"controller\":\"" +
                "did:web:example.com\",\"publicKeyMultibase\":\"" +
                "z6MkpTHR8VNsBxYRrBcrSthuyT77S9J94DA8vyidbMHWf4id\"}],\"assertionMethod\":[\"" +
                "did:web:example.com#key-1\"]}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl(anyString());

        PublicKey publicKey = spyResolver.getPublicKey(did, null);
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(publicKey.getAlgorithm(), "Ed25519");
    }

    @Test
    public void testCache() throws Exception {
        String did = "did:web:example.com";
        String mockResponse = "{\"id\":\"did:web:example.com\"}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl(anyString());

        DIDDocument doc1 = spyResolver.resolve(did, true);
        DIDDocument doc2 = spyResolver.resolve(did, true);
        Assert.assertSame(doc1, doc2, "Documents should be the same instance due to caching");
        
        spyResolver.clearCache(did);
        DIDDocument doc3 = spyResolver.resolve(did, true);
        Assert.assertNotSame(doc1, doc3, "Document should be re-resolved after cache clear");
    }
}
