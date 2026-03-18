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

package org.wso2.carbon.identity.openid4vc.presentation.did.service.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.did.model.DIDDocument;
import org.wso2.carbon.identity.openid4vc.presentation.did.util.Base58;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

/**
 * Unit tests for DIDResolverServiceImpl.
 */
public class DIDResolverServiceImplTest {

    private DIDResolverServiceImpl resolver;

    /**
     * Sets system properties used by Carbon utility classes.
     */
    @BeforeClass(alwaysRun = true)
    public static void setupSystemProperties() {
        System.setProperty("carbon.home", ".");
    }

    /**
     * Initializes a fresh resolver before each test.
     */
    @BeforeMethod
    public void setUp() {
        resolver = new DIDResolverServiceImpl();
    }

    /**
     * Tests successful Universal Resolver fallback for unsupported DID methods.
     *
     * @throws Exception if test setup fails.
     */
    @Test
    public void testResolveViaUniversalResolverSuccess() throws Exception {
        String did = "did:ion:12345";
        String mockResponse = "{"
                + "\"didDocument\":{"
                + "\"id\":\"did:ion:12345\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"did:ion:12345#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"did:ion:12345\","
                + "\"publicKeyMultibase\":\"z6MkpTHR8VNsBxYRrBcrSthuyT77S9J94DA8vyidbMHWf4id\""
                + "}],"
                + "\"assertionMethod\":[\"did:ion:12345#key-1\"]"
                + "}"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(mockResponse).when(spyResolver).fetchUrl("https://dev.uniresolver.io/1.0/identifiers/" + did);

        DIDDocument document = spyResolver.resolve(did, false);

        Assert.assertNotNull(document);
        Assert.assertEquals(did, document.getId());
        Assert.assertNotNull(document.getVerificationMethod());
        Assert.assertFalse(document.getVerificationMethod().isEmpty());
    }

    /**
     * Tests Universal Resolver fallback failure when didDocument is missing.
     *
     * @throws Exception if test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveViaUniversalResolverMissingDidDocument() throws Exception {
        String did = "did:polygonid:abc123";
        String invalidResponse = "{\"didResolutionMetadata\":{},\"didDocumentMetadata\":{}}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(invalidResponse).when(spyResolver).fetchUrl("https://dev.uniresolver.io/1.0/identifiers/" + did);

        spyResolver.resolve(did, false);
    }

    /**
     * Tests isSupported behavior for arbitrary DID methods.
     */
    @Test
    public void testIsSupportedForArbitraryDidMethod() {
        Assert.assertTrue(resolver.isSupported("did:ion:123"));
        Assert.assertTrue(resolver.isSupported("did:cheqd:mainnet:abc123"));
        Assert.assertFalse(resolver.isSupported("invalid-did"));
    }

    /**
     * Tests did:web resolution and cache behavior.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testResolveDidWebAndCache() throws Exception {
        String did = "did:web:example.com";
        String didDoc = "{\"id\":\"did:web:example.com\"}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://example.com/.well-known/did.json");

        DIDDocument first = spyResolver.resolve(did, true);
        DIDDocument second = spyResolver.resolve(did, true);

        Assert.assertNotNull(first);
        Assert.assertSame(first, second);
    }

    /**
     * Tests did:web path resolution URL pattern.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testResolveDidWebWithPath() throws Exception {
        String did = "did:web:example.com:user:alice";
        String didDoc = "{\"id\":\"did:web:example.com:user:alice\"}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://example.com/user/alice/did.json");

        DIDDocument result = spyResolver.resolve(did, false);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getId(), did);
    }

    /**
     * Tests invalid DID rejection.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveInvalidDid() throws Exception {
        resolver.resolve("not-a-did", false);
    }

    /**
     * Tests Universal Resolver invalid JSON response handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveViaUniversalResolverInvalidJson() throws Exception {
        String did = "did:ion:bad-json";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn("not-json").when(spyResolver).fetchUrl("https://dev.uniresolver.io/1.0/identifiers/" + did);

        spyResolver.resolve(did, false);
    }

    /**
     * Tests getPublicKey extraction from RSA JWK.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetPublicKeyFromRsaJwk() throws Exception {
        String did = "did:web:rsa.example.com";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsigned(rsaPublicKey.getModulus()));
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsigned(rsaPublicKey.getPublicExponent()));

        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"JsonWebKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyJwk\":{\"kty\":\"RSA\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}"
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://rsa.example.com/.well-known/did.json");

        PublicKey publicKey = spyResolver.getPublicKey(did, null);
        Assert.assertEquals(publicKey.getAlgorithm(), "RSA");
    }

    /**
     * Tests getPublicKey extraction from EC JWK.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetPublicKeyFromEcJwk() throws Exception {
        String did = "did:web:ec.example.com";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPoint point = ecPublicKey.getW();

        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(toFixedLength(point.getAffineX(), 32));
        String y = Base64.getUrlEncoder().withoutPadding().encodeToString(toFixedLength(point.getAffineY(), 32));

        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"JsonWebKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x
                + "\",\"y\":\"" + y + "\"}"
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://ec.example.com/.well-known/did.json");

        PublicKey publicKey = spyResolver.getPublicKey(did, null);
        Assert.assertEquals(publicKey.getAlgorithm(), "EC");
    }

    /**
     * Tests getPublicKey extraction from multibase Ed25519 key.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetPublicKeyFromMultibaseEd25519() throws Exception {
        String did = "did:web:ed.example.com";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] encoded = keyPair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        byte[] multicodec = new byte[34];
        multicodec[0] = (byte) 0xed;
        multicodec[1] = (byte) 0x01;
        System.arraycopy(raw, 0, multicodec, 2, 32);
        String multibase = "z" + Base58.encode(multicodec);

        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyMultibase\":\"" + multibase + "\""
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://ed.example.com/.well-known/did.json");

        PublicKey publicKey = spyResolver.getPublicKey(did, null);
        Assert.assertTrue("Ed25519".equals(publicKey.getAlgorithm())
            || "EdDSA".equals(publicKey.getAlgorithm()));
    }

    /**
     * Tests getPublicKey from verification method reference.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetPublicKeyFromReference() throws Exception {
        String did = "did:web:ref.example.com";
        String vmId = did + "#key-1";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] encoded = keyPair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        String base58 = Base58.encode(raw);

        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + vmId + "\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyBase58\":\"" + base58 + "\""
                + "}],"
                + "\"assertionMethod\":[\"" + vmId + "\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://ref.example.com/.well-known/did.json");

        PublicKey publicKey = spyResolver.getPublicKeyFromReference(vmId);
        Assert.assertNotNull(publicKey);
    }

    /**
     * Tests resolver metadata helper methods.
     */
    @Test
    public void testResolverMetadataHelpers() {
        Assert.assertEquals(resolver.getMethod("did:web:example.com"), "web");
        Assert.assertEquals(resolver.getIdentifier("did:web:example.com:user"), "example.com:user");
        Assert.assertTrue(resolver.isValidDID("did:custom:abc"));
        Assert.assertFalse(resolver.isValidDID("did::abc"));
        Assert.assertEquals(resolver.getSupportedMethods().length, 1);
    }

    /**
     * Tests key extraction failure when no key material is present.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyNoKeyMaterial() throws Exception {
        String did = "did:web:nokey.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\""
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://nokey.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests key-not-found handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyKeyNotFound() throws Exception {
        String did = "did:web:notfound.example.com";
        String didDoc = "{\"id\":\"" + did + "\"}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://notfound.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, "missing-key");
    }

    /**
     * Tests unsupported JWK key type handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyUnsupportedJwkType() throws Exception {
        String did = "did:web:badkty.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"JsonWebKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyJwk\":{\"kty\":\"oct\",\"k\":\"abc\"}"
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://badkty.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests unsupported OKP curve handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyUnsupportedOkpCurve() throws Exception {
        String did = "did:web:badokp.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"JsonWebKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"AQAB\"}"
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://badokp.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests unsupported EC curve handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyUnsupportedEcCurve() throws Exception {
        String did = "did:web:badec.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"JsonWebKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-999\",\"x\":\"AQAB\",\"y\":\"AQAB\"}"
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://badec.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests unsupported multibase prefix handling.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyUnsupportedMultibase() throws Exception {
        String did = "did:web:badmb.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyMultibase\":\"mnot-supported\""
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://badmb.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests unsupported key type handling for Base58 keys.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyUnsupportedTypeForBase58() throws Exception {
        String did = "did:web:badtype.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"RsaVerificationKey2018\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyBase58\":\"2NEpo7TZRRrLZSi2U\""
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://badtype.example.com/.well-known/did.json");

        spyResolver.getPublicKey(did, null);
    }

    /**
     * Tests non-HTTPS URL rejection in fetchUrl.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testFetchUrlRejectsNonHttps() throws Exception {
        resolver.fetchUrl("http://example.com/did.json");
    }

    /**
     * Tests validation for empty verification method references.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testGetPublicKeyFromReferenceEmpty() throws Exception {
        resolver.getPublicKeyFromReference("");
    }

    /**
     * Tests explicit cache clear operations.
     */
    @Test
    public void testClearCacheOperations() {
        resolver.clearCache("did:web:cache.example.com");
        resolver.clearAllCache();
    }

    /**
     * Tests parser behavior for object-based relationships and service endpoints.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testParseDIDDocumentWithObjectRelationshipsAndServiceMap() throws Exception {
        String did = "did:web:parse.example.com";
        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"@context\":\"https://www.w3.org/ns/did/v1\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\","
                + "\"publicKeyBase58\":\"2NEpo7TZRRrLZSi2U\""
                + "}],"
                + "\"authentication\":[{\"id\":\"" + did + "#key-1\"}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"],"
                + "\"service\":[{"
                + "\"id\":\"" + did + "#svc\","
                + "\"type\":\"LinkedDomains\","
                + "\"serviceEndpoint\":{\"uri\":\"https://example.com\"}"
                + "}]"
                + "}";

        DIDDocument document = resolver.parseDIDDocument(did, didDoc);
        Assert.assertNotNull(document);
        Assert.assertEquals(document.getId(), did);
        Assert.assertEquals(document.getContext().size(), 1);
        Assert.assertEquals(document.getAuthentication().size(), 1);
        Assert.assertEquals(document.getService().size(), 1);
    }

    /**
     * Tests parser failure for malformed JSON.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testParseDIDDocumentMalformedJson() throws Exception {
        resolver.parseDIDDocument("did:web:badjson.example.com", "{not-json");
    }

    /**
     * Tests reference resolution when only DID is provided.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testGetPublicKeyFromReferenceWithDidOnly() throws Exception {
        String did = "did:web:didonly.example.com";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] encoded = keyPair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        String base58 = Base58.encode(raw);

        String didDoc = "{"
                + "\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{"
                + "\"id\":\"" + did + "#key-1\","
                + "\"type\":\"Ed25519VerificationKey2020\","
                + "\"controller\":\"" + did + "\","
            + "\"publicKeyBase58\":\"" + base58 + "\""
                + "}],"
                + "\"assertionMethod\":[\"" + did + "#key-1\"]"
                + "}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(didDoc).when(spyResolver).fetchUrl("https://didonly.example.com/.well-known/did.json");

        PublicKey key = spyResolver.getPublicKeyFromReference(did);
        Assert.assertNotNull(key);
    }

    /**
     * Tests method and identifier helper edge cases.
     */
    @Test
    public void testMethodAndIdentifierEdgeCases() {
        Assert.assertNull(resolver.getMethod(null));
        Assert.assertNull(resolver.getMethod("invalid"));
        Assert.assertNull(resolver.getIdentifier("invalid"));
        Assert.assertNull(resolver.getIdentifier("did:web"));
    }

    /**
     * Tests that cache is bypassed when useCache is false.
     *
     * @throws Exception If test setup fails.
     */
    @Test
    public void testResolveBypassCacheWhenDisabled() throws Exception {
        String did = "did:web:nocache.example.com";
        String first = "{\"id\":\"did:web:nocache.example.com\"}";
        String second = "{\"id\":\"did:web:nocache.example.com:updated\"}";

        DIDResolverServiceImpl spyResolver = spy(resolver);
        doReturn(first).doReturn(second)
                .when(spyResolver).fetchUrl("https://nocache.example.com/.well-known/did.json");

        DIDDocument firstDoc = spyResolver.resolve(did, false);
        DIDDocument secondDoc = spyResolver.resolve(did, false);

        Assert.assertNotEquals(firstDoc.getId(), secondDoc.getId());
    }

    /**
     * Tests network error mapping for did:web resolution.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveDidWebNetworkError() throws Exception {
        String did = "did:web:ioerror.example.com";
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doThrow(new IOException("network")).when(spyResolver)
                .fetchUrl("https://ioerror.example.com/.well-known/did.json");

        spyResolver.resolve(did, false);
    }

    /**
     * Tests network error mapping for Universal Resolver fallback.
     *
     * @throws Exception If test setup fails.
     */
    @Test(expectedExceptions = DIDResolutionException.class)
    public void testResolveUniversalResolverNetworkError() throws Exception {
        String did = "did:ion:ioerror123";
        DIDResolverServiceImpl spyResolver = spy(resolver);
        doThrow(new IOException("network")).when(spyResolver)
                .fetchUrl("https://dev.uniresolver.io/1.0/identifiers/" + did);

        spyResolver.resolve(did, false);
    }

    private static byte[] toUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = toUnsigned(value);
        if (raw.length == length) {
            return raw;
        }

        byte[] fixed = new byte[length];
        int srcPos = Math.max(0, raw.length - length);
        int copyLen = Math.min(raw.length, length);
        System.arraycopy(raw, srcPos, fixed, length - copyLen, copyLen);
        return fixed;
    }
}
