/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;

/**
 * Utility class for verifying cryptographic signatures in Verifiable
 * Credentials.
 * Supports JWT signatures and JSON-LD Linked Data signatures.
 */
public class SignatureVerifier {

    private static final Log LOG = LogFactory.getLog(SignatureVerifier.class);

    public SignatureVerifier() {
        // No dependencies required.
    }

    /**
     * Verify a JWT signature.
     *
     * @param jwt       The complete JWT string (header.payload.signature)
     * @param publicKey The public key for verification
     * @param algorithm The JWT algorithm (RS256, ES256, EdDSA, etc.)
     * @return true if signature is valid
     * @throws CredentialVerificationException if verification fails
     */
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public boolean verifyJwtSignature(String jwt, PublicKey publicKey, String algorithm)
            throws CredentialVerificationException {

        if (jwt == null || publicKey == null || algorithm == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("verifyJwtSignature called with missing params. jwt=" + (jwt != null) +
                        ", key=" + (publicKey != null) + ", alg=" + VerificationUtil.removeCRLF(algorithm));
            }
            throw new CredentialVerificationException("JWT, public key, and algorithm are required");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("verifyJwtSignature called with algorithm: " + VerificationUtil.removeCRLF(algorithm));
            LOG.debug("PublicKey: " + VerificationUtil.removeCRLF(String.valueOf(publicKey)));
        }

        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT format");
        }

        try {
            boolean result;

            if (publicKey instanceof RSAPublicKey) {
                // Use Nimbus RSASSAVerifier for RSA keys (idiomatic JWT handling;
                // avoids manual base64url decoding, consistent with EC path below).
                SignedJWT signedJWT = SignedJWT.parse(jwt);
                RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                result = signedJWT.verify(verifier);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("RSASSAVerifier result=" + result);
                }

            } else if (publicKey instanceof ECPublicKey) {
                // Use Nimbus ECDSAVerifier for EC keys.
                SignedJWT signedJWT = SignedJWT.parse(jwt);
                ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
                result = signedJWT.verify(verifier);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("ECDSAVerifier result=" + result);
                }

            } else {
                // Fallback to JCA for EdDSA and other key types.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Falling back to JCA for key type: "
                            + VerificationUtil.removeCRLF(publicKey.getAlgorithm()));
                }
                result = verifyJwtSignatureWithJca(parts, publicKey, algorithm);
            }

            if (!result) {
                LOG.info("JWT signature verification failed: algorithm=" + VerificationUtil.removeCRLF(algorithm)
                        + ", keyType=" + publicKey.getAlgorithm()
                        + ", jwtHeader=" + VerificationUtil.removeCRLF(Base64URL.from(parts[0]).decodeToString()));
            }
            return result;

        } catch (ParseException | JOSEException e) {
            throw new CredentialVerificationException(
                    "JWT signature verification failed: " + e.getMessage(), e);
        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "JWT signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verify a JWT signature using the JCA Signature API.
     * Used as a fallback for key types not supported by Nimbus verifiers (e.g. EdDSA).
     */
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    private boolean verifyJwtSignatureWithJca(String[] parts, PublicKey publicKey, String algorithm)
            throws CredentialVerificationException {

        try {
            String signingInput = parts[0] + "." + parts[1];
            byte[] signatureBytes = Base64URL.from(parts[2]).decode();
            String jcaAlgorithm = getJcaAlgorithm(algorithm);

            if (LOG.isDebugEnabled()) {
                LOG.debug("JCA verification: jcaAlgorithm=" + VerificationUtil.removeCRLF(jcaAlgorithm)
                        + ", signingInputLength=" + signingInput.length()
                        + ", signatureBytesLength=" + signatureBytes.length);
            }

            Signature sig = Signature.getInstance(jcaAlgorithm);
            sig.initVerify(publicKey);
            sig.update(signingInput.getBytes(StandardCharsets.UTF_8));

            if (algorithm.startsWith("ES")) {
                signatureBytes = convertJwtEcdsaToDer(signatureBytes, algorithm);
            }

            boolean result = sig.verify(signatureBytes);
            if (LOG.isDebugEnabled()) {
                LOG.debug("JCA verification result=" + result);
            }
            return result;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "JCA JWT signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verify a Linked Data signature (JSON-LD).
     *
     * @param document   The JSON-LD document (without proof)
     * @param publicKey  The public key for verification
     * @param proofType  The proof type (Ed25519Signature2020, JsonWebSignature2020,
     *                   etc.)
     * @param proofValue The proof value or JWS
     * @return true if signature is valid
     * @throws CredentialVerificationException if verification fails
     */
    public boolean verifyLinkedDataSignature(String document, PublicKey publicKey,
            String proofType, String proofValue)
            throws CredentialVerificationException {

        if (document == null || publicKey == null || proofType == null || proofValue == null) {
            throw new CredentialVerificationException(
                    "Document, public key, proof type, and proof value are required");
        }

        try {
            // Handle different proof types
            if (proofType.contains("Ed25519Signature")) {
                return verifyEd25519Signature(document, publicKey, proofValue);
            } else if (proofType.contains("JsonWebSignature")) {
                return verifyJsonWebSignature(document, publicKey, proofValue);
            } else if (proofType.contains("EcdsaSecp256k1")) {
                return verifyEcdsaSecp256k1Signature(document, publicKey, proofValue);
            } else {
                return verifyGenericSignature(document, publicKey, proofValue, proofType);
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Linked data signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decode a proof value that may be multibase-encoded (base58btc prefix 'z') or base64.
     */
    private byte[] decodeProofValue(String proofValue) throws CredentialVerificationException {
        byte[] signatureBytes;
        if (proofValue.startsWith("z")) {
            signatureBytes = base58Decode(proofValue.substring(1));
        } else {
            try {
                signatureBytes = Base64.getUrlDecoder().decode(proofValue);
            } catch (Exception e) {
                signatureBytes = Base64.getDecoder().decode(proofValue);
            }
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new CredentialVerificationException("Failed to decode proof value");
        }
        return signatureBytes;
    }

    /**
     * Verify an Ed25519 signature.
     */
    private boolean verifyEd25519Signature(String document, PublicKey publicKey, String proofValue)
            throws Exception {

        byte[] signatureBytes = decodeProofValue(proofValue);

        // Ed25519 performs its own internal SHA-512 hashing, so we pass the raw document bytes
        byte[] documentBytes = document.getBytes(StandardCharsets.UTF_8);

        // Verify using EdDSA
        try {
            Signature sig = Signature.getInstance("EdDSA");
            sig.initVerify(publicKey);
            sig.update(documentBytes);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            // Ed25519 verification requires specific support
            throw new CredentialVerificationException(
                    "Ed25519 verification not supported: " + e.getMessage());
        }
    }

    /**
     * Verify a JSON Web Signature (detached JWS).
     */
    private boolean verifyJsonWebSignature(String document, PublicKey publicKey, String jws)
            throws Exception {

        // JWS format: header..signature (detached payload)
        String[] parts = jws.split("\\.");
        if (parts.length < 2) {
            throw new CredentialVerificationException("Invalid JWS format");
        }

        // Get algorithm from header
        String headerJson = Base64URL.from(parts[0]).decodeToString();
        String algorithm = extractAlgorithmFromHeader(headerJson);

        // For detached JWS, create the payload from the document
        byte[] documentHash = VerificationUtil.hashDocument(document, "SHA-256");
        String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(documentHash);

        // Reconstruct the JWS with payload
        String fullJws;
        if (parts.length == 3 && parts[1].isEmpty()) {
            // Detached format: header..signature
            fullJws = parts[0] + "." + encodedPayload + "." + parts[2];
        } else if (parts.length == 2) {
            // Compact detached format: header.signature
            fullJws = parts[0] + "." + encodedPayload + "." + parts[1];
        } else {
            fullJws = jws;
        }

        return verifyJwtSignature(fullJws, publicKey, algorithm);
    }

    /**
     * Verify an ECDSA secp256k1 signature.
     */
    private boolean verifyEcdsaSecp256k1Signature(String document, PublicKey publicKey, String proofValue)
            throws Exception {

        byte[] signatureBytes = decodeProofValue(proofValue);

        // Hash the document
        byte[] documentHash = VerificationUtil.hashDocument(document, "SHA-256");

        // Verify using ECDSA
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(publicKey);
        sig.update(documentHash);

        // Convert from compact format to DER if needed
        if (signatureBytes.length == 64) {
            signatureBytes = compactToDer(signatureBytes);
        }

        return sig.verify(signatureBytes);
    }

    /**
     * Generic signature verification fallback.
     */
    private boolean verifyGenericSignature(String document, PublicKey publicKey,
            String proofValue, String proofType)
            throws Exception {

        byte[] signatureBytes = decodeProofValue(proofValue);

        byte[] documentHash = VerificationUtil.hashDocument(document, "SHA-256");

        // Try to determine algorithm from key type
        String algorithm;
        if (publicKey instanceof RSAPublicKey) {
            algorithm = "SHA256withRSA";
        } else if (publicKey instanceof ECPublicKey) {
            algorithm = "SHA256withECDSA";
        } else {
            algorithm = "SHA256withRSA"; // Default fallback
        }

        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(publicKey);
        sig.update(documentHash);

        return sig.verify(signatureBytes);
    }

    /**
     * Get the JCA algorithm name from JWT algorithm name.
     */
    private String getJcaAlgorithm(String jwtAlgorithm) throws CredentialVerificationException {
        switch (jwtAlgorithm) {
            case "RS256":
                return "SHA256withRSA";
            case "RS384":
                return "SHA384withRSA";
            case "RS512":
                return "SHA512withRSA";
            case "ES256":
                return "SHA256withECDSA";
            case "ES384":
                return "SHA384withECDSA";
            case "ES512":
                return "SHA512withECDSA";
            case "ES256K":
                return "SHA256withECDSA";
            case "EdDSA":
                return "EdDSA";
            case "PS256":
                return "SHA256withRSAandMGF1";
            case "PS384":
                return "SHA384withRSAandMGF1";
            case "PS512":
                return "SHA512withRSAandMGF1";
            default:
                throw new CredentialVerificationException("Unsupported JWT algorithm: " + jwtAlgorithm);
        }
    }

    /**
     * Extract algorithm from JWT/JWS header.
     */
    private String extractAlgorithmFromHeader(String headerJson) {
        // Simple extraction - in production use proper JSON parsing
        if (headerJson.contains("\"alg\"")) {
            int start = headerJson.indexOf("\"alg\"") + 6;
            int colonIndex = headerJson.indexOf(":", start);
            int quoteStart = headerJson.indexOf("\"", colonIndex);
            int quoteEnd = headerJson.indexOf("\"", quoteStart + 1);
            if (quoteStart > 0 && quoteEnd > quoteStart) {
                return headerJson.substring(quoteStart + 1, quoteEnd);
            }
        }
        return "RS256"; // Default
    }

    /**
     * Convert JWT ECDSA signature format to DER format.
     * JWT uses concatenated R||S format, JCA needs DER format.
     */
    private byte[] convertJwtEcdsaToDer(byte[] jwtSignature, String algorithm)
            throws CredentialVerificationException {

        int componentLength;
        switch (algorithm) {
            case "ES256":
            case "ES256K":
                componentLength = 32;
                break;
            case "ES384":
                componentLength = 48;
                break;
            case "ES512":
                componentLength = 66;
                break;
            default:
                return jwtSignature;
        }

        if (jwtSignature.length != componentLength * 2) {
            // Already in DER format or unknown format
            return jwtSignature;
        }

        return compactToDer(jwtSignature);
    }

    /**
     * Convert compact ECDSA signature (R||S) to DER format.
     */
    private byte[] compactToDer(byte[] compact) {
        int half = compact.length / 2;
        byte[] r = new byte[half];
        byte[] s = new byte[half];
        System.arraycopy(compact, 0, r, 0, half);
        System.arraycopy(compact, half, s, 0, half);

        // Remove leading zeros and handle negative values
        r = trimLeadingZeros(r);
        s = trimLeadingZeros(s);

        // Add padding byte if high bit is set (to avoid negative interpretation)
        if ((r[0] & 0x80) != 0) {
            byte[] padded = new byte[r.length + 1];
            System.arraycopy(r, 0, padded, 1, r.length);
            r = padded;
        }
        if ((s[0] & 0x80) != 0) {
            byte[] padded = new byte[s.length + 1];
            System.arraycopy(s, 0, padded, 1, s.length);
            s = padded;
        }

        // Build DER structure
        int totalLength = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + totalLength];
        int offset = 0;

        // SEQUENCE tag
        der[offset++] = 0x30;
        der[offset++] = (byte) totalLength;

        // INTEGER (R)
        der[offset++] = 0x02;
        der[offset++] = (byte) r.length;
        System.arraycopy(r, 0, der, offset, r.length);
        offset += r.length;

        // INTEGER (S)
        der[offset++] = 0x02;
        der[offset++] = (byte) s.length;
        System.arraycopy(s, 0, der, offset, s.length);

        return der;
    }

    /**
     * Trim leading zeros from a byte array.
     */
    private byte[] trimLeadingZeros(byte[] bytes) {
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) {
            start++;
        }
        if (start == 0) {
            return bytes;
        }
        byte[] trimmed = new byte[bytes.length - start];
        System.arraycopy(bytes, start, trimmed, 0, trimmed.length);
        return trimmed;
    }

    /**
     * Decode base58 string (Bitcoin alphabet).
     */
    private byte[] base58Decode(String base58) {
        String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        if (base58 == null || base58.isEmpty()) {
            return new byte[0];
        }

        // Count leading zeros
        int zeros = 0;
        for (int i = 0; i < base58.length() && base58.charAt(i) == '1'; i++) {
            zeros++;
        }

        // Decode
        java.math.BigInteger value = java.math.BigInteger.ZERO;
        java.math.BigInteger base = java.math.BigInteger.valueOf(58);

        for (int i = 0; i < base58.length(); i++) {
            int index = alphabet.indexOf(base58.charAt(i));
            if (index < 0) {
                return new byte[0];
            }
            value = value.multiply(base).add(java.math.BigInteger.valueOf(index));
        }

        byte[] decoded = value.toByteArray();

        // Remove leading zero if present (sign byte)
        if (decoded.length > 0 && decoded[0] == 0) {
            byte[] tmp = new byte[decoded.length - 1];
            System.arraycopy(decoded, 1, tmp, 0, tmp.length);
            decoded = tmp;
        }

        // Add leading zeros back
        if (zeros > 0) {
            byte[] result = new byte[zeros + decoded.length];
            System.arraycopy(decoded, 0, result, zeros, decoded.length);
            return result;
        }

        return decoded;
    }

}
