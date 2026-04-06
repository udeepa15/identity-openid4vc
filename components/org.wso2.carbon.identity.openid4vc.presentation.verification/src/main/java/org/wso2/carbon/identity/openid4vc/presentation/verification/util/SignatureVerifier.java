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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDResolverService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDResolverServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.JwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.Jwt;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;

/**
 * Utility class for verifying cryptographic signatures of Verifiable Presentations and Credentials.
 */
public class SignatureVerifier {

    private static final Log LOG = LogFactory.getLog(SignatureVerifier.class);

    private static final long CLOCK_SKEW_TOLERANCE_MS = 60 * 1000;

    /**
     * Creates a utility class instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only static utility methods.</p>
     */
    private SignatureVerifier() {
    }

    /**
     * Verifies the cryptographic signature of a JWT using either DID-based key
     * resolution or issuer metadata/JWKS discovery.
     *
     * @param jwt The parsed JWT to verify
     * @return {@code true} when signature and expiration checks pass
     * @throws VerificationException If key resolution or signature validation fails
     */
    public static boolean verifySignature(SignedJWT jwt)
            throws VerificationException {

        if (jwt == null) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR, "JWT is null");
        }

        DIDResolverService didResolverService = new DIDResolverServiceImpl();
        try {
            String alg = jwt.getHeader().getAlgorithm().getName();
            String kid = jwt.getHeader().getKeyID();

            Jwt payload = new Jwt();
            JwtVerifier.populateJwtModel(payload, jwt);
            String issuer = payload.getIss();

            if (StringUtils.isBlank(issuer)) {
                if (kid != null && kid.startsWith(VerificationConstants.DID_PREFIX)) {
                    issuer = kid.split("#")[0];
                }
            }

            PublicKey publicKey;

            if (issuer != null && issuer.startsWith(VerificationConstants.DID_PREFIX)) {
                if (kid != null && kid.startsWith(VerificationConstants.DID_PREFIX) && kid.contains("#")) {
                    publicKey = didResolverService.getPublicKeyFromReference(kid);
                } else {
                    publicKey = didResolverService.getPublicKey(issuer, null);
                }

                boolean signatureValid = verifyJwtSignature(jwt.getParsedString(), publicKey, alg);
                if (signatureValid) {
                    verifyExpiration(payload);
                }
                return signatureValid;
            }

            if (issuer != null && issuer.startsWith(VerificationConstants.HTTP_PREFIX)) {
                String jwksUri = resolveJwksUri(issuer);
                if (jwksUri != null) {
                    boolean signatureValid = validateSignatureUsingJwks(jwt.getParsedString(), jwksUri, alg);
                    if (signatureValid) {
                        verifyExpiration(payload);
                    }
                    return signatureValid;
                }
            }

            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Cannot verify signature for issuer: " + issuer);

        } catch (DIDResolutionException e) {
            throw new VerificationServerException(VerificationErrorCode.DID_RESOLUTION_ERROR,
                    "Failed to resolve issuer DID: " + e.getMessage(), e);
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
         * Verifies a JWT signature using a provided public key and JWS algorithm.
         *
         * @param jwtString The raw compact JWT string
         * @param publicKey The public key used for signature verification
         * @param algorithm The expected JWS algorithm identifier
         * @return {@code true} if the signature is valid; otherwise {@code false}
         * @throws VerificationException If verification fails due to parsing or JOSE errors
     */
    public static boolean verifyJwtSignature(String jwtString, PublicKey publicKey, String algorithm)
            throws VerificationException {

        try {
            SignedJWT jwt = SignedJWT.parse(jwtString);
            JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(
                    jwt.getHeader(), publicKey);
            return jwt.verify(verifier);
        } catch (JOSEException | ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to verify JWT signature: " + e.getMessage(), e);
        }
    }

    /**
         * Validates a JWT signature using a remote JWKS endpoint.
         *
         * @param jwtString The raw compact JWT string
         * @param jwksUri The remote JWKS URI
         * @param algorithm The expected JWS algorithm identifier
         * @return {@code true} if the signature validates successfully
         * @throws VerificationException If validation fails for any reason
     */
    public static boolean validateSignatureUsingJwks(String jwtString, String jwksUri, String algorithm)
            throws VerificationException {

        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(
                            new JOSEObjectType("jwt"),
                            new JOSEObjectType(VerificationConstants.FORMAT_SD_JWT),
                            null
                    )
            );

            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new java.net.URI(jwksUri).toURL());

            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(algorithm);
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            jwtProcessor.process(jwtString, null);
            return true;

        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
        * Resolves the issuer JWKS URI from OpenID4VC issuer metadata.
        *
        * @param issuer The issuer URL
        * @return The discovered JWKS URI, or {@code null} if not published
        * @throws VerificationException If metadata retrieval or parsing fails
     */
    public static String resolveJwksUri(String issuer) throws VerificationException {

        try {
            String metadataUrl = issuer.endsWith("/") ? issuer + ".well-known/jwt-vc-issuer"
                    : issuer + "/.well-known/jwt-vc-issuer";

            JsonObject metadata = HttpClientUtil.fetchJson(metadataUrl);
            if (metadata != null && metadata.has("jwks_uri")) {
                return metadata.get("jwks_uri").getAsString();
            }
        } catch (VerificationException e) {
            throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Failed to resolve JWKS URI: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Unknown error while resolving JWKS URI", e);
        }
        return null;
    }

    /**
        * Verifies that the credential has not expired, allowing a configured
        * clock-skew tolerance.
        *
        * @param payload The mapped JWT payload containing time claims
        * @throws VerificationException If the credential is expired
     */
    public static void verifyExpiration(Jwt payload) throws VerificationException {

        Long exp = payload.getExp();
        if (exp != null) {
            long currentTime = System.currentTimeMillis();
            if (currentTime > (exp + CLOCK_SKEW_TOLERANCE_MS)) {
                throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                        "Credential has expired at " + new Date(exp));
            }
        }
    }
}
