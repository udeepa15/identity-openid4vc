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

package org.wso2.carbon.identity.openid4vc.presentation.verification.jwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;



/**
 * This replaces the usage of identity-inbound-auth-oauth's JWKSBasedJWTValidator which is restricted to RSA.
 */
public class ExtendedJWKSValidator {

    private static final Log log = LogFactory.getLog(ExtendedJWKSValidator.class);

    /**
     * Validate a JWT signature using a JWKS URI.
     *
     * @param jwtString The JWT string.
     * @param jwksUri   The JWKS URI.
     * @param algorithm The expected algorithm (e.g., "EdDSA", "ES256", "RS256").
     * @return true if valid.
     * @throws CredentialVerificationException If verification fails.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings({"REC_CATCH_EXCEPTION", "CRLF_INJECTION_LOGS"})
    public boolean validateSignature(String jwtString, String jwksUri, String algorithm)
            throws CredentialVerificationException {

        try {
            // 1. Create ConfigurableJWTProcessor
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

            // Configure JOSE Type Verifier to allow "vc+sd-jwt" and standard "JWT"
            jwtProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(
                            JOSEObjectType.JWT,
                            new JOSEObjectType("vc+sd-jwt"),
                            null // allow missing "typ" header
                    )
            );

            // 2. Configure Key Source (RemoteJWKSet handles caching)
            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new java.net.URI(jwksUri).toURL());

            // 3. Configure Key Selector
            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(algorithm);
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            // 4. Process (Verify Signature & Claims)
            // We pass null for SecurityContext as we don't need semantic validation here, just signature + exp check
            jwtProcessor.process(jwtString, null);

            if (log.isDebugEnabled()) {
                String safeJwksUri = jwksUri != null ? jwksUri.replaceAll("[\r\n]", "") : "null";
                log.debug("Successfully verified JWT signature using JWKS: " + safeJwksUri);
            }
            return true;

        } catch (Exception e) {
            // Log the specific error for debugging
            if (log.isDebugEnabled()) {
                String safeJwksUri = jwksUri != null ? jwksUri.replaceAll("[\r\n]", "") : "null";
                String safeAlg = algorithm != null ? algorithm.replaceAll("[\r\n]", "") : "null";
                String safeError = e.getMessage() != null ? e.getMessage().replaceAll("[\r\n]", "") : "null";
                
                log.debug("Signature verification failed for JWKS: " + safeJwksUri + ", alg: " + safeAlg +
                        ". Error: " + safeError, e);
            }
            throw new CredentialVerificationException("Signature verification failed: " + e.getMessage(), e);
        }
    }
}
