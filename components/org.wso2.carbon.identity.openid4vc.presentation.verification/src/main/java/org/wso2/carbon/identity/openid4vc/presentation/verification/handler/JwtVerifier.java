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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handler;

import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.Jwt;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * Verifier for standard JWT-VP tokens.
 */
public final class JwtVerifier implements Verifier {

    @Override
    public boolean canHandle(final String format) {
        return VerificationConstants.FORMAT_JWT.equals(format);
    }

    @Override
    public Map<String, Object> handle(final PresentationSubmission submission,
                                     final int tenantId, final String vpToken) 
            throws VerificationException {
        
        try {
            SignedJWT parsedVp;
            try {
                parsedVp = SignedJWT.parse(vpToken);
            } catch (ParseException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to parse VP token: " + e.getMessage(), e);
            }

            boolean signatureValid = SignatureVerifier.verifySignature(parsedVp);

            if (!signatureValid) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Signature verification failed for JWT VP");
            }

            Jwt payload = mapToJwt(parsedVp);
            return getClaims(payload);
        } catch (ParseException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to extract claims from JWT VP: " + e.getMessage(), e);
        }
    }

    /**
     * Get claims from the Jwt payload.
     */
    private Map<String, Object> getClaims(final Jwt payload) {
        Map<String, Object> claims = new HashMap<>(payload.getAdditionalClaims());
        claims.put(VerificationConstants.CLAIM_ISS, payload.getIss());
        claims.put(VerificationConstants.CLAIM_SUB, payload.getSub());
        claims.put(VerificationConstants.CLAIM_IAT, payload.getIat());
        claims.put(VerificationConstants.CLAIM_EXP, payload.getExp());
        if (payload.getCnf() != null) {
            claims.put(VerificationConstants.CLAIM_CNF, payload.getCnf());
        }
        return claims;
    }

    /**
     * Map SignedJWT claims to Jwt model.
     */
    private Jwt mapToJwt(final SignedJWT jwt) throws ParseException {
        Jwt payload = new Jwt();
        populateJwtModel(payload, jwt);
        return payload;
    }

    /**
     * Populate a Jwt model with claims from a SignedJWT.
     */
    public static void populateJwtModel(final Jwt model,
                                        final SignedJWT jwt) throws ParseException {
        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

        if (claims.containsKey(VerificationConstants.CLAIM_ISS)) {
            model.setIss(claims.get(VerificationConstants.CLAIM_ISS).toString());
        }
        if (claims.containsKey(VerificationConstants.CLAIM_IAT) 
                && jwt.getJWTClaimsSet().getIssueTime() != null) {
            model.setIat(jwt.getJWTClaimsSet().getIssueTime().getTime());
        }
        if (claims.containsKey(VerificationConstants.CLAIM_EXP) 
                && jwt.getJWTClaimsSet().getExpirationTime() != null) {
            model.setExp(jwt.getJWTClaimsSet().getExpirationTime().getTime());
        }
        if (claims.containsKey(VerificationConstants.CLAIM_SUB)) {
            model.setSub(claims.get(VerificationConstants.CLAIM_SUB).toString());
        }
        if (claims.containsKey(VerificationConstants.CLAIM_CNF)
                && claims.get(VerificationConstants.CLAIM_CNF) instanceof Map) {
            model.setCnf((Map<String, Object>) claims.get(VerificationConstants.CLAIM_CNF));
        }

        Map<String, Object> additional = new HashMap<>(claims);
        additional.remove(VerificationConstants.CLAIM_ISS);
        additional.remove(VerificationConstants.CLAIM_IAT);
        additional.remove(VerificationConstants.CLAIM_EXP);
        additional.remove(VerificationConstants.CLAIM_SUB);
        additional.remove(VerificationConstants.CLAIM_CNF);
        model.setAdditionalClaims(additional);
    }
}
