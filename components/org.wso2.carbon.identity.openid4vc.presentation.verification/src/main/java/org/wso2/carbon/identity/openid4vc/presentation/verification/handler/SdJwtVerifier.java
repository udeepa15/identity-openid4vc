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
import org.wso2.carbon.identity.openid4vc.presentation.verification.vcmodel.SdJwt;
import org.wso2.carbon.identity.sdjwt.Disclosure;
import org.wso2.carbon.identity.sdjwt.SDJWT;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;
 
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifier for SD-JWT tokens.
 */
public final class SdJwtVerifier implements Verifier {
 
    @Override
    public boolean canHandle(final String format) {
        
        return VerificationConstants.FORMAT_SD_JWT.equals(format);
    }

    @Override
    public Map<String, Object> handle(final PresentationSubmission submission, 
                                     final int tenantId, final String vpToken) 
            throws VerificationException {
        
        try {
            SDJWT sdJwt;
            try {
                sdJwt = SDJWT.parse(vpToken);
            } catch (SDJWTException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to parse SD-JWT VP: " + e.getMessage(), e);
            }

            // Parse the JWT part.
            SignedJWT parsedVp;
            try {
                parsedVp = SignedJWT.parse(sdJwt.getIssuerSignedJwt());
            } catch (ParseException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to parse inner VP token: " + e.getMessage(), e);
            }

            boolean signatureValid = SignatureVerifier.verifySignature(parsedVp);
            
            if (!signatureValid) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Signature verification failed for SD-JWT VP");
            }

            SdJwt payload = mapToSdJwt(parsedVp);
            Map<String, Object> claims = getClaims(payload);

            if (sdJwt.getDisclosureCount() > 0) {
                verifyDisclosures(payload, sdJwt.getDisclosures(), claims);
            }

            return claims;
        } catch (ParseException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to extract claims from SD-JWT VP: " + e.getMessage(), e);
        }
    }

    /**
     * Get claims from the SdJwt payload.
     */
    private Map<String, Object> getClaims(final SdJwt payload) {
        
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
     * Verify disclosures against the _sd hashes in the payload and add verified claims.
     */
    private void verifyDisclosures(final SdJwt payload,
                                   final List<Disclosure> disclosures,
                                   final Map<String, Object> claims)
            throws VerificationException {
        
        List<String> sdHashes = payload.getSd();
        if (sdHashes == null || sdHashes.isEmpty()) {
            return;
        }
 
        String sdAlg = payload.getSdAlg();
 
        try {
            for (Disclosure disclosure : disclosures) {
                String calculatedHash = disclosure.digest(sdAlg);
 
                if (sdHashes.contains(calculatedHash)) {
                    // Disclosure verified! Extract claim if it's an object property.
                    if (!disclosure.isArrayElement()) {
                        claims.put(disclosure.getClaimName(), disclosure.getClaimValue());
                    }
                }
            }
        } catch (SDJWTException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error verifying SD-JWT disclosures: " + e.getMessage(), e);
        }
    }

    /**
     * Map SignedJWT claims to SdJwt model.
     */
    private SdJwt mapToSdJwt(final SignedJWT jwt) throws ParseException {
        
        SdJwt payload = new SdJwt();
        JwtVerifier.populateJwtModel(payload, jwt);

        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

        if (claims.containsKey(VerificationConstants.CLAIM_SD_ALG)) {
            payload.setSdAlg(claims.get(VerificationConstants.CLAIM_SD_ALG).toString());
        }
        if (claims.containsKey(VerificationConstants.CLAIM_SD)
                && claims.get(VerificationConstants.CLAIM_SD) instanceof List) {
            payload.setSd((List<String>) claims.get(VerificationConstants.CLAIM_SD));
        }

        Map<String, Object> additional = payload.getAdditionalClaims();
        additional.remove(VerificationConstants.CLAIM_SD);
        additional.remove(VerificationConstants.CLAIM_SD_ALG);

        return payload;
    }
}
