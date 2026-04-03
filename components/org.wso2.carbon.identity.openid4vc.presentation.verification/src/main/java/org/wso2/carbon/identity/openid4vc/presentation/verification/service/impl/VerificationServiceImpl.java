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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.JwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.SdJwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handler.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Implementation of the {@link VerificationService} for OpenID4VC presentations.
 */
@Component(
        name = "openid4vc.presentation.verification.service",
        immediate = true,
        service = VerificationService.class
)
public class VerificationServiceImpl implements VerificationService {
    
    private PresentationDefinitionService presentationDefinitionService;
    private final List<Verifier> verifiers;

    public VerificationServiceImpl() {
        this.verifiers = initVerifiers();
    }

    private List<Verifier> initVerifiers() {
        List<Verifier> verifierList = new java.util.ArrayList<>();
        verifierList.add(new JwtVerifier());
        verifierList.add(new SdJwtVerifier());
        return verifierList;
    }

    @Override
    public VerificationResult verify(PresentationSubmission submission, int tenantId, String vpToken)
            throws VerificationException {

        validateRequest(submission, vpToken);

        if (tenantId == MultitenantConstants.INVALID_TENANT_ID) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Invalid tenant ID provided.");
        }

        String format = submission.getDescriptorMap().get(0).getFormat();
        Verifier verifier = verifiers.stream()
                .filter(v -> v.canHandle(format))
                .findFirst()
                .orElseThrow(() -> new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                        "No verifier found for format: " + format));

        Map<String, Object> verifiedClaims = verifier.handle(submission, tenantId, vpToken);
        
        if (presentationDefinitionService == null) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not available");
        }

        PresentationDefinition definition;
        try {
            definition = presentationDefinitionService.getPresentationDefinitionById(
                    submission.getDefinitionId(), tenantId);
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error fetching presentation definition: " + e.getMessage(), e);
        }
        
        Map<String, Object> finalClaims = verifyAgainstDefinition(verifiedClaims, definition);
        
        VerificationResult result = new VerificationResult();
        result.setVerifiedClaims(finalClaims);
        result.setStatus(VerificationResult.VerificationStatus.VERIFIED);
        return result;
    }

    /**
     * Verify verified claims against a Presentation Definition.
     */
    private Map<String, Object> verifyAgainstDefinition(Map<String, Object> verifiedClaims,
                                                       PresentationDefinition definition)
            throws VerificationException {

        if (definition == null || definition.getRequestedCredentials() == null) {
            return verifiedClaims;
        }

        for (PresentationDefinition.RequestedCredential req : definition.getRequestedCredentials()) {

            String pdIssuer = req.getIssuer();
            if (StringUtils.isNotBlank(pdIssuer)) {
                Object issClaimValue = verifiedClaims.get(VerificationConstants.CLAIM_ISS);
                if (issClaimValue == null) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "Issuer verification failed: 'iss' claim is missing from the VP token.");
                }
                String tokenIssuer = issClaimValue.toString();
                String pdNormalized = normalizeIssuer(pdIssuer);
                String tokenNormalized = normalizeIssuer(tokenIssuer);
                if (pdNormalized == null || tokenNormalized == null || !pdNormalized.equals(tokenNormalized)) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "Issuer verification failed: token issuer '" + tokenIssuer
                                    + "' does not match the expected issuer '" + pdIssuer + "'.");
                }
            }

            if (req.getClaims() != null && !req.getClaims().isEmpty()) {
                for (String claim : req.getClaims()) {
                    if (!verifiedClaims.containsKey(claim)) {
                        throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                                "Requested claim '" + claim + "' is missing from the presentation");
                    }
                }
            }
        }

        return verifiedClaims;
    }

    /**
     * Validate the VP token and presentation submission before processing.
     *
     * <p>This is a pre-flight guard that catches structural and format problems early,
     * so that downstream verifiers receive well-formed inputs.
     *
     * <p>The following conditions are verified:
     * <ul>
     *   <li>The {@code vpToken} is neither null nor blank.</li>
     *   <li>The {@code submission} is not null and contains a non-blank {@code definition_id}.</li>
     *   <li>The {@code descriptor_map} is present and contains at least one entry with a known format.</li>
     * </ul>
     *
     * @param submission The presentation_submission object from the client.
     * @param vpToken    The raw VP token string from the client.
     * @throws VerificationClientException If any validation rule is violated.
     */
    private void validateRequest(PresentationSubmission submission, String vpToken)
            throws VerificationClientException {

        // --- VP token checks ---
        if (StringUtils.isBlank(vpToken)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    VerificationConstants.ERROR_INVALID_VP_TOKEN);
        }

        // --- Submission checks ---
        if (submission == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Presentation submission is null.");
        }

        List<PresentationSubmission.DescriptorMap> descriptorMap = submission.getDescriptorMap();
        if (descriptorMap == null || descriptorMap.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "Presentation submission descriptor_map is missing or empty.");
        }

        // --- Format checks ---
        String format = descriptorMap.get(0).getFormat();
        if (StringUtils.isBlank(format)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                    "Presentation submission descriptor_map entry is missing a format.");
        }
        boolean isSupportedFormat = VerificationConstants.FORMAT_JWT.equals(format)
                || VerificationConstants.FORMAT_SD_JWT.equals(format);
        if (!isSupportedFormat) {
            throw new NotImplementedException("Unsupported VP format: " + format + ". Supported formats: "
                    + VerificationConstants.FORMAT_JWT + ", " + VerificationConstants.FORMAT_SD_JWT);
        }
    }

    /**
     * Normalize an issuer identifier for strict comparison.
     */
    private String normalizeIssuer(String issuer) {

        if (StringUtils.isBlank(issuer)) {
            return null;
        }

        issuer = issuer.trim();

        if (issuer.startsWith(VerificationConstants.DID_WEB_PREFIX)) {
            String afterPrefix = issuer.substring(VerificationConstants.DID_WEB_PREFIX.length());
            if (StringUtils.isBlank(afterPrefix)) {
                return null;
            }

            String[] segments = afterPrefix.split(":");
            StringBuilder normalized = new StringBuilder(segments[0].toLowerCase(Locale.ROOT));

            for (int i = 1; i < segments.length; i++) {
                normalized.append("/").append(segments[i]);
            }
            String result = normalized.toString();
            return result.endsWith("/") ? result.substring(0, result.length() - 1) : result;
        }

        try {
            URI uri = new URI(issuer);
            String host = uri.getHost();
            if (host == null) {
                return null;
            }

            StringBuilder normalized = new StringBuilder(host.toLowerCase(Locale.ROOT));
            int port = uri.getPort();
            if (port != -1 && port != 443 && port != 80) {
                normalized.append(":").append(port);
            }

            String path = uri.getPath();
            if (StringUtils.isNotBlank(path)) {
                if (!path.startsWith("/")) {
                    normalized.append("/");
                }
                normalized.append(path);
            }

            String result = normalized.toString();
            return result.endsWith("/") ? result.substring(0, result.length() - 1) : result;

        } catch (URISyntaxException e) {
            return null;
        }
    }

    @Reference(
            name = "presentation.definition.service",
            service = PresentationDefinitionService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionService"
    )
    protected void setPresentationDefinitionService(PresentationDefinitionService service) {
        this.presentationDefinitionService = service;
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService service) {
        this.presentationDefinitionService = null;
    }
}
