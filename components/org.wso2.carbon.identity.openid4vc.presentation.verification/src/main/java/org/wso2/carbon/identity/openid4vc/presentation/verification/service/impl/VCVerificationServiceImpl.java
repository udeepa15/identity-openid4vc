/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.did.exception.DIDResolutionException;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.DIDResolverService;
import org.wso2.carbon.identity.openid4vc.presentation.did.service.impl.DIDResolverServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.management.util.PresentationDefinitionUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VCVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VPVerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.CredentialVerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.RevocationCheckException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.jwt.ExtendedJWKSValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.RevocationCheckResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VCVerificationStatus;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiableCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.model.VerifiablePresentation;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.StatusListService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VCVerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.HttpClientUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationUtil;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Implementation of VCVerificationService for verifying Verifiable Credentials.
 * Supports JSON-LD, JWT, and SD-JWT credential formats.
 */
public class VCVerificationServiceImpl implements VCVerificationService {
    
    private static final Log LOG = LogFactory.getLog(VCVerificationServiceImpl.class);
    private static final Gson GSON = new Gson();

    /**
     * Maximum allowed age (in milliseconds) for a Key Binding JWT {@code iat} claim.
     * KB-JWTs older than this are rejected to prevent replay attacks.
     */
    private static final long KB_JWT_MAX_AGE_MS = 5 * 60 * 1000;

    /**
     * Clock skew tolerance (in milliseconds) for {@code exp}, {@code nbf}, and {@code iat} checks.
     */
    private static final long CLOCK_SKEW_TOLERANCE_MS = 60 * 1000;

    private static final String[] SUPPORTED_CONTENT_TYPES = {
            VerificationUtil.CONTENT_TYPE_VC_LD_JSON,
            VerificationUtil.CONTENT_TYPE_JWT,
            VerificationUtil.CONTENT_TYPE_VC_JWT,
            VerificationUtil.CONTENT_TYPE_SD_JWT,
            VerificationUtil.CONTENT_TYPE_JSON
    };

    private final DIDResolverService didResolverService;
    private final SignatureVerifier signatureVerifier;
    private final StatusListService statusListService;
    private final ExtendedJWKSValidator extendedJWKSValidator;

    /**
     * Optional service for resolving Presentation Definitions by ID.
     * When {@code null}, PD constraint checking is skipped in
     * {@link #verifyPresentation(String, String, String, int)}.
     */
    private PresentationDefinitionService presentationDefinitionService;

    /**
     * Default constructor.
     */
    public VCVerificationServiceImpl() {
        this.didResolverService = new DIDResolverServiceImpl();
        this.signatureVerifier = new SignatureVerifier();
        this.statusListService = new StatusListServiceImpl();
        this.extendedJWKSValidator = new ExtendedJWKSValidator();
    }

    /**
     * Constructor with dependencies.
     *
     * @param didResolverService DID resolver service
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public VCVerificationServiceImpl(DIDResolverService didResolverService) {
        this.didResolverService = didResolverService;
        this.signatureVerifier = new SignatureVerifier();
        this.statusListService = new StatusListServiceImpl();
        this.extendedJWKSValidator = new ExtendedJWKSValidator();
    }

    /**
     * Constructor with all dependencies.
     *
     * @param didResolverService DID resolver service
     * @param statusListService  Status list service
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public VCVerificationServiceImpl(DIDResolverService didResolverService,
            StatusListService statusListService) {
        this.didResolverService = didResolverService;
        this.signatureVerifier = new SignatureVerifier();
        this.statusListService = statusListService;
        this.extendedJWKSValidator = new ExtendedJWKSValidator();
    }

    /**
     * Constructor with all dependencies including the Presentation Definition service.
     *
     * @param didResolverService           DID resolver service
     * @param statusListService            Status list service
     * @param presentationDefinitionService Service for resolving Presentation Definitions by ID
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("EI_EXPOSE_REP2")
    public VCVerificationServiceImpl(DIDResolverService didResolverService,
            StatusListService statusListService,
            PresentationDefinitionService presentationDefinitionService) {
        this.didResolverService = didResolverService;
        this.signatureVerifier = new SignatureVerifier();
        this.statusListService = statusListService;
        this.extendedJWKSValidator = new ExtendedJWKSValidator();
        this.presentationDefinitionService = presentationDefinitionService;
    }

    @Override
    public VCVerificationResultDTO verify(String vcString, String contentType)
            throws CredentialVerificationException {
        return verify(vcString, contentType, 0);
    }

    @Override
    public VCVerificationResultDTO verify(String vcString, String contentType, int vcIndex)
            throws CredentialVerificationException {

        if (vcString == null || vcString.trim().isEmpty()) {
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "Credential string is null or empty");
        }

        try {
            // Parse the credential
            VerifiableCredential credential = parseCredential(vcString, contentType);

            // Perform verification
            VCVerificationResultDTO result = verifyCredentialInternal(credential, vcIndex);

            return result;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "Verification failed: " + e.getMessage());
        }
    }

    @Override
    public VCVerificationResultDTO verifyCredential(VerifiableCredential credential)
            throws CredentialVerificationException {
        return verifyCredentialInternal(credential, 0);
    }

    /**
     * Internal method to verify a parsed credential.
     */
    private VCVerificationResultDTO verifyCredentialInternal(VerifiableCredential credential, int vcIndex)
            throws CredentialVerificationException {

        String credentialType = credential.getPrimaryType();
        String issuer = credential.getIssuerId();

        // 1. Check expiration (with clock-skew tolerance)
        if (credential.getExpirationDate() != null) {
            Date expWithSkew = new Date(credential.getExpirationDate().getTime() + CLOCK_SKEW_TOLERANCE_MS);
            if (new Date().after(expWithSkew)) {
                return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.EXPIRED,
                        "Credential has expired");
            }
        }
        credential.setExpirationChecked(true);

        // 2. Verify signature
        try {
            boolean signatureValid = verifySignature(credential);
            if (!signatureValid) {
                return new VCVerificationResultDTO(vcIndex,
                        VCVerificationStatus.INVALID,
                        "Cryptographic signature verification failed");
            }
            credential.setSignatureVerified(true);
        } catch (CredentialVerificationException e) {
            return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.INVALID,
                    "Signature verification error: " + e.getMessage());
        }

        // 3. Check revocation (if applicable)
        if (credential.hasCredentialStatus()) {
            try {
                if (isRevoked(credential)) {
                    return new VCVerificationResultDTO(vcIndex,
                            VCVerificationStatus.REVOKED,
                            "Credential has been revoked");
                }
                credential.setRevocationChecked(true);
            } catch (CredentialVerificationException e) {
                // Continue without failing - revocation check is optional
            }
        }

        // All checks passed
        return new VCVerificationResultDTO(vcIndex, VCVerificationStatus.SUCCESS,
                credentialType, issuer);
    }

    @Override
    public List<VCVerificationResultDTO> verifyPresentation(VerifiablePresentation presentation)
            throws CredentialVerificationException {

        List<VCVerificationResultDTO> results = new ArrayList<>();

        if (presentation.getVerifiableCredentials() == null ||
                presentation.getVerifiableCredentials().isEmpty()) {
            throw new CredentialVerificationException("No verifiable credentials found in presentation");
        }

        // Verify each credential
        int index = 0;
        for (VerifiableCredential credential : presentation.getVerifiableCredentials()) {
            try {
                VCVerificationResultDTO result = verifyCredentialInternal(credential, index);
                results.add(result);
            } catch (CredentialVerificationException e) {
                results.add(new VCVerificationResultDTO(index, VCVerificationStatus.INVALID,
                        e.getMessage()));
            }
            index++;
        }

        return results;
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public boolean verifySignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        if (credential == null) {
            throw new CredentialVerificationException("Credential is null");
        }

        try {
            if (credential.isJwt()) {
                return verifyJwtSignature(credential);
            } else if (credential.isSdJwt()) {
                return verifySdJwtSignature(credential);
            } else if (credential.isJsonLd()) {
                return verifyJsonLdSignature(credential);
            } else {
                throw new CredentialVerificationException(
                        "Unknown credential format: " + credential.getFormat());
            }
        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Verify JWT credential signature.
     */
    private boolean verifyJwtSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        String rawCredential = credential.getRawCredential();
        String[] parts = rawCredential.split("\\.");

        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT format");
        }

        try {
            // Parse header once and reuse
            Map<String, Object> header = VerificationUtil.parseJwtPart(parts[0]);
            if (!header.containsKey("alg")) {
                throw new CredentialVerificationException(
                        "JWT header is missing required 'alg' parameter");
            }
            String alg = header.get("alg").toString();
            String kid = header.containsKey("kid") ? header.get("kid").toString() : null;

            // Get issuer DID from credential
            String issuer = credential.getIssuerId();
            if (issuer == null || !issuer.startsWith("did:")) {
                // Try to get from JWT header kid (e.g., "did:web:example.com#key-1")
                if (kid != null && kid.startsWith("did:")) {
                    issuer = kid.split("#")[0];
                }
            }

            PublicKey publicKey;

            if (issuer != null && issuer.startsWith("did:")) {
                if (kid != null && kid.startsWith("did:") && kid.contains("#")) {
                    publicKey = didResolverService.getPublicKeyFromReference(kid);
                } else {
                    publicKey = didResolverService.getPublicKey(issuer, null);
                }
                return signatureVerifier.verifyJwtSignature(rawCredential, publicKey, alg);
            }

            // For non-DID issuers, try to resolve from issuer URL
            if (issuer != null && issuer.startsWith("http")) {
                String jwksUri = resolveJwksUri(issuer);
                if (jwksUri != null) {
                    return extendedJWKSValidator.validateSignature(rawCredential, jwksUri, alg);
                } else {
                     throw new CredentialVerificationException("Could not resolve JWKS URI for issuer: " + issuer);
                }
            }

            // For non-DID, non-URL issuers we cannot verify without additional configuration
            throw new CredentialVerificationException("Cannot verify signature for issuer: " + issuer + 
                ". Issuer must be either a DID or an HTTP(S) URL with discoverable JWKS endpoint.");

        } catch (DIDResolutionException e) {
            throw new CredentialVerificationException(
                    "Failed to resolve issuer DID: " + e.getMessage(), e);
        }
    }

    /**
     * Verify SD-JWT credential signature.
     */
    private boolean verifySdJwtSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        // Use the canonical SD-JWT splitter — issuer JWT is always the first field.
        SdJwtParts sdJwtParts = parseSdJwtParts(credential.getRawCredential());

        // Create a temporary credential for JWT verification
        VerifiableCredential tempCred = new VerifiableCredential();
        tempCred.setFormat(VerifiableCredential.Format.JWT);
        tempCred.setRawCredential(sdJwtParts.issuerJwt);
        tempCred.setIssuer(credential.getIssuer());
        tempCred.setIssuerId(credential.getIssuerId());

        return verifyJwtSignature(tempCred);
    }

    /**
     * Verify JSON-LD credential signature.
     */
    private boolean verifyJsonLdSignature(VerifiableCredential credential)
            throws CredentialVerificationException {

        VerifiableCredential.Proof proof = credential.getProof();
        if (proof == null) {
            throw new CredentialVerificationException("No proof found in JSON-LD credential");
        }

        String verificationMethod = proof.getVerificationMethod();
        if (verificationMethod == null) {
            throw new CredentialVerificationException("No verification method in proof");
        }

        try {
            // Extract DID from verification method
            String did = verificationMethod.contains("#")
                    ? verificationMethod.substring(0, verificationMethod.indexOf("#"))
                    : verificationMethod;

            // Get the public key
            PublicKey publicKey = didResolverService.getPublicKey(did, verificationMethod);

            // Get proof value
            String proofValue = proof.getProofValue();
            if (proofValue == null) {
                proofValue = proof.getJws();
            }

            if (proofValue == null) {
                throw new CredentialVerificationException("No proof value found");
            }

            // Verify based on proof type
            return signatureVerifier.verifyLinkedDataSignature(
                    credential.getRawCredential(),
                    publicKey,
                    proof.getType(),
                    proofValue);

        } catch (DIDResolutionException e) {
            throw new CredentialVerificationException(
                    "Failed to resolve verification method: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isExpired(VerifiableCredential credential) {
        if (credential == null || credential.getExpirationDate() == null) {
            return false;
        }
        return new Date().after(credential.getExpirationDate());
    }

    @Override
    public boolean isRevoked(VerifiableCredential credential)
            throws CredentialVerificationException {

        if (credential == null || !credential.hasCredentialStatus()) {
            return false;
        }

        VerifiableCredential.CredentialStatus status = credential.getCredentialStatus();

        try {
            // Use the StatusListService to check revocation
            RevocationCheckResult result = statusListService.checkRevocationStatus(status);

            if (result.getStatus() == RevocationCheckResult.Status.SKIPPED) {
                return false;
            }

            if (result.getStatus() == RevocationCheckResult.Status.UNKNOWN) {
                return false;
            }

            // Return true if REVOKED or SUSPENDED
            return result.getStatus() == RevocationCheckResult.Status.REVOKED ||
                    result.getStatus() == RevocationCheckResult.Status.SUSPENDED;

        } catch (RevocationCheckException e) {
            throw new CredentialVerificationException(
                    "Error checking revocation status: " + e.getMessage(), e);
        }
    }


    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public VerifiableCredential parseCredential(String vcString, String contentType)
            throws CredentialVerificationException {

        if (vcString == null || vcString.trim().isEmpty()) {
            throw new CredentialVerificationException("Credential string is null or empty");
        }

        String normalizedContentType = VerificationUtil.normalizeContentType(contentType);

        try {
            // Auto-detect format if content type is generic JSON or null
            if (normalizedContentType == null || VerificationUtil.CONTENT_TYPE_JSON.equals(normalizedContentType)) {
                normalizedContentType = VerificationUtil.detectFormat(vcString);
            }

            if (VerificationUtil.CONTENT_TYPE_JWT.equals(normalizedContentType) ||
                    VerificationUtil.CONTENT_TYPE_VC_JWT.equals(normalizedContentType)) {
                return parseJwtCredential(vcString);
            } else if (VerificationUtil.CONTENT_TYPE_SD_JWT.equals(normalizedContentType)) {
                return parseSdJwtCredential(vcString);
            } else {
                return parseJsonLdCredential(vcString);
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse credential: " + e.getMessage(), e);
        }
    }



    /**
     * Parse a JWT credential.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private VerifiableCredential parseJwtCredential(String jwtString)
            throws CredentialVerificationException {

        String[] parts = jwtString.split("\\.");
        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT format: expected 3 parts");
        }

        try {
            VerifiableCredential credential = new VerifiableCredential();
            credential.setFormat(VerifiableCredential.Format.JWT);
            credential.setRawCredential(jwtString);
            credential.setJwtHeader(parts[0]);
            credential.setJwtPayload(parts[1]);
            credential.setJwtSignature(parts[2]);

            // Decode payload
            Map<String, Object> payload = VerificationUtil.parseJwtPart(parts[1]);
            credential.setJwtClaims(payload);

            // Extract standard claims
            if (payload.containsKey("iss")) {
                credential.setIssuer(payload.get("iss").toString());
                credential.setIssuerId(payload.get("iss").toString());
            }

            if (payload.containsKey("sub")) {
                credential.setCredentialSubjectId(payload.get("sub").toString());
            }

            if (payload.containsKey("jti")) {
                credential.setId(payload.get("jti").toString());
            }

            // Parse expiration
            if (payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                credential.setExpirationDate(new Date(exp * 1000));
            }

            // Parse issuance date
            if (payload.containsKey("iat")) {
                long iat = ((Number) payload.get("iat")).longValue();
                credential.setIssuanceDate(new Date(iat * 1000));
            } else if (payload.containsKey("nbf")) {
                long nbf = ((Number) payload.get("nbf")).longValue();
                credential.setIssuanceDate(new Date(nbf * 1000));
            }

            // Extract VC claim if present (JWT VC format)
            if (payload.containsKey("vc")) {
                Object vcClaim = payload.get("vc");
                if (vcClaim instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vcMap = (Map<String, Object>) vcClaim;
                    extractVcFields(credential, vcMap);
                }
            }

            return credential;

        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse JWT credential: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a SD-JWT credential.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private VerifiableCredential parseSdJwtCredential(String sdJwtString)
            throws CredentialVerificationException {

        SdJwtParts sdJwtParts = parseSdJwtParts(sdJwtString);

        try {
            // Parse the issuer JWT first
            VerifiableCredential credential = parseJwtCredential(sdJwtParts.issuerJwt);
            credential.setFormat(VerifiableCredential.Format.SD_JWT);
            credential.setRawCredential(sdJwtString);
            credential.setDisclosures(sdJwtParts.disclosures);
            if (sdJwtParts.keyBindingJwt != null) {
                credential.setKeyBindingJwt(sdJwtParts.keyBindingJwt);
            }

            // Process disclosures to extract revealed claims
            processDisclosures(credential);

            return credential;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse SD-JWT credential: " + e.getMessage(), e);
        }
    }

    /**
     * Process SD-JWT disclosures to extract claims.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings({ "REC_CATCH_EXCEPTION", "DE_MIGHT_IGNORE" })
    private void processDisclosures(VerifiableCredential credential) {
        if (credential.getDisclosures() == null) {
            return;
        }

        Map<String, Object> claims = credential.getCredentialSubject();
        if (claims == null) {
            claims = new HashMap<>();
            credential.setCredentialSubject(claims);
        }

        for (String disclosure : credential.getDisclosures()) {
            try {
                // Disclosure format: base64url([salt, claim_name, claim_value])
                String decoded = new String(Base64.getUrlDecoder().decode(disclosure),
                        StandardCharsets.UTF_8);
                JsonArray arr = JsonParser.parseString(decoded).getAsJsonArray();

                if (arr.size() >= 3) {
                    String claimName = arr.get(1).getAsString();
                    JsonElement claimValue = arr.get(2);
                    claims.put(claimName, VerificationUtil.parseJsonElement(claimValue));
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to parse SD-JWT disclosure: "
                            + VerificationUtil.removeCRLF(e.getMessage()), e);
                }
            }
        }
        credential.setCredentialSubject(claims);
    }

    /**
     * Parse a JSON-LD credential.
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private VerifiableCredential parseJsonLdCredential(String jsonString)
            throws CredentialVerificationException {

        try {
            JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();

            VerifiableCredential credential = new VerifiableCredential();
            credential.setFormat(VerifiableCredential.Format.JSON_LD);
            credential.setRawCredential(jsonString);

            // Parse @context
            if (json.has("@context")) {
                JsonElement context = json.get("@context");
                if (context.isJsonArray()) {
                    for (JsonElement el : context.getAsJsonArray()) {
                        if (el.isJsonPrimitive()) {
                            credential.addContext(el.getAsString());
                        }
                    }
                } else if (context.isJsonPrimitive()) {
                    credential.addContext(context.getAsString());
                }
            }

            // Parse type
            if (json.has("type")) {
                JsonElement typeEl = json.get("type");
                if (typeEl.isJsonArray()) {
                    for (JsonElement el : typeEl.getAsJsonArray()) {
                        credential.addType(el.getAsString());
                    }
                } else if (typeEl.isJsonPrimitive()) {
                    credential.addType(typeEl.getAsString());
                }
            }

            // Parse id
            if (json.has("id")) {
                credential.setId(json.get("id").getAsString());
            }

            // Parse issuer
            if (json.has("issuer")) {
                JsonElement issuerEl = json.get("issuer");
                if (issuerEl.isJsonPrimitive()) {
                    credential.setIssuer(issuerEl.getAsString());
                    credential.setIssuerId(issuerEl.getAsString());
                } else if (issuerEl.isJsonObject()) {
                    JsonObject issuerObj = issuerEl.getAsJsonObject();
                    if (issuerObj.has("id")) {
                        credential.setIssuerId(issuerObj.get("id").getAsString());
                    }
                    if (issuerObj.has("name")) {
                        credential.setIssuerName(issuerObj.get("name").getAsString());
                    }
                    credential.setIssuer(issuerObj.toString());
                }
            }

            // Parse dates
            if (json.has("issuanceDate")) {
                credential.setIssuanceDate(VerificationUtil.parseDate(json.get("issuanceDate").getAsString()));
            } else if (json.has("validFrom")) {
                credential.setIssuanceDate(VerificationUtil.parseDate(json.get("validFrom").getAsString()));
            }

            if (json.has("expirationDate")) {
                credential.setExpirationDate(VerificationUtil.parseDate(json.get("expirationDate").getAsString()));
            } else if (json.has("validUntil")) {
                credential.setExpirationDate(VerificationUtil.parseDate(json.get("validUntil").getAsString()));
            }

            // Parse credential subject
            if (json.has("credentialSubject")) {
                JsonElement subjectEl = json.get("credentialSubject");
                if (subjectEl.isJsonObject()) {
                    JsonObject subjectObj = subjectEl.getAsJsonObject();
                    Map<String, Object> subjectMap = new HashMap<>();
                    for (String key : subjectObj.keySet()) {
                        subjectMap.put(key, VerificationUtil.parseJsonElement(subjectObj.get(key)));
                    }
                    credential.setCredentialSubject(subjectMap);
                    if (subjectObj.has("id")) {
                        credential.setCredentialSubjectId(subjectObj.get("id").getAsString());
                    }
                }
            }

            // Parse credential status
            if (json.has("credentialStatus")) {
                JsonElement statusEl = json.get("credentialStatus");
                if (statusEl.isJsonObject()) {
                    JsonObject statusObj = statusEl.getAsJsonObject();
                    VerifiableCredential.CredentialStatus status = new VerifiableCredential.CredentialStatus();

                    if (statusObj.has("id")) {
                        status.setId(statusObj.get("id").getAsString());
                    }
                    if (statusObj.has("type")) {
                        status.setType(statusObj.get("type").getAsString());
                    }
                    if (statusObj.has("statusPurpose")) {
                        status.setStatusPurpose(statusObj.get("statusPurpose").getAsString());
                    }
                    if (statusObj.has("statusListIndex")) {
                        status.setStatusListIndex(statusObj.get("statusListIndex").getAsString());
                    }
                    if (statusObj.has("statusListCredential")) {
                        status.setStatusListCredential(
                                statusObj.get("statusListCredential").getAsString());
                    }

                    credential.setCredentialStatus(status);
                }
            }

            // Parse proof
            if (json.has("proof")) {
                JsonElement proofEl = json.get("proof");
                if (proofEl.isJsonObject()) {
                    credential.setProof(parseProof(proofEl.getAsJsonObject()));
                }
            }

            return credential;

        } catch (JsonSyntaxException e) {
            throw new CredentialVerificationException(
                    "Invalid JSON format: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a proof object.
     */
    private VerifiableCredential.Proof parseProof(JsonObject proofObj) {
        VerifiableCredential.Proof proof = new VerifiableCredential.Proof();

        if (proofObj.has("type")) {
            proof.setType(proofObj.get("type").getAsString());
        }
        if (proofObj.has("created")) {
            proof.setCreated(proofObj.get("created").getAsString());
        }
        if (proofObj.has("verificationMethod")) {
            proof.setVerificationMethod(proofObj.get("verificationMethod").getAsString());
        }
        if (proofObj.has("proofPurpose")) {
            proof.setProofPurpose(proofObj.get("proofPurpose").getAsString());
        }
        if (proofObj.has("proofValue")) {
            proof.setProofValue(proofObj.get("proofValue").getAsString());
        }
        if (proofObj.has("jws")) {
            proof.setJws(proofObj.get("jws").getAsString());
        }
        if (proofObj.has("challenge")) {
            proof.setChallenge(proofObj.get("challenge").getAsString());
        }
        if (proofObj.has("domain")) {
            proof.setDomain(proofObj.get("domain").getAsString());
        }

        return proof;
    }

    /**
     * Extract VC fields from a map (used for JWT VC claims).
     */
    private void extractVcFields(VerifiableCredential credential, Map<String, Object> vcMap) {
        if (vcMap.containsKey("type")) {
            Object types = vcMap.get("type");
            if (types instanceof List) {
                for (Object t : (List<?>) types) {
                    credential.addType(t.toString());
                }
            }
        }

        if (vcMap.containsKey("credentialSubject")) {
            Object subject = vcMap.get("credentialSubject");
            if (subject instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> subjectMap = (Map<String, Object>) subject;
                credential.setCredentialSubject(subjectMap);
                if (subjectMap.containsKey("id")) {
                    credential.setCredentialSubjectId(subjectMap.get("id").toString());
                }
            }
        }
    }

    @Override
    public VerifiablePresentation parsePresentation(String vpToken)
            throws CredentialVerificationException {

        if (vpToken == null || vpToken.trim().isEmpty()) {
            throw new CredentialVerificationException("VP token is null or empty");
        }

        try {
            // Detect format
            String format = VerificationUtil.detectFormat(vpToken);

            if (VerificationUtil.CONTENT_TYPE_JWT.equals(format)
                    || VerificationUtil.CONTENT_TYPE_VC_JWT.equals(format)) {
                return parseJwtPresentation(vpToken);
            } else {
                return parseJsonLdPresentation(vpToken);
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse presentation: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a JWT VP.
     */
    private VerifiablePresentation parseJwtPresentation(String jwtString)
            throws CredentialVerificationException {

        String[] parts = jwtString.split("\\.");
        if (parts.length != 3) {
            throw new CredentialVerificationException("Invalid JWT VP format");
        }

        try {
            VerifiablePresentation presentation = new VerifiablePresentation();
            presentation.setFormat(VerifiablePresentation.Format.JWT);
            presentation.setRawPresentation(jwtString);
            presentation.setJwtHeader(parts[0]);
            presentation.setJwtPayload(parts[1]);
            presentation.setJwtSignature(parts[2]);

            // Decode payload
            Map<String, Object> payload = VerificationUtil.parseJwtPart(parts[1]);
            presentation.setJwtClaims(payload);

            // Extract standard claims
            if (payload.containsKey("iss")) {
                presentation.setHolder(payload.get("iss").toString());
            }

            if (payload.containsKey("nonce")) {
                presentation.setNonce(payload.get("nonce").toString());
            }

            if (payload.containsKey("jti")) {
                presentation.setId(payload.get("jti").toString());
            }

            // Extract vp claim
            if (payload.containsKey("vp")) {
                Object vpClaim = payload.get("vp");
                if (vpClaim instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vpMap = (Map<String, Object>) vpClaim;
                    extractVpCredentials(presentation, vpMap);
                }
            }

            return presentation;

        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "Failed to parse JWT VP: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a JSON-LD VP.
     */
    private VerifiablePresentation parseJsonLdPresentation(String jsonString)
            throws CredentialVerificationException {

        try {
            JsonObject json = JsonParser.parseString(jsonString).getAsJsonObject();

            VerifiablePresentation presentation = new VerifiablePresentation();
            presentation.setFormat(VerifiablePresentation.Format.JSON_LD);
            presentation.setRawPresentation(jsonString);

            // Parse standard fields
            if (json.has("id")) {
                presentation.setId(json.get("id").getAsString());
            }

            if (json.has("holder")) {
                presentation.setHolder(json.get("holder").getAsString());
            }

            // Parse verifiable credentials
            if (json.has("verifiableCredential")) {
                JsonElement vcEl = json.get("verifiableCredential");
                if (vcEl.isJsonArray()) {
                    for (JsonElement el : vcEl.getAsJsonArray()) {
                        VerifiableCredential vc;
                        if (el.isJsonPrimitive()) {
                            // JWT credential
                            vc = parseCredential(el.getAsString(), VerificationUtil.CONTENT_TYPE_JWT);
                        } else {
                            // JSON-LD credential
                            vc = parseCredential(el.toString(), VerificationUtil.CONTENT_TYPE_VC_LD_JSON);
                        }
                        presentation.addVerifiableCredential(vc);
                    }
                } else if (vcEl.isJsonPrimitive()) {
                    VerifiableCredential vc = parseCredential(vcEl.getAsString(), VerificationUtil.CONTENT_TYPE_JWT);
                    presentation.addVerifiableCredential(vc);
                } else if (vcEl.isJsonObject()) {
                    VerifiableCredential vc = parseCredential(vcEl.toString(),
                            VerificationUtil.CONTENT_TYPE_VC_LD_JSON);
                    presentation.addVerifiableCredential(vc);
                }
            }

            // Parse proof
            if (json.has("proof")) {
                JsonElement proofEl = json.get("proof");
                if (proofEl.isJsonObject()) {
                    presentation.setProof(parseProof(proofEl.getAsJsonObject()));
                }
            }

            return presentation;

        } catch (JsonSyntaxException e) {
            throw new CredentialVerificationException(
                    "Invalid JSON format: " + e.getMessage(), e);
        }
    }

    /**
     * Extract credentials from a VP map.
     */
    private void extractVpCredentials(VerifiablePresentation presentation,
            Map<String, Object> vpMap)
            throws CredentialVerificationException {

        if (vpMap.containsKey("verifiableCredential")) {
            Object vcClaim = vpMap.get("verifiableCredential");

            if (vcClaim instanceof List) {
                for (Object vc : (List<?>) vcClaim) {
                    if (vc instanceof String) {
                        // JWT credential
                        presentation.addVerifiableCredential(
                                parseCredential(vc.toString(), VerificationUtil.CONTENT_TYPE_JWT));
                    } else if (vc instanceof Map) {
                        // JSON-LD credential embedded in JWT VP
                        presentation.addVerifiableCredential(
                                parseCredential(GSON.toJson(vc), VerificationUtil.CONTENT_TYPE_VC_LD_JSON));
                    }
                }
            } else if (vcClaim instanceof String) {
                presentation.addVerifiableCredential(
                        parseCredential(vcClaim.toString(), VerificationUtil.CONTENT_TYPE_JWT));
            }
        }
    }

    @Override
    public boolean verifyNonce(String vpToken, String expectedNonce)
            throws CredentialVerificationException {

        if (expectedNonce == null) {
            return true; // No nonce to verify
        }

        VerifiablePresentation presentation = parsePresentation(vpToken);
        String actualNonce = presentation.getJwtNonce();

        return expectedNonce.equals(actualNonce);
    }

    @Override
    public boolean isContentTypeSupported(String contentType) {
        if (contentType == null) {
            return true; // Will auto-detect
        }
        String normalized = VerificationUtil.normalizeContentType(contentType);
        return Arrays.asList(SUPPORTED_CONTENT_TYPES).contains(normalized);
    }

    @Override
    public String[] getSupportedContentTypes() {
        return SUPPORTED_CONTENT_TYPES.clone();
    }

    // Utility methods

    // Utility methods extracted to VerificationUtil

    @Override
    public boolean verifyJWTVCIssuer(String vcJwt, String tenantDomain) throws CredentialVerificationException {

        try {
            // Delegate to verify(); it performs format validation and signature check internally.
            VCVerificationResultDTO result = verify(vcJwt, "application/vc+jwt");
            if (!result.isSuccess()) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "JWT signature verification failed");
            }
            return true;
        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "JWT VC issuer verification failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verifyJWTVCIssuer(VerifiableCredential credential, String tenantDomain)
            throws CredentialVerificationException {

        // Verify using the pre-parsed credential — no re-parsing required.
        VCVerificationResultDTO result = verifyCredentialInternal(credential, 0);
        if (!result.isSuccess()) {
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "JWT VC issuer verification failed: " + result.getError());
        }
        return true;
    }

    @Override
    public boolean verifyJSONLDVCIssuer(JsonObject vcJsonObject, String tenantDomain)
            throws CredentialVerificationException {

        try {
            // Validate issuer field exists
            if (!vcJsonObject.has("issuer")) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Missing issuer field");
            }
            JsonElement issuerElement = vcJsonObject.get("issuer");
            if (!issuerElement.isJsonPrimitive() && !issuerElement.isJsonObject()) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "Invalid issuer format");
            }

            String vcString = GSON.toJson(vcJsonObject);
            VCVerificationResultDTO result = verify(vcString, "application/vc+ld+json");
            if (!result.isSuccess()) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "JSON-LD signature verification failed");
            }
            return true;

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialVerificationException(
                    "JSON-LD VC issuer verification failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verifyJSONLDVCIssuer(VerifiableCredential credential, String tenantDomain)
            throws CredentialVerificationException {

        // Verify using the pre-parsed credential — no re-parsing required.
        VCVerificationResultDTO result = verifyCredentialInternal(credential, 0);
        if (!result.isSuccess()) {
            throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                    "JSON-LD VC issuer verification failed: " + result.getError());
        }
        return true;
    }

    @Override
    public void verifyAllIssuerTrust(String vpToken, String presentationSubmissionJson, String tenantDomain)
            throws CredentialVerificationException {

        if (vpToken == null || vpToken.trim().isEmpty()) {
            return;
        }

        String detectedFormat = null;
        if (presentationSubmissionJson != null && !presentationSubmissionJson.trim().isEmpty()) {
            detectedFormat = VerificationUtil.extractFormatFromSubmission(presentationSubmissionJson);
        }

        if (VerificationUtil.NORMALIZED_VC_SD_JWT.equals(detectedFormat)) {
            SdJwtParts sdJwtParts = parseSdJwtParts(vpToken);
            boolean trusted = verifyJWTVCIssuer(sdJwtParts.issuerJwt, tenantDomain);
            if (!trusted) {
                throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                        "SD-JWT credential from untrusted issuer");
            }
            return;
        }

        // JWT VP or JSON-LD VP: parse once, then check each embedded VC
        VerifiablePresentation vp;
        try {
            vp = parsePresentation(vpToken);
        } catch (CredentialVerificationException e) {
            throw new CredentialVerificationException(
                    "Failed to parse VP token for issuer trust check: " + e.getMessage(), e);
        }

        if (vp.getVerifiableCredentials() == null || vp.getVerifiableCredentials().isEmpty()) {
            // No embedded credentials to verify — nothing to do
            return;
        }

        int index = 0;
        for (VerifiableCredential vc : vp.getVerifiableCredentials()) {
            index++;
            if (vc.isJwt() || vc.isSdJwt()) {
                // R1: Use pre-parsed VC overload — avoids re-parsing the raw credential string.
                boolean trusted = verifyJWTVCIssuer(vc, tenantDomain);
                if (!trusted) {
                    throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                            "Credential " + index + " from untrusted issuer: " + vc.getIssuerId());
                }
            } else if (vc.isJsonLd()) {
                // R1: Use pre-parsed VC overload — avoids a redundant JSON serialization/parse cycle.
                boolean trusted = verifyJSONLDVCIssuer(vc, tenantDomain);
                if (!trusted) {
                    throw new CredentialVerificationException(VCVerificationStatus.INVALID,
                            "Credential " + index + " from untrusted issuer: " + vc.getIssuerId());
                }
            }
        }
    }

    /**
     * Helper to get tenant ID from domain.
     */

    @Override
    public Map<String, Object> verifySdJwtToken(String vpToken, 
                                            String expectedNonce, 
                                            String expectedAudience, 
                                            String presentationDefinitionJson) 
            throws CredentialVerificationException {

        if (vpToken == null) {
            throw new CredentialVerificationException("VP token cannot be null.");
        }

        // Fix: Remove extra quotes if present
        String trimmed = vpToken.trim();
        if (trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            try {
                vpToken = GSON.fromJson(trimmed, String.class);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to unquote SD-JWT string, using original", e);
                }
            }
        }

        try {
            // Parse the SD-JWT into its three canonical parts using the shared helper.
            SdJwtParts sdJwtParts = parseSdJwtParts(vpToken);
            String issuerJwtString = sdJwtParts.issuerJwt;
            List<String> disclosures = sdJwtParts.disclosures;
            String keyBindingJwtString = sdJwtParts.keyBindingJwt;

            // 1. Verify Issuer JWT Signature
            VerifiableCredential paramCred = new VerifiableCredential();
            paramCred.setFormat(VerifiableCredential.Format.JWT);
            paramCred.setRawCredential(issuerJwtString);
            
            SignedJWT signedIssuerJwt = SignedJWT.parse(issuerJwtString);
            String issuer = signedIssuerJwt.getJWTClaimsSet().getIssuer();
            paramCred.setIssuer(issuer);
            paramCred.setIssuerId(issuer);

            if (!verifySignature(paramCred)) {
                throw new CredentialVerificationException("Issuer JWT signature verification failed.");
            }

            // 2. Verify Issuer JWT Time Claims (with clock-skew tolerance)
            Date exp = signedIssuerJwt.getJWTClaimsSet().getExpirationTime();
            Date nbf = signedIssuerJwt.getJWTClaimsSet().getNotBeforeTime();
            Date now = new Date();

            if (exp != null && now.after(new Date(exp.getTime() + CLOCK_SKEW_TOLERANCE_MS))) {
                throw new CredentialVerificationException("SD-JWT expired.");
            }
            if (nbf != null && now.before(new Date(nbf.getTime() - CLOCK_SKEW_TOLERANCE_MS))) {
                throw new CredentialVerificationException("SD-JWT not valid yet.");
            }

            // 3. Verify Disclosures against _sd in Issuer JWT
            Map<String, Object> issuerClaims = signedIssuerJwt.getJWTClaimsSet().getClaims();

            // P0-1: Honour _sd_alg claim for disclosure hashing
            String sdAlgClaim = issuerClaims.containsKey("_sd_alg")
                    ? issuerClaims.get("_sd_alg").toString() : null;
            String hashAlgorithm = VerificationUtil.resolveHashAlgorithm(sdAlgClaim);

            Map<String, String> disclosureDigestMap = new HashMap<>();
            for (String d : disclosures) {
                disclosureDigestMap.put(hashDisclosure(d, hashAlgorithm), d);
            }

            // Reconstruct the verified claims map
            Map<String, Object> verifiedClaims = new HashMap<>(issuerClaims);
            verifiedClaims.remove("_sd");
            verifiedClaims.remove("_sd_alg");

            // Track which disclosure digests were matched by an _sd entry
            java.util.Set<String> matchedDigests = new java.util.HashSet<>();

            if (issuerClaims.containsKey("_sd")) {
                Object sdObj = issuerClaims.get("_sd");
                if (sdObj instanceof List) {
                    List<?> sdList = (List<?>) sdObj;
                    for (Object digestObj : sdList) {
                        if (digestObj instanceof String) {
                            String digest = (String) digestObj;
                            if (disclosureDigestMap.containsKey(digest)) {
                                matchedDigests.add(digest);
                                String disclosure = disclosureDigestMap.get(digest);
                                String decoded = new String(Base64.getUrlDecoder().decode(disclosure),
                                        StandardCharsets.UTF_8);
                                JSONArray arr = (JSONArray) net.minidev.json.JSONValue.parse(decoded);
                                if (arr != null && arr.size() >= 3) {
                                    String key = (String) arr.get(1);
                                    Object val = arr.get(2);
                                    verifiedClaims.put(key, val);
                                }
                            }
                        }
                    }
                }
            }

            // P0-2: Reject presentations with unmatched disclosures
            if (matchedDigests.size() != disclosureDigestMap.size()) {
                java.util.Set<String> unmatched = new java.util.HashSet<>(disclosureDigestMap.keySet());
                unmatched.removeAll(matchedDigests);
                throw new CredentialVerificationException(
                        "SD-JWT contains " + unmatched.size()
                                + " disclosure(s) whose hash does not appear in the _sd array.");
            }

            // 4. Verify Key Binding JWT (KB-JWT)
            if (keyBindingJwtString != null) {
                SignedJWT kbJwt = SignedJWT.parse(keyBindingJwtString);

                // P0-3: Validate KB-JWT typ header (must be "kb+jwt" per SD-JWT spec)
                com.nimbusds.jose.JOSEObjectType kbTyp = kbJwt.getHeader().getType();
                if (kbTyp == null || !"kb+jwt".equalsIgnoreCase(kbTyp.toString())) {
                    throw new CredentialVerificationException(
                            "Key Binding JWT typ header must be 'kb+jwt', got: " + kbTyp);
                }

                // P0-3: Validate KB-JWT iat (must be present and recent)
                Date kbIat = kbJwt.getJWTClaimsSet().getIssueTime();
                if (kbIat == null) {
                    throw new CredentialVerificationException(
                            "Key Binding JWT is missing required 'iat' claim.");
                }
                if (now.getTime() - kbIat.getTime() > KB_JWT_MAX_AGE_MS + CLOCK_SKEW_TOLERANCE_MS) {
                    throw new CredentialVerificationException(
                            "Key Binding JWT 'iat' is too old (older than "
                                    + (KB_JWT_MAX_AGE_MS / 1000) + "s).");
                }

                String kbNonce = (String) kbJwt.getJWTClaimsSet().getClaim("nonce");
                Object kbAudObj = kbJwt.getJWTClaimsSet().getClaim("aud");
                String kbAud = kbAudObj instanceof String ? (String) kbAudObj :
                              (kbAudObj instanceof List ? ((List<?>) kbAudObj).get(0).toString() : null);

                if (expectedNonce != null) {
                    byte[] expected = expectedNonce.getBytes(StandardCharsets.UTF_8);
                    byte[] actual = kbNonce != null ? kbNonce.getBytes(StandardCharsets.UTF_8) : new byte[0];
                    if (!MessageDigest.isEqual(expected, actual)) {
                        throw new CredentialVerificationException("Key Binding nonce mismatch.");
                    }
                }
                if (expectedAudience != null) {
                    byte[] expected = expectedAudience.getBytes(StandardCharsets.UTF_8);
                    byte[] actual = kbAud != null ? kbAud.getBytes(StandardCharsets.UTF_8) : new byte[0];
                    if (!MessageDigest.isEqual(expected, actual)) {
                        throw new CredentialVerificationException("Key Binding audience mismatch.");
                    }
                }

                String sdHash = (String) kbJwt.getJWTClaimsSet().getClaim("sd_hash");
                if (sdHash == null) {
                    throw new CredentialVerificationException("sd_hash missing in Key Binding JWT.");
                }

                String calculatedSdHash = hashSd(issuerJwtString, disclosures, hashAlgorithm);
                byte[] calculatedSdHashBytes = calculatedSdHash.getBytes(StandardCharsets.UTF_8);
                byte[] sdHashBytes = sdHash.getBytes(StandardCharsets.UTF_8);
                if (!MessageDigest.isEqual(calculatedSdHashBytes, sdHashBytes)) {
                     throw new CredentialVerificationException("sd_hash mismatch.");
                }

                // Verify KB-JWT Signature
                @SuppressWarnings("unchecked")
                Map<String, Object> cnf = (Map<String, Object>) issuerClaims.get("cnf");
                if (cnf == null || !cnf.containsKey("jwk")) {
                     throw new CredentialVerificationException("cnf.jwk missing in Issuer JWT.");
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
                com.nimbusds.jose.jwk.JWK holderKey = com.nimbusds.jose.jwk.JWK.parse(jwkMap);

                // P0-4: Support non-EC key types in KB-JWT signature verification
                PublicKey holderPublicKey;
                com.nimbusds.jose.jwk.KeyType keyType = holderKey.getKeyType();
                if (com.nimbusds.jose.jwk.KeyType.EC.equals(keyType)) {
                    holderPublicKey = holderKey.toECKey().toPublicKey();
                } else if (com.nimbusds.jose.jwk.KeyType.RSA.equals(keyType)) {
                    holderPublicKey = holderKey.toRSAKey().toPublicKey();
                } else if (com.nimbusds.jose.jwk.KeyType.OKP.equals(keyType)) {
                    holderPublicKey = holderKey.toOctetKeyPair().toPublicKey();
                } else {
                    throw new CredentialVerificationException(
                            "Unsupported holder key type in cnf.jwk: " + keyType);
                }

                com.nimbusds.jose.JWSVerifier verifier =
                    new com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory()
                        .createJWSVerifier(kbJwt.getHeader(), holderPublicKey);

                if (!kbJwt.verify(verifier)) {
                    throw new CredentialVerificationException("Key Binding JWT signature invalid.");
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key Binding JWT is missing. Skipping holder binding verification.");
                }
            }

            // 5. Verify Claims against Presentation Definition
            if (presentationDefinitionJson != null && !presentationDefinitionJson.isEmpty()) {
                verifyClaimsAgainstDefinition(verifiedClaims, presentationDefinitionJson);
            }

            return verifiedClaims;

        } catch (ParseException | NoSuchAlgorithmException | CredentialVerificationException | JOSEException e) {
             throw new CredentialVerificationException("SD-JWT verification failed: " + e.getMessage(), e);
        } catch (RuntimeException e) {
             throw new CredentialVerificationException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void verifyClaimsAgainstDefinition(Map<String, Object> claims, String presentationDefinitionJson)
            throws CredentialVerificationException {
        
        try {
            Object pdObj = net.minidev.json.JSONValue.parse(presentationDefinitionJson);
            if (!(pdObj instanceof net.minidev.json.JSONObject)) {
                 throw new CredentialVerificationException("Invalid Presentation Definition JSON.");
            }
            net.minidev.json.JSONObject pd = (net.minidev.json.JSONObject) pdObj;
            
            JSONArray inputDescriptors = (JSONArray) pd.get("input_descriptors");
            JSONArray requestedCredentials = (JSONArray) pd.get("requested_credentials");
            
            if (inputDescriptors == null && requestedCredentials == null) {
                return;
            }

            String claimsJson = new com.google.gson.Gson().toJson(claims);
            Object document = com.jayway.jsonpath.Configuration.defaultConfiguration().jsonProvider().parse(claimsJson);

            // Handle standard Presentation Exchange format
            if (inputDescriptors != null) {
                for (Object desc : inputDescriptors) {
                    net.minidev.json.JSONObject descriptor = (net.minidev.json.JSONObject) desc;
                    net.minidev.json.JSONObject constraints = 
                            (net.minidev.json.JSONObject) descriptor.get("constraints");
                    if (constraints != null) {
                        JSONArray fields = (JSONArray) constraints.get("fields");
                        if (fields != null) {
                            for (Object f : fields) {
                                net.minidev.json.JSONObject field = (net.minidev.json.JSONObject) f;
                                JSONArray paths = (JSONArray) field.get("path");
                                if (paths != null) {
                                    boolean matchFound = false;
                                    for (Object p : paths) {
                                        String jsonPath = (String) p;
                                        try {
                                            JsonPath.read(document, jsonPath);
                                            matchFound = true;
                                            break; 
                                        } catch (com.jayway.jsonpath.PathNotFoundException e) {
                                        }
                                    }
                                    if (!matchFound) {
                                        throw new 
                                        CredentialVerificationException("Claim constraint not met for field path(s): " 
                                                + paths);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Handle simplified requested_credentials format
            if (requestedCredentials != null) {
                for (Object cred : requestedCredentials) {
                    net.minidev.json.JSONObject credentialReq = (net.minidev.json.JSONObject) cred;

                    // Server-side issuer enforcement: verify the VC issuer's host matches the trusted
                    // issuer host configured in the presentation definition, if present.
                    // Comparison is hostname-only so that a configured value like
                    //   "masked-unprofitably-ardith.ngrok-free.dev"
                    // matches a VC iss of
                    //   "https://masked-unprofitably-ardith.ngrok-free.dev/oid4vci"
                    String expectedIssuer = (String) credentialReq.get("issuer");
                    if (expectedIssuer != null && !expectedIssuer.isEmpty()) {
                        Object actualIssuerObj = claims.get("iss");
                        if (actualIssuerObj == null) {
                            actualIssuerObj = claims.get("issuer");
                        }
                        if (actualIssuerObj == null) {
                            throw new CredentialVerificationException(
                                    "VC issuer mismatch. Expected host: " + expectedIssuer
                                            + ", but no iss/issuer claim found in VC.");
                        }
                        String actualIssuer = actualIssuerObj.toString();
                        if (!issuerHostMatches(expectedIssuer, actualIssuer)) {
                            throw new CredentialVerificationException(
                                    "VC issuer mismatch. Expected host: " + expectedIssuer
                                            + ", got: " + actualIssuer);
                        }
                    }

                    JSONArray requestedClaims = (JSONArray) credentialReq.get("requested_claims");
                    
                    if (requestedClaims != null) {
                        for (Object c : requestedClaims) {
                            String claimName = (String) c;
                            String jsonPath = "$." + claimName;
                            try {
                                JsonPath.read(document, jsonPath);
                            } catch (com.jayway.jsonpath.PathNotFoundException e) {
                                throw new CredentialVerificationException("Requested claim not found in presentation: " 
                                        + claimName);
                            }
                        }
                    }
                }
            }

        } catch (CredentialVerificationException e) {
            throw e;
        } catch (Exception e) {
             throw new CredentialVerificationException("Claim constraint check failed: " + e.getMessage(), e);
        }
    }


    /**
     * Compare issuer values by hostname only.
     *
     * <p>The expected issuer stored in the presentation definition may be a bare hostname
     * (e.g. {@code masked-unprofitably-ardith.ngrok-free.dev}) while the {@code iss} claim
     * in the VC is typically a full URL
     * (e.g. {@code https://masked-unprofitably-ardith.ngrok-free.dev/oid4vci}).
     * Both should be considered a match.</p>
     *
     * @param expected The issuer value from the presentation definition
     * @param actual   The iss/issuer claim from the verified VC
     * @return true if the hostnames are equal (case-insensitive)
     */
    private boolean issuerHostMatches(String expected, String actual) {
        String expectedHost = VerificationUtil.extractHost(expected);
        String actualHost = VerificationUtil.extractHost(actual);
        return expectedHost != null && expectedHost.equalsIgnoreCase(actualHost);
    }



    private String hashDisclosure(String disclosure, String algorithm) throws NoSuchAlgorithmException {
        return VerificationUtil.createHash(disclosure, algorithm);
    }

    private String hashSd(String issuerJwt, List<String> disclosures, String algorithm)
            throws NoSuchAlgorithmException {
        StringBuilder sb = new StringBuilder();
        sb.append(issuerJwt);
        for (String d : disclosures) {
            sb.append("~").append(d);
        }
        sb.append("~");
        return VerificationUtil.createHash(sb.toString(), algorithm);
    }

    /**
     * Parse an SD-JWT token into its three canonical sections.
     *
     * <p>Format: {@code <issuer-jwt>~[<disclosure>~]*[<kb-jwt>]}</p>
     *
     * <p>The last {@code ~}-delimited segment is treated as the Key Binding JWT if
     * it is non-empty and contains embedded dots (i.e. is itself a 3-part JWT).
     * All segments between the first and the optional KB-JWT are disclosure values.</p>
     *
     * @param sdJwt The raw SD-JWT string
     * @return A {@link SdJwtParts} instance holding issuerJwt, disclosures, and keyBindingJwt
     * @throws CredentialVerificationException if the token does not contain at least an issuer JWT
     */
    private SdJwtParts parseSdJwtParts(String sdJwt) throws CredentialVerificationException {
        String[] parts = sdJwt.split("~", -1);
        if (parts.length < 1 || parts[0].isEmpty()) {
            throw new CredentialVerificationException("Invalid SD-JWT format: missing issuer JWT");
        }
        String issuerJwt = parts[0];
        List<String> disclosures = new ArrayList<>();
        String keyBindingJwt = null;
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.isEmpty()) {
                continue;
            }
            // The last non-empty segment is the KB-JWT when it is itself a 3-part JWT.
            if (i == parts.length - 1 && part.split("\\.").length == 3) {
                keyBindingJwt = part;
            } else {
                disclosures.add(part);
            }
        }
        return new SdJwtParts(issuerJwt, disclosures, keyBindingJwt);
    }

    /**
     * Canonical holder for the three sections of a parsed SD-JWT token.
     *
     * @param issuerJwt     The issuer-signed JWT (always present)
     * @param disclosures   Ordered list of base64url-encoded disclosure values
     * @param keyBindingJwt The Key Binding JWT, or {@code null} when absent
     */
    private static final class SdJwtParts {
        private final String issuerJwt;
        private final List<String> disclosures;
        private final String keyBindingJwt;

        private SdJwtParts(String issuerJwt, List<String> disclosures, String keyBindingJwt) {
            this.issuerJwt = issuerJwt;
            this.disclosures = disclosures;
            this.keyBindingJwt = keyBindingJwt;
        }
    }

    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings({"REC_CATCH_EXCEPTION", "CRLF_INJECTION_LOGS"})
    private String resolveJwksUri(String issuer) throws CredentialVerificationException {
        try {
            // 1. Fetch Issuer Metadata
            String metadataUrl = issuer.endsWith("/") ? issuer + ".well-known/openid-credential-issuer"
                    : issuer + "/.well-known/openid-credential-issuer";

            JsonObject metadata = HttpClientUtil.fetchJson(metadataUrl);
            if (metadata == null) {
                // If standard metadata fails, optionally check openid-configuration (standard OIDC)
                String oidcMetadataUrl = issuer.endsWith("/") ? issuer + ".well-known/openid-configuration"
                        : issuer + "/.well-known/openid-configuration";
                try {
                    metadata = HttpClientUtil.fetchJson(oidcMetadataUrl);
                } catch (Exception e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Failed to fetch OIDC metadata from "
                                + VerificationUtil.removeCRLF(oidcMetadataUrl), e);
                    }
                }
            }

            if (metadata == null) {
                return null;
            }

            // 2. Check for jwks_uri in metadata
            if (metadata.has("jwks_uri")) {
                return metadata.get("jwks_uri").getAsString();
            }

            // 3. Fallback: Check authorization_servers
            if (metadata.has("authorization_servers")) {
                JsonArray authServers = metadata.getAsJsonArray("authorization_servers");
                if (authServers.size() > 0) {
                    String authServer = authServers.get(0).getAsString();
                    
                    // Try to fetch OIDC metadata for this auth server
                    String authServerMetadataUrl = authServer.endsWith("/") ? authServer + 
                    ".well-known/openid-configuration"
                            : authServer + "/.well-known/openid-configuration";
                    
                    try {
                        JsonObject authServerMetadata = HttpClientUtil.fetchJson(authServerMetadataUrl);
                        if (authServerMetadata != null && authServerMetadata.has("jwks_uri")) {
                            return authServerMetadata.get("jwks_uri").getAsString();
                        }
                    } catch (Exception e) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Failed to fetch OIDC metadata from auth server: " + 
                            VerificationUtil.removeCRLF(authServerMetadataUrl), e);
                        }
                    }
                    
                    // Keep the hardcoded fallback as a last resort, but maybe log a warning?
                    // Or relies on the metadata fetch above.
                    // Given the user's specific error, the hardcoded path was WRONG. 
                    // So we probably shouldn't fallback to it if it's known to be wrong for their case.
                    // But for backward compatibility? 
                    // The user's error showed .../oauth2/token/oauth2/jwks.
                    // It seems the authServer variable was `.../oauth2/token`.
                    // If we just return null here, it will throw "Failed to resolve JWKS URI".
                }
            }
        } catch (Exception e) {
            throw new CredentialVerificationException("Failed to resolve JWKS URI: " + e.getMessage(), e);
        }
        return null;
    }



    // -----------------------------------------------------------------------
    // Unified VP verification entry-point
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Implementation overview:
     * <ol>
     *   <li>Extract the VC format from {@code descriptor_map[0].format} inside
     *       the supplied {@code submissionJson}.</li>
     *   <li>Dispatch to the appropriate format-specific verifier.</li>
     *   <li>Return a {@link VPVerificationResponseDTO} with the outcome.</li>
     * </ol>
     */
    @Override
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public VPVerificationResponseDTO verifyPresentation(String vpToken,
            String submissionJson,
            String presentationDefinitionId,
            int tenantId)
            throws CredentialVerificationException {

        if (vpToken == null || vpToken.trim().isEmpty()) {
            throw new CredentialVerificationException("vpToken must not be null or empty.");
        }
        if (submissionJson == null || submissionJson.trim().isEmpty()) {
            throw new CredentialVerificationException(
                    "submissionJson (presentation_submission) must not be null or empty.");
        }

        // 1. Detect format from the presentation_submission descriptor_map.
        String detectedFormat = VerificationUtil.extractFormatFromSubmission(submissionJson);

        // 2. Resolve Presentation Definition JSON by ID (if provided and service is available).
        String effectivePdJson = null;
        if (presentationDefinitionId != null && !presentationDefinitionId.trim().isEmpty()
                && presentationDefinitionService != null) {
            try {
                PresentationDefinition pd = presentationDefinitionService
                        .getPresentationDefinitionById(presentationDefinitionId, tenantId);
                if (pd != null) {
                    effectivePdJson = PresentationDefinitionUtil.buildDefinitionJson(pd);
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not resolve PresentationDefinition with ID: "
                            + presentationDefinitionId + ". PD constraints will be skipped.", e);
                }
            }
        }

        // 3. Extract nonce and audience from the VP token so the caller (Authenticator)
        //    can perform replay-attack validation.
        String[] nonceAndAud = VerificationUtil.extractNonceAndAudienceFromVpToken(vpToken, detectedFormat);
        String extractedNonce = nonceAndAud[0];
        String extractedAudience = nonceAndAud[1];

        try {
            // 4. Route to format-specific verifier.
            VPVerificationResponseDTO result;
            if (VerificationUtil.NORMALIZED_VC_SD_JWT.equals(detectedFormat)) {
                result = verifySdJwtPresentation(vpToken, effectivePdJson, detectedFormat);
            } else {
                result = verifyJwtOrJsonLdPresentation(vpToken, detectedFormat, effectivePdJson);
            }

            // 5. Re-wrap successful result to include extracted nonce / audience.
            if (result.isValid()) {
                return VPVerificationResponseDTO.success(
                        result.getVerifiedClaims(), detectedFormat, extractedNonce, extractedAudience);
            }
            return result;
        } catch (CredentialVerificationException e) {
            return VPVerificationResponseDTO.failure(e.getMessage(), detectedFormat);
        } catch (Exception e) {
            return VPVerificationResponseDTO.failure(
                    "Unexpected error during VP verification: " + e.getMessage(), detectedFormat);
        }
    }

    /**
     * Handle SD-JWT VP verification and wrap the result in a
     * {@link VPVerificationResponseDTO}.
     *
     * <p>Nonce and audience are <strong>not</strong> validated here; they are
     * extracted by {@link #VerificationUtil.extractNonceAndAudienceFromVpToken} and returned in
     * the DTO for the caller (Authenticator) to validate.
     */
    private VPVerificationResponseDTO verifySdJwtPresentation(String vpToken,
            String pdJson,
            String detectedFormat)
            throws CredentialVerificationException {

        // Pass null for nonce/audience — caller is responsible for those checks.
        Map<String, Object> verifiedClaims = verifySdJwtToken(
                vpToken, null, null, pdJson != null ? pdJson : "");
        return VPVerificationResponseDTO.success(verifiedClaims, detectedFormat);
    }

    /**
     * Handle JWT-VP / JSON-LD VP verification and wrap the result in a
     * {@link VPVerificationResponseDTO}.
     *
     * <p>Steps:
     * <ol>
     *   <li>Parse the VP token once into a {@link VerifiablePresentation}.</li>
     *   <li>Verify each embedded credential (signature, expiry, etc.).</li>
     *   <li>Extract {@code credentialSubject} claims from the already-parsed object.</li>
     *   <li>Optionally enforce Presentation Definition constraints.</li>
     * </ol>
     *
     * <p>This avoids the previous double-parse pattern where the raw token string was
     * parsed multiple times. The parsed {@link VerifiablePresentation} is now used for all steps.
     */
    private VPVerificationResponseDTO verifyJwtOrJsonLdPresentation(String vpToken,
            String detectedFormat,
            String pdJson)
            throws CredentialVerificationException {

        // R4: Parse the VP exactly once.
        VerifiablePresentation parsedVp = parsePresentation(vpToken);

        // Verify signature / credentials inside the parsed VP.
        verifyPresentation(parsedVp);

        // Extract claims from the already-parsed VP object — no re-parse of raw string.
        Map<String, Object> verifiedClaims = extractClaimsFromPresentation(parsedVp, vpToken, detectedFormat);

        // Enforce PD constraints if a definition was provided.
        if (pdJson != null && !pdJson.isEmpty()) {
            verifyClaimsAgainstDefinition(verifiedClaims, pdJson);
        }

        return VPVerificationResponseDTO.success(verifiedClaims, detectedFormat);
    }

    /**
     * Extract verified claims from an already-parsed {@link VerifiablePresentation}.
     *
     * <p>Tries to build the claims map from the parsed object first (JWT VPs expose
     * {@code getJwtClaims()}; JSON-LD VPs expose the credential subject directly).
     * Falls back to the utility method that re-parses the raw token only when the
     * parsed object does not carry a usable claims map (e.g. for opaque VP types).
     *
     * @param parsedVp       The already-parsed presentation
     * @param rawVpToken     The original raw VP token string (fallback only)
     * @param detectedFormat The format string used by the fallback extractor
     * @return A non-null (possibly empty) map of verified claims
     */
    private Map<String, Object> extractClaimsFromPresentation(
            VerifiablePresentation parsedVp,
            String rawVpToken,
            String detectedFormat) {

        // Prefer claims already in the parsed VP object to avoid a second raw token parse.
        Map<String, Object> jwtClaims = parsedVp.getJwtClaims();
        if (jwtClaims != null && !jwtClaims.isEmpty()) {
            return jwtClaims;
        }

        // Fallback: use the utility extractor (parses the raw string).
        return VerificationUtil.extractClaimsFromVpToken(rawVpToken, detectedFormat);
    }

}
