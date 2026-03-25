# OpenID4VP Presentation Verification — Class & Method Reference

This document explains each class and method purpose, flow role, inputs, outputs, and error handling for the `presentation.verification` component.

---

## 1) End-to-end flow map (how all classes work together)

1. Wallet submission is validated by `VPSubmissionValidator`.
2. Main orchestration starts in `VCVerificationServiceImpl.verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`.
3. Format is detected from `presentation_submission.descriptor_map[0].format`.
4. Route:
   - SD-JWT → `verifySdJwtPresentation()` / `verifySdJwtToken()`
   - JWT-VP / JSON-LD VP → `verifyJwtOrJsonLdPresentation()`
5. Each embedded VC is parsed (`parseCredential`) and verified (`verifyCredentialInternal`) for:
   - expiry
   - signature
   - revocation (optional soft-fail behavior)
6. Revocation status is checked via `StatusListServiceImpl`.
7. Utility helpers (`VerificationUtil`, `SignatureVerifier`, `HttpClientUtil`, `ExtendedJWKSValidator`) support parsing, hashing, signatures, and HTTP/JWKS fetch.
8. Final response is wrapped in `VPVerificationResponseDTO`.

---

## 2) Service interfaces

## 2.1 `VCVerificationService`
Purpose: public contract for VC/VP verification.

### Public methods
- `verify(String vcString, String contentType)`
  - Input: VC string + content type
  - Return: `VCVerificationResultDTO`
  - Errors: `CredentialVerificationException`

- `verify(String vcString, String contentType, int vcIndex)`
  - Same as above with VC index context

- `verifyCredential(VerifiableCredential credential)`
  - Input: parsed VC object
  - Return: `VCVerificationResultDTO`
  - Errors: `CredentialVerificationException`

- `verifyPresentation(VerifiablePresentation presentation)`
  - Input: parsed VP object
  - Return: list of per-VC results
  - Errors: `CredentialVerificationException`

- `verifySignature(VerifiableCredential credential)`
  - Input: parsed VC
  - Return: signature-valid boolean
  - Errors: `CredentialVerificationException`

- `isExpired(VerifiableCredential credential)`
  - Input: VC
  - Return: boolean

- `isRevoked(VerifiableCredential credential)`
  - Input: VC
  - Return: boolean
  - Errors: `CredentialVerificationException`

- `parseCredential(String vcString, String contentType)`
  - Input: raw VC and content type
  - Return: `VerifiableCredential`
  - Errors: `CredentialVerificationException`

- `parsePresentation(String vpToken)`
  - Input: raw VP token
  - Return: `VerifiablePresentation`
  - Errors: `CredentialVerificationException`

- `verifyNonce(String vpToken, String expectedNonce)`
  - Input: VP token + expected nonce
  - Return: boolean
  - Errors: `CredentialVerificationException`

- `isContentTypeSupported(String contentType)`
  - Input: content type
  - Return: boolean

- `getSupportedContentTypes()`
  - Return: supported content type array

- `verifyJWTVCIssuer(String vcJwt, String tenantDomain)`
- `verifyJWTVCIssuer(VerifiableCredential credential, String tenantDomain)`
- `verifyJSONLDVCIssuer(JsonObject vcJsonObject, String tenantDomain)`
- `verifyJSONLDVCIssuer(VerifiableCredential credential, String tenantDomain)`
  - Purpose: issuer trust + signature-level issuer verification entry points
  - Errors: `CredentialVerificationException`

- `verifyAllIssuerTrust(String vpToken, String presentationSubmissionJson, String tenantDomain)` *(deprecated)*
  - Purpose: legacy trust pre-check flow

- `verifySdJwtToken(String vpToken, String expectedNonce, String expectedAudience, String presentationDefinitionJson)`
  - Purpose: SD-JWT deep verification
  - Return: verified claims map
  - Errors: `CredentialVerificationException`

- `verifyClaimsAgainstDefinition(Map<String, Object> claims, String presentationDefinitionJson)`
  - Purpose: enforce PD constraints
  - Errors: `CredentialVerificationException`

- `verifyPresentation(String vpToken, String submissionJson, String presentationDefinitionId, int tenantId)`
  - Purpose: unified VP verification
  - Return: `VPVerificationResponseDTO`
  - Errors: `CredentialVerificationException` for unrecoverable failures

---

## 2.2 `StatusListService`
Purpose: contract for revocation checking.

Methods:
- `checkRevocationStatus(CredentialStatus)` → `RevocationCheckResult`, throws `RevocationCheckException`
- `checkStatusList2021(String url, int index, String purpose)` → result, throws
- `checkBitstringStatusList(String url, int index, String purpose)` → result, throws
- `fetchAndDecodeStatusList(String url)` → `byte[]`, throws
- `isBitSet(byte[] bitstring, int index)` → boolean
- `clearCache()`
- `isRevocationCheckEnabled()` → boolean

---

## 3) Service implementations

## 3.1 `VCVerificationServiceImpl`
Purpose: main orchestration class.

### Constructors
- `VCVerificationServiceImpl()`
- `VCVerificationServiceImpl(DIDResolverService)`
- `VCVerificationServiceImpl(DIDResolverService, StatusListService)`
- `VCVerificationServiceImpl(DIDResolverService, StatusListService, PresentationDefinitionService)`

Role: wire defaults or injected dependencies.

### Small assignment helpers
- `assignDIDResolverService(...)`
- `assignStatusListService(...)`
- `assignPresentationDefinitionService(...)`

Role: local helper methods used in constructors.

### VC verification API
- `verify(...)` (2 overloads)
  - Flow: validate input → parse VC → call `verifyCredentialInternal`
  - Returns: `VCVerificationResultDTO`
  - Errors: wraps unexpected errors as `CredentialVerificationException`

- `verifyCredential(VerifiableCredential)`
  - Delegates to `verifyCredentialInternal`

- `verifyCredentialInternal(VerifiableCredential, int vcIndex)` *(private core)*
  - Flow:
    1. expiry check (clock skew)
    2. signature check
    3. revocation check (optional soft-fail if check itself errors)
    4. build result DTO
  - Returns: `VCVerificationResultDTO`

### VP verification API
- `verifyPresentation(VerifiablePresentation presentation)`
  - Flow: iterate embedded VCs and verify each
  - Returns: list of per-VC result DTOs
  - Errors: throws for null/empty VP credential list

### Signature verification API
- `verifySignature(VerifiableCredential credential)`
  - Route by VC format:
    - JWT → `verifyJwtSignature`
    - SD-JWT → `verifySdJwtSignature`
    - JSON-LD → `verifyJsonLdSignature`

- `verifyJwtSignature(VerifiableCredential)` *(private)*
  - Input: parsed JWT VC
  - Return: boolean
  - Flow:
    - parse JWT header (`alg`,`kid`)
    - resolve issuer key (DID or URL JWKS)
    - verify signature using `SignatureVerifier` or `ExtendedJWKSValidator`
  - Errors: `CredentialVerificationException` on format, DID, JWKS failures

- `verifySdJwtSignature(VerifiableCredential)` *(private)*
  - Input: parsed SD-JWT VC
  - Return: boolean
  - Flow: split SD-JWT parts → verify issuer JWT as normal JWT

- `verifyJsonLdSignature(VerifiableCredential)` *(private)*
  - Input: JSON-LD VC with `proof`
  - Return: boolean
  - Flow: resolve verification method DID key → verify linked-data signature

### Status checks
- `isExpired(VerifiableCredential)`
- `isRevoked(VerifiableCredential)`
  - Uses `statusListService.checkRevocationStatus(...)`
  - Treats `SKIPPED`/`UNKNOWN` as not-revoked in caller context

### Parsing methods
- `parseCredential(String vcString, String contentType)`
  - Auto-detects format for generic/null content type
  - Routes to parse JWT / SD-JWT / JSON-LD

- `parseJwtCredential(String jwtString)` *(private)*
  - Parses JWT claims and VC claim sub-structure
  - Populates issuer, subject, dates, types, credentialSubject

- `parseSdJwtCredential(String sdJwtString)` *(private)*
  - Splits SD-JWT parts
  - Parses issuer JWT and merges disclosures

- `processDisclosures(VerifiableCredential)` *(private)*
  - Decodes disclosure arrays and injects revealed claims

- `parseJsonLdCredential(String jsonString)` *(private)*
  - Parses JSON-LD VC fields (`@context`, `type`, issuer, dates, subject, status, proof)

- `parseProof(JsonObject)` *(private)*
  - Converts proof JSON to `VerifiableCredential.Proof`

- `extractVcFields(VerifiableCredential, Map<String,Object>)` *(private)*
  - Applies `vc` claim data from JWT VC to model

- `parsePresentation(String vpToken)`
  - Auto-detects VP format and routes

- `parseJwtPresentation(String jwtString)` *(private)*
  - Parses JWT VP claims and embedded credentials

- `parseJsonLdPresentation(String jsonString)` *(private)*
  - Parses JSON-LD VP and embedded credentials

- `extractVpCredentials(VerifiablePresentation, Map<String,Object>)` *(private)*
  - Extracts embedded credentials from VP map

### Nonce/content-type helpers
- `verifyNonce(String vpToken, String expectedNonce)`
  - Parses VP and compares nonce value

- `isContentTypeSupported(String contentType)`
- `getSupportedContentTypes()`

### Issuer trust helpers
- `verifyJWTVCIssuer(...)` (2 overloads)
- `verifyJSONLDVCIssuer(...)` (2 overloads)
- `verifyAllIssuerTrust(...)` *(deprecated)*

Purpose: issuer trust + signature verification entry points.

### SD-JWT deep verification and PD checks
- `verifySdJwtToken(...)`
  - Main SD-JWT compliance path:
    - issuer JWT verification
    - time claim checks
    - disclosure hash checks (`_sd_alg` aware)
    - KB-JWT checks (`typ`,`iat`,`nonce`,`aud`,`sd_hash`,`cnf.jwk` key verification)
    - optional PD claim checks
  - Returns: verified claims map
  - Errors: `CredentialVerificationException` for any failed security check

- `verifyClaimsAgainstDefinition(...)`
  - Supports both:
    - standard PE `input_descriptors.constraints.fields.path`
    - simplified `requested_credentials/requested_claims`
  - Throws `CredentialVerificationException` when constraints fail

- `issuerHostMatches(...)` *(private)*
  - Hostname-based issuer comparison helper

- `hashDisclosure(...)`, `hashSd(...)` *(private)*
  - Hash helper wrappers

- `parseSdJwtParts(String)` *(private)*
  - Splits SD-JWT into issuer JWT / disclosures / KB-JWT

- `resolveJwksUri(String issuer)` *(private)*
  - Fetches issuer metadata and extracts `jwks_uri`

### Unified VP entry point
- `verifyPresentation(String vpToken, String submissionJson, String presentationDefinitionId, int tenantId)`
  - Orchestrates full flow and returns `VPVerificationResponseDTO`

- `verifySdJwtPresentation(...)` *(private)*
- `verifyJwtOrJsonLdPresentation(...)` *(private)*
- `extractClaimsFromPresentation(...)` *(private)*

Role: routing wrappers and normalized final extraction.

---

## 3.2 `StatusListServiceImpl`
Purpose: revocation status checker with cache and safe decoding.

### Public methods
- `checkRevocationStatus(CredentialStatus)`
  - Route by status type (`StatusList2021`, `BitstringStatusList`)
  - Return: `RevocationCheckResult`

- `checkStatusList2021(String url, int index, String purpose)`
  - Fetch + decode status list, inspect bit
  - Maps bit + purpose to `VALID`/`REVOKED`/`SUSPENDED`

- `checkBitstringStatusList(String url, int index, String purpose)`
  - Delegates to StatusList2021 logic

- `fetchAndDecodeStatusList(String url)`
  - Uses cache; if miss then fetches credential and decodes `encodedList`

- `isBitSet(byte[] bitstring, int index)`
  - Bit extraction helper (MSB-first)

- `clearCache()`
- `isRevocationCheckEnabled()`
- `setRevocationCheckEnabled(boolean)`

### Private helpers
- `isStatusList2021(String)`
- `isBitstringStatusList(String)`
- `checkStatusList2021FromCredentialStatus(...)`
- `checkBitstringStatusListFromCredentialStatus(...)`
- `fetchStatusListCredential(String url)`
  - Uses `HttpClientUtil.fetchContent(...)`
- `extractEncodedList(String credentialJson)`
- `decodeStatusList(String encodedList)`
  - Base64 + GZIP with decompression size limit

### Nested class
- `CachedStatusList`
  - Stores decoded bitstring + creation time + expiry check

### Error handling
- Primary exception: `RevocationCheckException`
- Converts network/parse/decode errors using static factories (`networkError`, `invalidStatusList`, `decodingError`)

---

## 4) Utility classes

## 4.1 `VerificationUtil`
Purpose: static helpers for parsing, hashing, normalization, extraction.

### Methods
- `removeCRLF(String)` → sanitizes line breaks
- `createHash(String)` / `createHash(String, String)` → Base64URL digest
- `resolveHashAlgorithm(String sdAlg)` → maps `_sd_alg` to JCA algorithm
- `hashDocument(String, String)` → raw hash bytes
- `normalizeContentType(String)`
- `parseDate(String)`
- `parseJsonElement(JsonElement)`
- `parseJwtPart(String)`
- `detectFormat(String vcString)`
- `extractFormatFromSubmission(String submissionJson)`
- `extractNonceAndAudienceFromVpToken(String vpToken, String detectedFormat)`
- `extractClaimsFromVpToken(String vpToken, String detectedFormat)`
- `flattenVpCredentialSubject(JsonObject vpData, Map<String,Object> target)`
- `extractHost(String value)`

### Errors
- Throws `CredentialVerificationException` for submission-format parsing failures
- Throws `NoSuchAlgorithmException` for unsupported hash algorithms

---

## 4.2 `SignatureVerifier`
Purpose: cryptographic verification utility for JWT and linked-data proofs.

### Methods
- `verifyJwtSignature(String jwt, PublicKey publicKey, String algorithm)`
  - Main JWT signature verification route
  - Uses Nimbus verifiers for RSA/EC, JCA fallback for other key types

- `verifyJwtSignatureWithJca(...)` *(private)*
- `verifyLinkedDataSignature(String canonicalizedDocument, PublicKey publicKey, String proofType, String proofValue)`

Private proof helpers:
- `decodeProofValue(...)`
- `verifyEd25519Signature(...)`
- `verifyJsonWebSignature(...)`
- `verifyJwsSigningInput(...)`
- `verifyEcdsaSecp256k1Signature(...)`
- `verifyGenericSignature(...)`

Algorithm/encoding helpers:
- `getJcaAlgorithm(String)`
- `extractAlgorithmFromHeader(String)`
- `convertJwtEcdsaToDer(...)`
- `compactToDer(...)`
- `trimLeadingZeros(...)`
- `base58Decode(String)`

### Errors
- Throws `CredentialVerificationException` with explicit crypto context

---

## 4.3 `HttpClientUtil`
Purpose: safe HTTP fetch utility for remote documents.

### Methods
- `fetchContent(String urlString, Map<String,String> headers)`
  - Validates scheme/host
  - SSRF-protects by resolving and rejecting local/private/link-local addresses
  - Disables redirects
  - Applies timeout and response-size cap

- `fetchJson(String urlString)`
  - Wrapper to parse JSON response

Private helpers:
- `openSafeConnection(String)`
- `untaint(String)`
- `validateIpAddress(String host)`

### Errors
- Throws `IOException` for invalid URL/protocol/SSRF/network/oversize payload

---

## 4.4 `VPSubmissionValidator`
Purpose: validates incoming wallet submission DTO and presentation_submission shape.

### Methods
- `validateSubmission(VPSubmissionDTO dto)`
- `validatePresentationSubmissionJson(JsonObject submissionJson)`

Private helpers:
- `validateErrorResponse(VPSubmissionDTO dto)`
- `isValidErrorCode(String errorCode)`
- `validatePresentationSubmissionJsonStructure(JsonObject submissionJson)`
- `isNonBlankStringField(JsonObject object, String fieldName)`
- `isValidJsonPath(String path)`

### Errors
- Throws `VPSubmissionValidationException` for schema/field format violations

---

## 4.5 `ExtendedJWKSValidator`
Purpose: validates JWT signatures using remote JWKS (not RSA-only, supports broader algorithms via Nimbus processing).

### Method
- `validateSignature(String jwtString, String jwksUri, String algorithm)`
  - Configures JWT processor, allowed JOSE type, remote JWK source, and algorithm selector
  - Processes JWT to verify signature and relevant JOSE/JWT checks

### Errors
- Throws `CredentialVerificationException` on parse/algorithm/JOSE/JWKS/network failures

---

## 5) DTO classes

> Note: DTO classes mostly contain constructors, accessors, validation helpers, builder helpers, and `toString()`.

## 5.1 `VPVerificationResponseDTO`
Purpose: unified VP verification response.

Factory methods:
- `success(Map<String,Object> verifiedClaims, String formatDetected)`
- `success(Map<String,Object>, String, String nonce, String audience)`
- `failure(String errorMessage, String formatDetected)`
- `failure(String errorMessage)`

Accessors:
- `isValid()`, `getVerifiedClaims()`, `getFormatDetected()`, `getErrorMessage()`, `getNonce()`, `getAudience()`

Error handling:
- No thrown errors in normal path; immutable/defensive map behavior.

## 5.2 `VCVerificationResultDTO`
Purpose: per-credential verification result.

Core constructors:
- success constructor `(vcIndex, status, credentialType, issuer)`
- failure constructor `(vcIndex, status, error)`
- copy constructor

Helpers:
- `getVerificationStatusEnum()`
- `isSuccess()`
- nested `Builder` with `issuer()`, `format()`, `expired()`, `error()`, `build()`

## 5.3 `VPSubmissionDTO`
Purpose: request DTO from wallet.

Methods:
- field getters/setters
- `hasError()`, `hasVpToken()`, `isValid()`

## 5.4 `PresentationSubmissionDTO`
Purpose: DTO for `presentation_submission`.

Methods:
- `getId()/setId()`, `getDefinitionId()/setDefinitionId()`
- `getDescriptorMap()`
- `isValid()`

## 5.5 `DescriptorMapDTO`
Purpose: entry in descriptor map.

Methods:
- `getId()/setId()`, `getFormat()/setFormat()`, `getPath()/setPath()`
- `isValid()`

## 5.6 `PathNestedDTO`
Purpose: nested descriptor path details.

Methods:
- `getFormat()/setFormat()`, `getPath()/setPath()`

---

## 6) Model classes

## 6.1 `VerifiableCredential`
Purpose: normalized VC model supporting JSON-LD/JWT/SD-JWT.

Contains:
- enum `Format` with `fromValue()`
- nested `CredentialStatus`
- nested `Proof`
- rich getters/setters with defensive copying

Behavior methods:
- `getPrimaryType()`
- `hasCredentialStatus()`
- format checks: `isJsonLd()`, `isJwt()`, `isSdJwt()`
- `isExpired()`
- `getClaim(String)`

Nested class behaviors:
- `CredentialStatus.isStatusList2021()`
- `Proof.isEd25519()`, `Proof.isJsonWebSignature()`

## 6.2 `VerifiablePresentation`
Purpose: normalized VP model supporting JWT and JSON-LD.

Contains:
- enum `Format` with `fromValue()`
- VC list and proof
- JWT field support and metadata

Behavior methods:
- `addVerifiableCredential(...)`
- `getCredentialCount()`
- `isJsonLd()`, `isJwt()`
- `getJwtNonce()`

## 6.3 `RevocationCheckResult`
Purpose: revocation decision model.

Contains:
- enum `Status` (`VALID`,`REVOKED`,`SUSPENDED`,`UNKNOWN`,`SKIPPED`)
- static factories: `valid()`, `unknown(...)`, `skipped(...)`
- helper booleans: `isValid()`, `isRevoked()`, `isSuspended()`, `isRevokedOrSuspended()`
- nested builder (`status()`, `statusPurpose()`, `statusListCredentialUrl()`, `statusIndex()`, `message()`, `build()`)

## 6.4 `VCVerificationStatus` (enum)
Purpose: VC verification status vocabulary.

Methods:
- `getValue()`
- `fromValue(String)`
- `isSuccess()`
- `isFailure()`

---

## 7) Exception classes

## 7.1 `CredentialVerificationException`
Purpose: domain exception for VC/VP verification failures.

Constructors:
- message
- status + message
- status + vcIndex + message
- message + cause

Methods:
- `getVerificationStatus()`
- `getVcIndex()`

## 7.2 `RevocationCheckException`
Purpose: revocation-check-specific failure exception.

Constructors:
- message
- message + cause
- message + url + index + cause

Static factories:
- `networkError(url, cause)`
- `invalidStatusList(url, reason)`
- `decodingError(cause)`

Mutator:
- `setStatusListUrl(String)`

## 7.3 `VPSubmissionValidationException`
Purpose: submission schema/field validation exception.

Constructor:
- message

---

## 8) Error handling strategy (cross-component summary)

- Boundary validation failures:
  - `VPSubmissionValidationException`

- Verification failures (format/signature/claims/time etc.):
  - `CredentialVerificationException`

- Revocation-specific failures:
  - `RevocationCheckException` (wrapped or translated when needed)

- Soft-fail behavior:
  - Revocation service failures do not always invalidate VC; policy is tolerant in `verifyCredentialInternal()`.

- Defensive behavior:
  - content type normalization
  - safe parsing with wrapped domain exceptions
  - constant-time comparisons for sensitive fields
  - network/size/SSRF protections

---

## 9) Practical review explanation pattern (for any method)

Use this 5-point format in review:
1. **Purpose** — why this method exists
2. **Input contract** — what it accepts and validates
3. **Output contract** — what it returns and in what shape
4. **Failure model** — what exceptions or fallback behavior it uses
5. **Flow placement** — where it is called in the end-to-end pipeline

This format makes method-level defense clear and consistent.
