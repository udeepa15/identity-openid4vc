# OID4VP Verification Component — Reviewer Guide

This guide gives reviewers a fast, structured understanding of OpenID for Verifiable Presentations (OID4VP) and how this component implements verification.

---

## 1) OID4VP in one page

OID4VP is the protocol flow where:
1. A Verifier requests proofs/credentials from a Wallet.
2. The Wallet returns a `vp_token` and `presentation_submission`.
3. The Verifier validates:
   - token format and structure,
   - credential signatures,
   - credential validity (expiry/revocation),
   - claim constraints from Presentation Definition,
   - replay-protection context (`nonce`, `audience`).

This component is the verification engine for step 3.

---

## 2) What this component is responsible for

- Validate incoming VP submission payload shape.
- Detect VP format from `presentation_submission` descriptor map.
- Verify VC/VP cryptographic integrity across formats:
  - JWT VC / JWT VP
  - JSON-LD VC / JSON-LD VP
  - SD-JWT VC presentation
- Check VC expiry and revocation status.
- Enforce Presentation Definition claim constraints.
- Extract `nonce` and `audience` from VP for caller-side replay checks.

Not responsible for session-state replay comparison itself (caller layer does that).

---

## 3) Core classes and roles

## 3.1 Main orchestration
- `VCVerificationService` (interface)
- `VCVerificationServiceImpl` (implementation)

This is the primary entry and routing layer.

## 3.2 Revocation
- `StatusListService` (interface)
- `StatusListServiceImpl` (implementation)

Handles StatusList2021 / BitstringStatusList fetch, decode, and bit checks.

## 3.3 Validation + utility
<<<<<<< Updated upstream
- `VPSubmissionValidator`
=======
>>>>>>> Stashed changes
- `VerificationUtil`
- `SignatureVerifier`
- `HttpClientUtil`
- `ExtendedJWKSValidator`

These support schema checks, parsing, hashing, signature verification, and safe HTTP/JWKS retrieval.

## 3.4 Data and results
- Models: `VerifiableCredential`, `VerifiablePresentation`, `RevocationCheckResult`, `VCVerificationStatus`
- DTOs: `VPVerificationResponseDTO`, `VCVerificationResultDTO`, submission DTOs

---

## 4) End-to-end verification flow

## Step A — Submission validation
<<<<<<< Updated upstream
`VPSubmissionValidator.validateSubmission(...)`

Checks mandatory fields (`state`, `vp_token`, `presentation_submission`) and descriptor map structure.
=======
Handled within `VCVerificationServiceImpl.verifyPresentation()` via minimal non-blank checks and format extraction.
>>>>>>> Stashed changes

## Step B — Unified VP verification
`VCVerificationServiceImpl.verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`

Flow:
1. Detect format from `presentation_submission.descriptor_map[0].format`.
2. Optionally resolve Presentation Definition by ID.
3. Extract nonce/audience from VP token.
4. Route:
   - SD-JWT → SD-specific verification
   - JWT/JSON-LD VP → parse VP and verify embedded VCs
5. Return unified `VPVerificationResponseDTO`.

## Step C — Per-VC verification pipeline
For each credential:
1. Expiration check
2. Signature check
3. Revocation check (if `credentialStatus` exists)
4. Build per-VC result DTO

---

## 5) Format-specific behavior

## 5.1 JWT VC / JWT VP
- Parses compact JWT.
- Resolves issuer key using DID (`did:*`) or issuer metadata + JWKS URI.
- Validates signature via `SignatureVerifier` / `ExtendedJWKSValidator`.

## 5.2 JSON-LD VC / VP
- Parses proof and verification method.
- Resolves DID public key.
- Verifies linked-data signature.

## 5.3 SD-JWT
- Splits token into issuer JWT + disclosures + optional KB-JWT.
- Verifies issuer JWT signature and time claims.
- Verifies disclosure hashes against `_sd` with `_sd_alg` handling.
- Verifies KB-JWT (`typ`, `iat`, `sd_hash`, holder key from `cnf.jwk`).
- Optionally enforces PD claim constraints.

---

## 6) Revocation implementation details

Revocation uses VC `credentialStatus` fields:
- `statusListCredential`
- `statusListIndex`
- `statusPurpose`

Implementation path:
1. Fetch status list credential over HTTP(S).
2. Parse `encodedList`.
3. Base64 decode + GZIP decompress.
4. Check bit at index.
5. Map to `VALID`, `REVOKED`, or `SUSPENDED`.

Resilience controls:
- in-memory cache with TTL,
- decoding size limit,
- strict URL scheme validation,
- SSRF protections in HTTP utility.

---

## 7) Error handling model

<<<<<<< Updated upstream
- Submission schema failures → `VPSubmissionValidationException`
=======
- Submission validation failures → `CredentialVerificationException`
>>>>>>> Stashed changes
- Verification failures (format/signature/claims) → `CredentialVerificationException`
- Revocation fetch/decode failures → `RevocationCheckException`

Design choice:
- signature/format failures are hard failures,
- revocation-check transport/parse issues are handled with tolerant behavior in VC flow when applicable.

---

## 8) Security posture

Key controls implemented:
- clock-skew tolerance on time claims,
- SD-JWT hash algorithm strict mapping,
- key-binding freshness checks (`iat`),
- constant-time comparison for sensitive values,
- safe remote fetch constraints (SSRF guards, redirects disabled, payload size limits),
- bounded decompression to mitigate zip-bomb style abuse.

---

## 9) How reviewers should read the code (recommended order)

1. `service/VCVerificationService.java`
2. `service/impl/VCVerificationServiceImpl.java`
3. `service/impl/StatusListServiceImpl.java`
4. `util/VerificationUtil.java`
5. `util/SignatureVerifier.java`
6. `util/HttpClientUtil.java`
7. `jwt/ExtendedJWKSValidator.java`
8. DTO/model classes

---

## 10) Test coverage entry points

Primary tests to inspect:
- `VCVerificationServiceTest`
- `VerificationUtilAndStatusListCoverageTest`
<<<<<<< Updated upstream
- `VPSubmissionValidatorTest`
=======
>>>>>>> Stashed changes
- `SignatureVerifierTest`
- `HttpClientAndJWKSValidatorTest`
- `DtoModelCoverageTest`

These cover parsing, routing, utility behavior, error paths, and model/DTO contracts.

---

## 11) Review checklist (quick)

- Is format detection tied correctly to `presentation_submission`?
- Are signature checks mandatory for every credential format?
- Are SD-JWT disclosure and KB-JWT checks complete?
- Is revocation check correctly sourced from `credentialStatus`?
- Are remote fetch protections and limits enforced?
- Are failure semantics (hard vs tolerant) consistent with design?

---

## 12) Summary

This component is a format-aware, security-focused OID4VP verification engine. It centralizes VP verification routing, credential validation, revocation checks, and claim-constraint enforcement while returning normalized results for upper layers to make final authentication and replay decisions.
