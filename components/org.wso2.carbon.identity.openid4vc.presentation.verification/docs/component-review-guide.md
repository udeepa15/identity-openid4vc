# OpenID4VP Presentation Verification Component — End-to-End Review Guide

## 1) What this component does

This module is the **verification engine** for OpenID4VP submissions.

It validates:
- VP request payload shape (`state`, `vp_token`, `presentation_submission`)
- VP format and routing (`vc+sd-jwt`, `jwt_vp`, `jwt_vp_json`, `ldp_vp`)
- VC cryptographic signatures (JWT / SD-JWT / JSON-LD)
- VC lifecycle checks (expiration, revocation)
- Presentation Definition claim constraints
- Nonce/Audience extraction for replay protection (caller validates values)

---

## 2) Where to start reading in code

### Main service and flow
1. `service/VCVerificationService.java` (contract)
2. `service/impl/VCVerificationServiceImpl.java` (all runtime orchestration)

### Validation + parsing helpers
3. `util/VPSubmissionValidator.java`
4. `util/VerificationUtil.java`
5. `util/SignatureVerifier.java`
6. `jwt/ExtendedJWKSValidator.java`

### Revocation
7. `service/StatusListService.java`
8. `service/impl/StatusListServiceImpl.java`

### Data models / DTOs
9. `model/VerifiableCredential.java`
10. `model/VerifiablePresentation.java`
11. `dto/VPVerificationResponseDTO.java`
12. `dto/VCVerificationResultDTO.java`

---

## 3) High-level architecture

### Core dependencies in `VCVerificationServiceImpl`
- `DIDResolverService` → resolve DID public keys
- `SignatureVerifier` → JWT + linked-data signature verification
- `StatusListService` → revocation checks (StatusList2021 / BitstringStatusList)
- `ExtendedJWKSValidator` → issuer URL + JWKS based verification
- optional `PresentationDefinitionService` → resolve PD by id for constraints

### Responsibility split
- **Service layer** decides flow and policy.
- **Util layer** does parsing, hashing, normalization, extraction.
- **Status service** does revocation fetch/decode/cache.
- **DTO/model layer** carries verification result and claims.

---

## 4) End-to-end runtime flow (what to explain in review)

## Step A — Wallet submission shape validation
`VPSubmissionValidator.validateSubmission()`

Checks:
- `state` is mandatory
- error response path is allowed and validated
- success path requires `vp_token` + `presentation_submission`
- `presentation_submission` must include:
  - `id`
  - `definition_id`
  - non-empty `descriptor_map`
  - each descriptor needs `id`, `format`, `path`

Why important: hard-fails malformed submissions early before cryptographic work.

---

## Step B — Unified VP verification entry point
`VCVerificationServiceImpl.verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`

Pipeline:
1. Read format from `presentation_submission.descriptor_map[0].format`
2. Optionally resolve Presentation Definition JSON by ID
3. Extract nonce + audience from VP token (for caller-side replay check)
4. Route by format:
   - SD-JWT path → `verifySdJwtPresentation()`
   - JWT/JSON-LD path → `verifyJwtOrJsonLdPresentation()`
5. Return `VPVerificationResponseDTO` with:
   - valid / invalid
   - verified claims
   - detected format
   - nonce
   - audience
   - error (if any)

---

## Step C1 — SD-JWT verification details
`verifySdJwtToken()`

Detailed checks:
1. Parse SD-JWT into:
   - issuer JWT
   - disclosures[]
   - optional key-binding JWT
2. Verify issuer JWT signature (`verifySignature()`)
3. Validate issuer JWT time claims (`exp`, `nbf`) with clock skew tolerance
4. Verify disclosures:
   - respect `_sd_alg` (`sha-256` default)
   - hash disclosures
   - match against `_sd` digests in issuer JWT
   - reject unmatched disclosures
5. Verify key-binding JWT (if present):
   - `typ = kb+jwt`
   - `iat` exists and is fresh
   - nonce/audience constant-time comparison when expected values provided
   - `sd_hash` correctness
   - signature against `cnf.jwk` public key (EC/RSA/OKP supported)
6. Optionally enforce PD constraints via JsonPath

Result: returns verified claim map.

---

## Step C2 — JWT VP / JSON-LD VP path
`verifyJwtOrJsonLdPresentation()`

1. Parse VP once (`parsePresentation()`)
2. Verify each embedded VC (`verifyPresentation(parsedVp)`)
3. Extract claims from parsed VP (`extractClaimsFromPresentation()`)
4. Apply PD constraints if present

Important design note: avoids repeated parse cycles for performance and consistency.

---

## Step D — VC-level verification pipeline
`verifyCredentialInternal()` for each VC:

1. Expiration check (with skew)
2. Signature verification
   - JWT VC: DID or issuer URL + JWKS
   - SD-JWT VC: verifies issuer JWT signature
   - JSON-LD VC: linked-data proof verification
3. Revocation check (if `credentialStatus` exists)
   - non-fatal behavior on revocation service errors (verification can continue)
4. Build `VCVerificationResultDTO`

---

## 5) Revocation flow (Status List)

`StatusListServiceImpl.checkRevocationStatus()`:
- supports `StatusList2021Entry` and `BitstringStatusListEntry`
- fetches `statusListCredential` over HTTP(S)
- extracts `encodedList`
- Base64 decode + GZIP decompress
- checks bit at `statusListIndex`
- maps status by `statusPurpose` (`revocation` / `suspension`)

Security/robustness controls:
- cache with TTL (5 min)
- decompressed size cap (2 MB)
- strict URL scheme validation
- SSRF IP validation in `HttpClientUtil`

---

## 6) Security controls to highlight in review

- Clock skew tolerance for time claims
- KB-JWT freshness (`iat` max age) to reduce replay risk
- Constant-time byte comparison for nonce/audience/hash checks
- `_sd_alg`-aware hash verification for SD-JWT
- SSRF protections in outbound HTTP utility
- Response-size limits to avoid memory abuse
- GZIP decompression size cap
- Multiple key type support for holder binding (`EC`, `RSA`, `OKP`)

---

## 7) What this component deliberately does NOT do

- It **extracts** nonce/audience and returns them.
- It does **not** compare them with session-bound expected values in unified VP path.
- That replay validation is caller responsibility (Authenticator layer).

This is an intentional separation of concerns.

---

## 8) Test coverage map (quick talking points)

- `service/impl/VCVerificationServiceTest.java`
  - parse JWT / SD-JWT / JSON-LD
  - nonce checks
  - content type support
  - issuer trust pre-check behavior
- `VerificationUtilAndStatusListCoverageTest.java`
  - util hashing/format/date/claim extraction
  - status list branching and decode paths
  - exception constructors/factories
- `util/VPSubmissionValidatorTest.java`
  - strict submission schema validation cases
- `util/SignatureVerifierTest.java`
  - algorithm mapping / helper behavior / error handling
- `util/HttpClientAndJWKSValidatorTest.java`
  - URL handling and validator failure paths
- `DtoModelCoverageTest.java`
  - DTO/model semantics and defensive copying

---

## 9) Code review walkthrough script (you can follow this exactly)

1. **Start with purpose**
   - “This module verifies VP submissions across SD-JWT, JWT-VP, and JSON-LD VP, then returns normalized claims and metadata.”

2. **Show the one entry point**
   - `verifyPresentation(...)` in `VCVerificationServiceImpl`
   - explain format detection and route split.

3. **Explain format-specific verification**
   - SD-JWT path: digest + disclosure + KB-JWT + holder binding.
   - JWT/JSON-LD path: parse once + per-VC verify.

4. **Go one layer deeper**
   - `verifyCredentialInternal()` → expiry, signature, revocation.

5. **Security section**
   - SSRF controls, replay-related checks, algorithm handling, limits.

6. **Boundary responsibility**
   - replay comparison happens in caller, not here.

7. **Close with test evidence**
   - mention the 6 focused test classes and what they protect.

---

## 10) Expected reviewer questions + crisp answers

### Q: Why detect format from `presentation_submission` instead of token only?
A: It follows PE descriptor mapping and avoids ambiguous token-only inference.

### Q: Why not enforce nonce/audience comparison inside unified verify method?
A: Component is stateless and verification-focused; session-bound replay checks belong to caller context.

### Q: What if revocation endpoint fails?
A: Revocation errors are handled gracefully; VC verification does not hard-fail by default on revocation network errors.

### Q: How are SD-JWT disclosures protected from tampering?
A: Disclosure hashes are recomputed using `_sd_alg` and matched to `_sd`; unmatched disclosures are rejected.

### Q: How is SSRF mitigated in revocation/JWKS fetching?
A: Protocol validation, host/IP checks for local/private ranges, redirect disabled, and response size limits.

---

## 11) If you have 2 minutes only (ultra-short summary)

- One entry point routes by VP format.
- SD-JWT path does issuer JWT + disclosure hash + key-binding checks.
- JWT/JSON-LD path parses VP and verifies each embedded VC.
- VC check order: expiry → signature → revocation.
- Returns normalized claims + format + nonce + audience in response DTO.
- Security hardening includes replay-related data extraction, SSRF controls, and strict parsing/limits.

---

## 12) Suggested pre-review checklist

- Build already passes: `mvn clean install`
- Reconfirm component tests pass
- Keep `VCVerificationServiceImpl` flow open during call
- Keep `VPVerificationResponseDTO` open to explain contract
- Keep `StatusListServiceImpl` open for revocation/security discussion

Good luck — if you follow this flow, you can explain the component from top to bottom clearly.
