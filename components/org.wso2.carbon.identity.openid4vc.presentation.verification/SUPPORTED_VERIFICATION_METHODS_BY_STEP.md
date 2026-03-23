# Supported Verification Methods by Step

This file lists the verification methods used at each stage in the verification component.

## 1) Format and Routing

| Step | Method(s) | Supported values / behavior |
|---|---|---|
| Detect presentation format from `presentation_submission` | `VerificationUtil.extractFormatFromSubmission(...)` | Uses `descriptor_map[0].format`; normalizes aliases to `vc+sd-jwt`. |
| Route flow by format | `VCVerificationServiceImpl.verifyPresentation(...)` | `vc+sd-jwt` → SD-JWT path; otherwise JWT-VP / JSON-LD VP path. |

## 2) VP Token Parsing

| Step | Method(s) | Supported formats |
|---|---|---|
| Parse VP token | `parsePresentation(...)` | JWT-VP and JSON-LD VP. |
| Parse JWT VP | `parseJwtPresentation(...)` | JWT compact (`header.payload.signature`). |
| Parse JSON-LD VP | `parseJsonLdPresentation(...)` | JSON object VP payload. |

## 3) VC Parsing

| Step | Method(s) | Supported content types / formats |
|---|---|---|
| Detect credential format | `VerificationUtil.detectFormat(...)` | SD-JWT (`~`), JWT (`3 parts`), JSON-LD (`{...}`). |
| Parse VC | `parseCredential(...)` | `application/vc+ld+json`, `application/jwt`, `application/vc+jwt`, `application/vc+sd-jwt`, `application/json` (auto-detect). |
| Parse JWT VC | `parseJwtCredential(...)` | JWT VC claims extraction (`iss`, `sub`, `exp`, `iat`, `vc`). |
| Parse SD-JWT VC | `parseSdJwtCredential(...)` + `processDisclosures(...)` | Issuer JWT + disclosures (+ optional KB-JWT). |
| Parse JSON-LD VC | `parseJsonLdCredential(...)` | JSON-LD fields (`issuer`, `credentialSubject`, `proof`, etc.). |

## 4) Signature Verification

| Credential type | Method chain | Supported verification methods |
|---|---|---|
| JWT VC / issuer JWT of SD-JWT | `verifySignature(...)` → `verifyJwtSignature(...)` | DID-based public key resolution or JWKS URI resolution. |
| RSA JWT signatures | `SignatureVerifier.verifyJwtSignature(...)` | Nimbus `RSASSAVerifier`. |
| EC JWT signatures | `SignatureVerifier.verifyJwtSignature(...)` | Nimbus `ECDSAVerifier`. |
| EdDSA / other JWT key types | `SignatureVerifier.verifyJwtSignatureWithJca(...)` | JCA fallback (`Signature` API), with ECDSA DER conversion when needed. |
| JWKS-based verification | `ExtendedJWKSValidator.validateSignature(...)` | Accepts expected alg (for example `RS256`, `ES256`, `EdDSA`), typ `JWT` and `vc+sd-jwt` (or missing typ). |
| JSON-LD proofs | `verifyJsonLdSignature(...)` → `SignatureVerifier.verifyLinkedDataSignature(...)` | `Ed25519Signature*`, `JsonWebSignature*`, `EcdsaSecp256k1*`, generic fallback. |

## 5) SD-JWT Specific Validation

| Step | Method(s) | Supported behavior |
|---|---|---|
| Disclosure digest check | `verifySdJwtToken(...)` + `hashDisclosure(...)` | SHA-256 base64url digest matching against `_sd`. |
| Holder binding | `verifySdJwtToken(...)` | Validates `nonce`, `aud`, and `sd_hash` when KB-JWT exists. |
| KB-JWT signature | `verifySdJwtToken(...)` | Verifies signature using holder public key from `cnf.jwk`. |

## 6) Revocation Verification

| Step | Method(s) | Supported mechanisms |
|---|---|---|
| Revocation decision | `isRevoked(...)` → `StatusListService.checkRevocationStatus(...)` | Only runs when VC has `credentialStatus`. |
| Status list types | `StatusListServiceImpl` | `StatusList2021Entry/StatusList2021`, `BitstringStatusListEntry/BitstringStatusList`. |
| Decoding and bit checks | `fetchAndDecodeStatusList(...)`, `isBitSet(...)` | Base64 + GZIP decoded bitstring with status index checks. |

## 7) Presentation Definition Constraint Verification

| Step | Method(s) | Supported behavior |
|---|---|---|
| Enforce PD constraints | `verifyClaimsAgainstDefinition(...)` | Supports both `input_descriptors` and `requested_credentials` structures. |
| Field path checks | `JsonPath.read(...)` | Validates required claim paths. |
| Trusted issuer host check | `issuerHostMatches(...)` | Compares issuer by hostname (case-insensitive). |

## 8) Replay-Related Data Handling

| Step | Method(s) | Notes |
|---|---|---|
| Extract nonce/audience | `VerificationUtil.extractNonceAndAudienceFromVpToken(...)` | Extracts from KB-JWT (SD-JWT), JWT-VP claims, or JSON-LD proof fields. |
| Compare expected nonce/audience | Caller responsibility | Done by Authenticator layer, not by verification component entrypoint. |

## 9) Supported Algorithm Types

### 9.1 JWT / JWS algorithms supported by the verification component

The JWT verification utility supports the following `alg` values:

- `RS256`
- `RS384`
- `RS512`
- `ES256`
- `ES384`
- `ES512`
- `ES256K`
- `EdDSA`
- `PS256`
- `PS384`
- `PS512`

These are mapped in `SignatureVerifier.getJcaAlgorithm(...)` and used by the JCA fallback path.

### 9.2 Algorithms used in current Presentation Definition format generation

From the current Presentation Definition builder (`PresentationDefinitionUtil.buildInputDescriptorFromRequestedCredential(...)`):

- `jwt_vp_json.alg`: `RS256`, `ES256`, `ES384`
- `vc+sd-jwt.alg`: `RS256`, `ES256`
- `dc+sd-jwt.alg`: `RS256`, `ES256`
- `vc+sd-jwt.sd-jwt_alg_values`: `RS256`, `ES256`
- `vc+sd-jwt.kb-jwt_alg_values`: `RS256`, `ES256`
- `dc+sd-jwt.sd-jwt_alg_values`: `RS256`, `ES256`
- `dc+sd-jwt.kb-jwt_alg_values`: `RS256`, `ES256`

### 9.3 Linked Data proof signature types supported

For JSON-LD credential proof verification (`SignatureVerifier.verifyLinkedDataSignature(...)`), the component handles:

- `Ed25519Signature*` (EdDSA verification path)
- `JsonWebSignature*` (detached JWS path)
- `EcdsaSecp256k1*`
- Other proof types via generic fallback verification
