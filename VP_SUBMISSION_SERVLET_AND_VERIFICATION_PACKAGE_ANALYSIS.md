# VP Submission Processing: Servlet vs Verification Package

## Scope
This note explains:
1. What `VPSubmissionServlet` does when a wallet submits a VP.
2. What the `presentation.verification` package does.
3. Whether there are duplicated responsibilities.

---

## 1) What `VPSubmissionServlet` does

File: `components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/.../VPSubmissionServlet.java`

`VPSubmissionServlet` is the wallet callback ingress endpoint (`/openid4vp/v1/response`) for direct-post responses.

### Main processing in `doPost(...)`

1. **Parse inbound submission**
   - Supports `application/x-www-form-urlencoded` and JSON body.
   - Reads `vp_token`, `presentation_submission`, `state`, and optional `error` fields.

2. **Validate request shape**
   - Calls `VPSubmissionValidator.validateSubmission(...)`.
   - Rejects malformed submissions with HTTP 400.

3. **Per-credential issuer/signature pre-check**
   - Calls `verifyAllCredentialIssuers(vpToken, tenantDomain)`.
   - Parses VP token (JWT or JSON-LD) and extracts embedded VCs.
   - For each VC:
     - JWT VC -> `VCVerificationService.verifyJWTVCIssuer(...)`
     - JSON-LD VC -> `VCVerificationService.verifyJSONLDVCIssuer(...)`
   - Rejects failures with HTTP 403 (`untrusted_issuer`).

4. **Build in-memory submission object**
   - Creates `VPSubmission` with `PENDING` verification status.
   - Stores it in cache (`WalletDataCache`) using `state` as request key.

5. **Notify async listeners**
   - Notifies status listeners/pollers through `StatusNotificationService` / `VPStatusListenerCache`.

6. **Return response to wallet**
   - Success response JSON: `{ "status": "received", "submission_id": ... }`.
   - On failure, OAuth-style error JSON.

### Important characteristic
`VPSubmissionServlet` is mainly an **ingestion + validation + early gatekeeping** layer. It does not complete the full authentication decision by itself.

---

## 2) What the verification package does

Folder: `components/org.wso2.carbon.identity.openid4vc.presentation.verification`

Primary service: `VCVerificationService` / `VCVerificationServiceImpl`.

### Core responsibilities

1. **Credential verification primitives**
   - Parse VC/VP payloads.
   - Verify signatures (JWT, JSON-LD, SD-JWT issuer JWT).
   - Check expiration.
   - Check revocation (when credential status exists).

2. **Issuer-specific helper checks**
   - `verifyJWTVCIssuer(...)`
   - `verifyJSONLDVCIssuer(...)`

3. **Unified VP verification API**
   - `verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`
   - Detects format from `presentation_submission` descriptor map.
   - Routes verification by format (SD-JWT vs JWT/JSON-LD VP).
   - Extracts claims.
   - Enforces Presentation Definition constraints (if provided).
   - Extracts nonce and audience and returns them for caller-side anti-replay checks.

4. **Submission validation utility**
   - `VPSubmissionValidator` validates request-level structure:
     - required fields (`state`, `vp_token` when applicable),
     - VP token format sanity,
     - `presentation_submission` schema basics.

### Important characteristic
The verification package is the **cryptographic and semantic verification engine** used by higher-level flows (Authenticator and related components).

---

## 3) Are there duplicate functionalities?

## Yes — there is partial overlap.

### Duplicate / overlapping areas

1. **VP parsing and VC extraction logic exists in two places**
   - Servlet method `verifyAllCredentialIssuers(...)` manually parses VP token and loops over embedded credentials.
   - Verification service also parses VPs (`parsePresentation(...)`) and iterates credentials (`verifyVPToken(...)`, `verifyPresentation(...)`).

2. **Signature/credential trust checks are triggered more than once in end-to-end flow**
   - First in servlet pre-check via `verifyJWTVCIssuer(...)` / `verifyJSONLDVCIssuer(...)`.
   - Again in full verification path (`verifyPresentation(...)` -> per-credential verification).

3. **Submission validation entry is in servlet, but logic lives in verification package**
   - This is acceptable layering, but contributes to split ownership of VP request handling.

### Not duplicate (clearly distinct)

- Servlet-only: HTTP transport handling, cache persistence, async listener notification, wallet callback response writing.
- Verification-only: cryptographic verification internals, revocation, PD constraint checks, nonce/audience extraction.

---

## 4) Practical conclusion

Current architecture has a **two-phase verification pattern**:
1. **Servlet pre-check phase** (early rejection before caching/continuation).
2. **Authenticator verification phase** (authoritative full verification).

This is workable but introduces duplicated VP parsing and repeated verification work.

If simplification is desired, centralizing VP/VC parsing and issuer checks behind `VCVerificationService.verifyPresentation(...)` (or a dedicated precheck API in the verification package) would reduce duplication and drift risk.
