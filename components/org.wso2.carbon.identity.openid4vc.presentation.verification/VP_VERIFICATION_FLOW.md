# VP Verification Flow

This document summarizes how VP verification is executed in the verification component.

## Entry Point

- `VCVerificationServiceImpl.verifyPresentation(String vpToken, String submissionJson, String presentationDefinitionId, int tenantId)`

## End-to-End Flow

1. **Input validation**
   - Rejects empty `vpToken` or `submissionJson`.

2. **Format detection**
   - Reads `presentation_submission.descriptor_map[0].format` using `VerificationUtil.extractFormatFromSubmission(...)`.
   - Normalizes aliases to `vc+sd-jwt` where applicable.

3. **Presentation Definition resolution (optional)**
   - If `presentationDefinitionId` is present and `PresentationDefinitionService` is available, resolves PD using:
     - `presentationDefinitionService.getPresentationDefinitionById(...)`
     - `PresentationDefinitionUtil.buildDefinitionJson(...)`

4. **Nonce/audience extraction for replay protection**
   - Extracts nonce and audience using `VerificationUtil.extractNonceAndAudienceFromVpToken(...)`.
   - Values are returned in `VPVerificationResponseDTO`.
   - **Important:** comparison to expected session values is performed by caller (Authenticator), not by this component.

5. **Branch by detected format**

   ### A) SD-JWT path (`vc+sd-jwt`)
   - `verifySdJwtPresentation(...)` → `verifySdJwtToken(...)`
   - Verification sequence:
     1. Parse SD-JWT parts (`issuer-jwt~disclosures~kb-jwt`).
     2. Verify issuer JWT signature (`verifySignature(...)` → `verifyJwtSignature(...)`).
     3. Validate `exp`/`nbf` of issuer JWT.
     4. Verify disclosures against `_sd` digests.
     5. If present, verify KB-JWT:
        - `nonce` and `aud` (if expected values are provided)
        - `sd_hash`
        - holder key signature using `cnf.jwk`.
     6. Enforce PD claim constraints via `verifyClaimsAgainstDefinition(...)` when PD JSON is provided.

   ### B) JWT-VP / JSON-LD VP path
   - `verifyJwtOrJsonLdPresentation(...)`
   - Verification sequence:
     1. `verifyVPToken(...)` parses presentation and verifies each embedded VC.
     2. Claims extraction via `VerificationUtil.extractClaimsFromVpToken(...)`.
     3. PD constraint enforcement via `verifyClaimsAgainstDefinition(...)` when PD JSON is provided.

6. **Result building**
   - Returns `VPVerificationResponseDTO.success(...)` with:
     - verification status
     - detected format
     - verified claims
     - extracted nonce
     - extracted audience
   - On failure, returns `VPVerificationResponseDTO.failure(...)`.

## Credential-Level Verification Flow (used by VP path)

For each VC (`verifyCredentialInternal(...)`):

1. Expiration check (`isExpired(...)`)
2. Signature verification (`verifySignature(...)`)
3. Revocation check (`isRevoked(...)`) if `credentialStatus` is present
4. Build per-credential result (`VCVerificationResultDTO`)
