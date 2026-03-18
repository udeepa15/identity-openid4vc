# OpenID4VP Authenticator Change Plan

## Objective
Update `OpenID4VPAuthenticator` to support optional subject resolution while preserving secure VC verification behavior.

## Target Scenarios
1. **No claims in Presentation Definition, no claim mapping, no subject claim**  
   - Validate VC cryptographically and by issuer.
   - Authenticate user without requiring claim extraction.

2. **Claims exist in Presentation Definition, no claim mapping, no subject claim**  
   - Validate VC cryptographically and by issuer.
   - Ensure requested claims are present via verification flow.
   - Authenticate without mapping attributes and without subject claim enforcement.

3. **Claims exist in Presentation Definition, claim mapping exists, no subject claim**  
   - Validate VC cryptographically and by issuer.
   - Ensure requested claims are present.
   - Map claims to local attributes.
   - Authenticate without subject claim enforcement.

4. **Claims exist in Presentation Definition, claim mapping exists, subject claim exists**  
   - Validate VC cryptographically and by issuer.
   - Ensure requested claims are present.
   - Map claims to local attributes.
   - Resolve subject from configured external `userIdClaim` and set authenticated subject.

## Implementation Plan

### Phase 1: Subject Resolution Policy
- Keep `userIdClaim` interpretation as **external/remote IdP claim**.
- Resolve subject claim name via IDP claim mappings (`remoteClaim` first, local fallback for backward compatibility).
- Make subject extraction conditional:
  - If subject claim is configured, enforce it.
  - If not configured, use an issuer-derived fallback subject identifier.

### Phase 2: Issuer-Only Authentication Path
- Add helper to resolve issuer from verified claims (`iss`, `issuer`, nested VC issuer fallback).
- Fail authentication when issuer cannot be resolved after verification.
- Use issuer value as subject only when subject claim is not configured.

### Phase 3: Attribute Mapping Behavior
- When no claim mappings exist, return empty attribute map (no synthetic mappings).
- When mappings exist, map only available verified claims.
- Preserve nested-claim lookup (`credentialSubject`, `vc.credentialSubject`) for compatibility.

### Phase 4: Presentation Definition Dependency
- Rely on verification component to enforce PD constraints (requested claims presence/format).
- Do not duplicate PD claim-validation logic in authenticator unless a concrete API is added for PD introspection.

### Phase 5: Robustness and Logging
- Keep sanitized logging (`sanitizeForLog`) in all exception/debug paths.
- Ensure no sensitive raw claims are logged.
- Preserve current anti-replay extension points (nonce/audience checks) for future activation.

### Phase 6: Validation Matrix
Execute functional tests for all four scenarios:
- **Input:** combinations of PD claims / IDP mapping / subject claim config.
- **Expected:** authentication success/failure, subject source, and mapped attributes.

Suggested checks per scenario:
- Whether authentication completes.
- Whether `context.getSubject()` is set.
- Whether mapped attributes are empty/populated as expected.
- Whether subject came from configured claim or issuer fallback.

## Security Checklist
- **Injection:** no new user-controlled values used in queries/commands.
- **Sensitive logging:** avoid logging VC payload/PII.
- **Access control:** no authorization bypass introduced; only authentication behavior adjusted.
- **Secrets:** no hardcoded credentials added.

## Deliverables
1. Updated subject-resolution and authentication flow in `OpenID4VPAuthenticator`.
2. Updated claim-mapping behavior for no-mapping scenarios.
3. Test evidence for all four scenarios.
4. Optional follow-up: formal PD introspection utility if required by architecture.

## Notes
- License header year in Java file should be updated to `2026` (or a range ending in `2026`) in the implementation PR.
