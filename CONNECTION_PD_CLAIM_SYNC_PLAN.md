# Connection ↔ Presentation Definition Claim Sync Plan

## Objective
Keep Presentation Definition (PD) requested claims synchronized with Identity Provider (connection) claim mappings for all connection claim-mapping CRUD operations.

## Problem Statement
When a connection is created or updated via one request (for example `PUT /api/server/v1/identity-providers/{id}`), claim mappings can change, but PD claim constraints may remain stale. This causes runtime mismatch between what the connection expects and what OpenID4VP verification requests.

## Target Outcome
For each connection update (single API request):
- Added mapping claim → added to PD constraints.
- Updated mapping claim (e.g., `email` → `email1`) → PD updated accordingly.
- Removed mapping claim → removed from PD constraints.
- No mapping changes → no PD mutation.

## Scope
- Connection operations: Create, Read, Update, Delete (with sync actions on Create/Update/Delete).
- Claim mapping source: connection `claims.mappings[].idpClaim`.
- PD destination: claim constraints in PD (`input_descriptors[*].constraints.fields[*]`).
- Applies to IDPs that are linked to the OpenID4VP flow.

## Recommended Integration Point
Implement synchronization in an IdP management listener/service layer (not only API layer), so updates from Console/API/import paths are all covered.

## High-Level Design

### 1) Claim Sync Service
Add a dedicated service (example name: `ConnectionPresentationDefinitionSyncService`) with methods:
- `syncOnIdpCreate(idp)`
- `syncOnIdpUpdate(previousIdp, updatedIdp)`
- `syncOnIdpDelete(idp)`

Responsibilities:
- Resolve associated PD for the connection.
- Compute claim diff from old/new mapping sets.
- Apply atomic PD patch.
- Enforce idempotency (same input = no-op).

### 2) PD Resolver
Resolve which PD to update using this order:
1. OpenID4VP authenticator config on the connection (`presentationDefinitionId`).
2. Existing application↔PD mapping table/service (if configured).
3. If not resolvable, skip sync with structured warning log.

### 3) Claim Extraction Rules
From connection payload:
- Source set = all non-empty `claims.mappings[].idpClaim` values.
- Normalize: trim, deduplicate, preserve deterministic order.

### 4) PD Claim Path Strategy
For each `idpClaim` create/update a PD field entry using approved path format(s), e.g.:
- `$.credentialSubject.<idpClaim>` and/or `$.vc.credentialSubject.<idpClaim>` based on current verifier expectations.

Store a marker in PD field metadata (or naming convention) to identify system-managed entries, so only managed fields are mutated.

### 5) Diff Algorithm (Update)
- `oldClaims = extract(previousIdp.claims.mappings)`
- `newClaims = extract(updatedIdp.claims.mappings)`
- `toAdd = newClaims - oldClaims`
- `toRemove = oldClaims - newClaims`
- `toKeep = oldClaims ∩ newClaims`

Apply changes only for system-managed PD fields.

## CRUD Behavior

### Create Connection
- If mapping exists and PD is resolvable, insert missing PD claim fields.
- If no mapping, no PD claim fields are added.

### Read Connection
- No mutation.

### Update Connection (single request)
- Compare old and new mapping sets.
- Add/remove PD claim fields accordingly.
- Keep unrelated manual PD fields untouched.

### Delete Connection
- Optional policy (choose one and document):
  1. Remove only system-managed fields tied to this connection; or
  2. Leave PD unchanged to avoid affecting shared usage.

Recommended default: remove only if PD is dedicated to that connection.

## Transaction and Consistency
- Execute connection update + PD sync in one transactional boundary where possible.
- If true distributed transaction is not possible:
  - Commit connection update.
  - Perform PD sync in reliable post-commit step.
  - On failure, emit retryable event/job and alert.

## API Request Handling (Your Example)
For a single request updating connection claim mappings:
- Parse new `claims.mappings`.
- Load persisted connection state before update.
- Compute diff.
- Resolve PD ID.
- Patch PD constraints in the same request lifecycle (or post-commit retryable step).
- Return success only when sync policy guarantees are met.

## Validation Rules
- Reject invalid/empty claim names.
- Prevent duplicate PD field paths.
- Preserve existing PD required flags/purpose where applicable.
- Never overwrite non-managed custom fields.

## Observability
- Add structured logs with correlation id, connection id, pd id, added/removed counts.
- Metrics:
  - `pd_claim_sync_total`
  - `pd_claim_sync_failures_total`
  - `pd_claim_sync_duration_ms`

## Security Considerations
- Treat claim names as untrusted input; sanitize before logging.
- Avoid exposing full PD documents in logs.
- Enforce authorization at existing IdP management layer (no new bypass paths).

## Test Plan

### Unit Tests
- Claim extraction and normalization.
- Diff calculation.
- Managed-field-only mutation logic.

### Integration Tests
1. Create connection with mappings → PD fields added.
2. Update mapping name (`email`→`email1`) → old field removed, new field added.
3. Remove mapping → PD field removed.
4. No-op update → PD unchanged.
5. PD unresolved → connection update succeeds, sync warning logged (or fails, based on policy).

### Regression Tests
- Existing OpenID4VP verification flows still pass.
- Manual custom PD fields remain unchanged.

## Rollout Plan
1. Add feature flag: `openid4vc.pdClaimSync.enabled`.
2. Deploy disabled, observe logs/metrics.
3. Enable in test environment.
4. Enable in production after validation.

## Deliverables
1. Sync service implementation.
2. Listener/service-layer hook for IdP create/update/delete.
3. PD patch utility with managed-field strategy.
4. Unit + integration tests.
5. Feature flag + operational docs.
