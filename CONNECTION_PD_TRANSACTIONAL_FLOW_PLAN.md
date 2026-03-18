# Connection + Presentation Definition Transactional Flow Plan

## Objective
Ensure connection (IdP) creation and Presentation Definition (PD) creation behave as a single reliable workflow:

1. Create PD first.
2. Use PD ID when creating/updating the connection.
3. Prevent orphan PDs if connection persistence fails.
4. Keep claim mappings and PD requested claims synchronized.

---

## Business Requirements

- A new connection must not be persisted without a valid PD reference.
- Connection create/update requests should remain single-request from the caller perspective.
- Failures must not leave inconsistent state:
  - No connection without PD (strict mode).
  - No orphan PD after failed connection persistence.
- CRUD claim mapping changes in connection must update PD claims accordingly.

---

## Consistency Model

Use **strict consistency with compensation**:

- **Primary guarantee:** If PD creation fails, connection creation fails.
- **Compensation guarantee:** If PD succeeds but connection fails, delete the newly created PD (best-effort immediate + retry).

This is effectively a local saga pattern.

---

## Proposed Lifecycle Hooks

Use Identity Provider Management listener hooks in the authenticator component:

- `doPreAddIdP(...)`
- `doPostAddIdP(...)`
- `doPostAddIdPWithException(...)` (or equivalent exception callback available in platform)
- `doPreUpdateIdP(...)`
- `doPostUpdateIdP(...)`
- `doPostUpdateIdPWithException(...)` (or equivalent)
- `doPreDeleteIdP(...)` / `doPostDeleteIdP(...)`

If exact exception hooks differ by platform version, implement the nearest supported failure callback and keep retry cleanup as fallback.

---

## End-to-End Create Flow

### Phase 1: Pre-Create (Prepare)
1. Detect whether OpenID4VP authenticator is enabled in the incoming IdP payload.
2. Resolve incoming claim mappings from `claims.mappings[].idpClaim`.
3. Build PD model:
   - `name`: `<idpName> Definition`
   - requested credential entries as per existing PD model.
   - requested claims = normalized `idpClaim` list.
4. Create PD via `PresentationDefinitionService.createPresentationDefinition(...)`.
5. Inject created `presentationDefinitionId` into OpenID4VP authenticator property in the same in-memory IdP object.
6. Store operation context (thread-local/request context):
   - `tenantDomain`
   - `createdPdId`
   - `idpName`
   - operation type (`ADD`)

### Phase 2: Connection Persistence
- Core IdP manager persists connection using mutated authenticator properties.

### Phase 3: Post-Create Success
1. Clear operation context.
2. Optional: run claim-sync to enforce final requested claims in PD from persisted IdP mapping.
3. Log success with correlation ID.

### Phase 4: Post-Create Failure (Compensation)
1. Read operation context.
2. If `createdPdId` exists, delete PD immediately.
3. If delete fails, persist cleanup task (retry queue/table).
4. Clear operation context.
5. Re-throw/propagate error so API returns failure.

---

## Update Flow

### Scenario A: Existing PD linked, mapping changed
1. In pre-update, resolve current PD ID from incoming IdP or existing persisted IdP.
2. If PD exists, do not create new PD by default.
3. Persist IdP update.
4. In post-update success, sync PD claims from latest mapping.

### Scenario B: No PD linked, OpenID4VP enabled
1. In pre-update, create PD and inject `presentationDefinitionId`.
2. On update failure, compensate by deleting the newly created PD.

### Scenario C: PD replaced explicitly in request
1. Validate target PD exists.
2. Persist update.
3. Optional: if old PD is dedicated to this IdP, schedule safe deletion policy.

---

## Delete Flow

1. In pre-delete, resolve PD linked to IdP.
2. Apply deletion policy:
   - If PD is dedicated to this IdP: delete PD.
   - If shared PD: keep PD.
3. Persist IdP delete.

For shared/dedicated decision, use explicit metadata or deterministic naming + ownership marker.

---

## Claim Mapping ↔ PD Sync Rules

- Source: `IdP.claimConfig.claimMappings[].remoteClaim.claimUri` (`idpClaim`).
- Normalize: trim, deduplicate, stable ordering.
- Destination: each `RequestedCredential.claims` in PD.
- Update rules:
  - add new claims,
  - remove deleted claims,
  - no-op when equal.
- Keep issuer/type/purpose unchanged unless explicitly configured otherwise.

---

## Error Handling Matrix

1. **PD create fails in pre-add/pre-update**
   - Abort operation immediately.
   - Return clear API error.

2. **PD create succeeds, IdP persistence fails**
   - Trigger compensation delete.
   - If delete fails, enqueue retry and alert.

3. **IdP persistence succeeds, PD sync fails in post phase**
   - Do not rollback IdP.
   - Emit warning/error + retry sync task.
   - Maintain eventual consistency for claim sync.

4. **Compensation retry exhausted**
   - Raise operational alert with orphan PD ID and tenant.

---

## Retry / Outbox Strategy

Create a lightweight retry record model:

- `operationId`
- `tenantId`
- `pdId`
- `operationType` (`DELETE_PD`, `SYNC_PD_CLAIMS`)
- `attemptCount`
- `nextRetryAt`
- `lastError`

Background job:
- polls due retries,
- applies exponential backoff,
- marks success/failure terminal state.

---

## Data and Configuration Additions

### New/Updated Properties
- `presentationDefinitionId` (canonical property on OpenID4VP authenticator).
- Optional feature flags:
  - `openid4vc.pd.transactionalCreate.enabled=true`
  - `openid4vc.pd.compensation.retry.enabled=true`

### Optional Metadata
- PD ownership marker (dedicated/shared).
- PD source marker (`managedBy=OpenID4VPIdPListener`).

---

## Security and Robustness

- Sanitize all logged IdP/PD identifiers.
- Do not log full request payload with claims in error logs.
- Keep operations tenant-isolated.
- Validate claim names before writing to PD.
- Ensure listener cannot bypass authorization checks (it runs post-authz in server internals only).

---

## Observability

Log fields:
- `correlationId`
- `tenantDomain`
- `idpName`
- `pdId`
- `operation`
- `result`

Metrics:
- `openid4vc_pd_create_total`
- `openid4vc_pd_compensation_total`
- `openid4vc_pd_compensation_failure_total`
- `openid4vc_pd_claim_sync_total`
- `openid4vc_pd_claim_sync_failure_total`

---

## Detailed Implementation Tasks

1. Extend listener to support pre-create PD generation in `doPreAddIdP` and conditional pre-update creation.
2. Add operation context holder (thread-local) for compensation metadata.
3. Add exception callback handling to delete orphan PD on failed add/update.
4. Refactor PD resolver and claim extractor utilities into reusable private methods.
5. Add retry/outbox service for failed compensation/sync operations.
6. Add feature-flag checks.
7. Add unit tests for each hook path.
8. Add integration tests for failure/compensation scenarios.

---

## Test Plan

### Unit
- Pre-add with valid mapping creates PD and injects PD ID.
- Pre-add PD create failure aborts.
- Post-add exception triggers compensation delete.
- Post-update sync adjusts claims add/remove/no-op.

### Integration
1. Create connection success: PD created and linked.
2. Create connection fail after PD create: PD deleted.
3. Update mapping (`email`→`email1`): PD claims synced.
4. Update fails after pre-created PD: compensation delete.
5. Delete dedicated connection: PD deleted.

### Negative
- Invalid claim names.
- PD service unavailable.
- Compensation delete failure path + retry scheduling.

---

## Rollout Strategy

1. Deploy with transactional feature flags OFF.
2. Enable in staging for selected tenants.
3. Validate metrics + orphan cleanup behavior.
4. Enable production gradually.
5. Add dashboard/alerts for compensation failures.

---

## Acceptance Criteria

- Connection create without PD is impossible when OpenID4VP is enabled.
- No orphan PD remains after failed connection create/update (orphan retries visible and recoverable).
- Claim mapping CRUD updates PD requested claims as defined.
- All tests for success/failure paths pass.
