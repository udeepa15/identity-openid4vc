# Plan: Move PD-update logic only to presentation.management

## Goal
Move only the **PD updating related logic** from `OpenID4VPIdentityProviderMgtListener` to `presentation.management`, while keeping listener ownership and non-PD-update callbacks in authenticator.

### In scope (move)
- `handlePrePersistence`
- `handlePostPersistence`
- `extractMappedIdpClaims`
- `hasClaimChanges`
- `buildSyncedDefinition`
- `doPreAddIdP` / `doPreUpdateIdP` behavior (via delegation)

### Out of scope (keep as-is for now)
- `doPreDeleteIdP`
- `doPostDeleteIdP`
- Delete cleanup policy
- Listener registration ownership (remains in authenticator in this phase)

## Current baseline
- Listener class lives in authenticator:
  - `OpenID4VPIdentityProviderMgtListener`
- Listener is registered in authenticator OSGi activation:
  - [components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/internal/VPServiceRegistrationComponent.java](components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/internal/VPServiceRegistrationComponent.java)
- PD CRUD service is provided by management component:
  - [components/org.wso2.carbon.identity.openid4vc.presentation.management/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/management/internal/PresentationDefinitionServiceComponent.java](components/org.wso2.carbon.identity.openid4vc.presentation.management/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/management/internal/PresentationDefinitionServiceComponent.java)

---

## Migration strategy (safe, incremental, scoped)

### Phase 0 — Preconditions and guardrails
1. Freeze behavior with tests before moving code.
2. Define strict scope boundaries (only methods listed in scope).
3. Keep listener registration and delete-flow behavior unchanged.

Deliverable:
- Test baseline + migration branch ready.

---

### Phase 1 — Extract PD-update orchestration service in management
Create a new management-side service for add/update-time PD linkage + claim sync only.

Proposed service contract (new interface in management):
- `OpenID4VPIdPUpdateSyncService` with methods:
  - `validatePreAddOrUpdate(IdentityProvider idp, String tenantDomain)`
  - `syncPostAddOrUpdate(IdentityProvider idp, String tenantDomain)`

Implementation location:
- `...presentation.management.service.impl.OpenID4VPIdPUpdateSyncServiceImpl`

Move logic from listener methods:
- `handlePrePersistence(...)`
- `handlePostPersistence(...)`
- `extractMappedIdpClaims(...)`
- `hasClaimChanges(...)`
- `buildSyncedDefinition(...)`

Keep helper methods inside listener if only needed for callback plumbing/logging:
- `sanitize(...)`
- delete-path helpers

Design notes:
- Do not depend on authenticator data holder inside the new service.
- Inject `PresentationDefinitionService` directly in management.
- Service should encapsulate PD lookup, validation, diffing, and update construction.
- Listener should map exceptions to `IdentityProviderManagementException` only at callback boundary.

Deliverable:
- New management update-sync service with unit tests.

---

### Phase 2 — Refactor existing authenticator listener to delegate pre/update logic
Do not move listener class in this phase.

Behavior in authenticator listener:
- Keep `getDefaultOrderId() == 99` unchanged.
- `doPreAddIdP` and `doPreUpdateIdP` delegate to `OpenID4VPIdPUpdateSyncService.validatePreAddOrUpdate(...)`.
- `doPostAddIdP` and `doPostUpdateIdP` delegate to `OpenID4VPIdPUpdateSyncService.syncPostAddOrUpdate(...)`.
- Keep delete callbacks as-is (no service delegation in this plan).

Registration model:
- No listener registration changes.
- Existing registration in authenticator remains unchanged.

Deliverable:
- Existing listener delegates PD update logic to management service.

---

### Phase 3 — Minimal wiring updates
1. Add OSGi reference for `OpenID4VPIdPUpdateSyncService` into authenticator component/data holder.
2. Keep existing `IdentityProviderMgtListener` registration path unchanged.
3. Keep existing `PresentationDefinitionService` usage for delete path until a separate delete migration.

Deliverable:
- PD update logic owner = management service.
- Listener owner = authenticator (unchanged).

---

### Phase 4 — POM and OSGi wiring updates (limited)

Management `pom.xml` updates:
- Add dependencies only if needed by new update-sync service API types.
- No requirement to register `IdentityProviderMgtListener` from management in this scope.

Authenticator `pom.xml` updates:
- Keep current listener dependencies.
- Add import for new management service contract if required.

Deliverable:
- Buildable modules with scoped dependency updates only.

---

### Phase 5 — Test plan (must pass before merge)

## Unit tests
1. Pre-add/update validation:
   - OpenID4VP IdP with missing `presentationDefinitionId` -> fails.
   - Non-OpenID4VP IdP -> no-op.
  - `doPreAddIdP` / `doPreUpdateIdP` delegate exactly once to new service.
2. Post-add/update sync:
   - Claim mappings changed -> PD updated.
   - No claim changes -> no update call.
3. Delete behavior regression (unchanged path):
  - Existing pre-delete cleanup still works.

## Integration tests
1. Add connection with valid PD ID -> success.
2. Add connection with invalid PD ID -> blocked.
3. Update connection claims -> PD requested claims synced.
4. Delete connection -> behavior unchanged from baseline.

## Runtime checks
- Confirm listener execution order remains `99`.
- Confirm no behavior change in callback registration path.

Deliverable:
- Green test suite + callback behavior parity report.

---

## Cutover checklist
- [ ] New `OpenID4VPIdPUpdateSyncService` implemented in management.
- [ ] Authenticator listener delegates pre/update methods to new service.
- [ ] Delete callbacks remain unchanged and validated.
- [ ] Build passes for both modules.
- [ ] Functional parity verified for add/update flows.

---

## Rollback plan
If production issues occur:
1. Revert listener delegation to old in-class implementations.
2. Keep management service code disabled/unreferenced.
3. Re-deploy with previous listener-only behavior.

Recommended safety mechanism:
- Add a feature flag for delegation, e.g., `openid4vp.pd.update.delegation.enabled=true|false`.

---

## Known risks and mitigations
1. **Risk: behavior drift in pre/update callbacks**
  - Mitigation: contract tests for `doPreAddIdP`, `doPreUpdateIdP`, `doPostAddIdP`, `doPostUpdateIdP`.

2. **Risk: dependency coupling through service API**
  - Mitigation: keep service API narrow and versioned.

3. **Risk: partial migration confusion**
  - Mitigation: document clearly that delete callbacks remain in listener for this phase.

4. **Risk: delete-by-name technical debt remains**
  - Mitigation: track separately as follow-up migration item.

---

## Recommended timeline
- Sprint 1: Phase 1 + unit tests.
- Sprint 2: Phase 2 + Phase 3 + integration tests.
- Sprint 3: stabilization and optional delete-flow migration decision.

---

## Final architecture after this scoped migration
- `presentation.management` owns:
  - PD CRUD
  - PD-update orchestration for add/update callbacks
- `presentation.authenticator` owns:
  - Listener registration and callback handling
  - Delete callback logic (unchanged)
  - Authentication runtime flow
