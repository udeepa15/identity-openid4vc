# Verification Component — Database, Cache, and Multi-Tenant Behavior Guide

This guide explains how the OID4VP verification component handles persistence-related dependencies, in-memory caching, and tenant isolation.

---

## 1) Database usage in this component

## 1.1 Direct database access
This component **does not directly access a database**.

There are:
- no DAO classes,
- no JDBC code,
- no SQL statements,
- no local persistence tables managed by this module.

So this module is primarily a **verification engine** and **integration consumer**.

## 1.2 Indirect database usage via service dependency
Database-backed data can still influence verification through this call path:

- `VCVerificationServiceImpl.verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`
- optionally resolves a Presentation Definition by ID using:
  - `presentationDefinitionService.getPresentationDefinitionById(presentationDefinitionId, tenantId)`

If the injected Presentation Definition service is backed by DB storage (typically in the management component), the verification component will consume that result and enforce constraints.

### What this means in practice
- Verification component: **no own DB writes/reads**.
- Presentation definition resolution: **delegated** to another component, potentially DB-backed.

---

## 2) Cache usage

## 2.1 What is cached
The component caches **decoded status-list bitstrings** used for revocation checks.

Location:
- `StatusListServiceImpl`

Cache structure:
- `Map<String, CachedStatusList> statusListCache = new ConcurrentHashMap<>()`
- key: `statusListCredentialUrl`
- value: decoded bitstring + creation timestamp

## 2.2 Cache TTL
- `CACHE_TTL_MS = 5 * 60 * 1000` (5 minutes)

Behavior:
1. On revocation check, component first checks cache.
2. If present and not expired, returns cached bitstring.
3. Otherwise fetches remote status list, decodes it, and stores fresh cache entry.

## 2.3 Cache lifecycle
- Automatic expiry is time-based per entry.
- Manual reset available through `clearCache()`.

## 2.4 Thread-safety
- `ConcurrentHashMap` is used, so concurrent reads/writes are safe within a JVM.

## 2.5 Cache scope
Important:
- cache is **in-memory and local to a single node/JVM**,
- not distributed across cluster nodes,
- each node builds and expires its own cache entries.

---

## 3) Multi-tenant handling

## 3.1 Tenant-aware API surfaces
Tenant context appears in two forms:

1. `tenantId` in unified VP verification:
- `verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)`
- used to resolve Presentation Definition with tenant scoping.

2. `tenantDomain` in issuer trust methods:
- `verifyJWTVCIssuer(..., tenantDomain)`
- `verifyJSONLDVCIssuer(..., tenantDomain)`
- `verifyAllIssuerTrust(..., tenantDomain)`

These methods preserve tenant context in API contract and flow orchestration.

## 3.2 Tenant isolation model
### Presentation Definition path
- Isolation is achieved by passing `tenantId` into `presentationDefinitionService.getPresentationDefinitionById(...)`.
- Correct tenant-scoped definition retrieval depends on implementation of the management service.

### Revocation cache path
- Current cache key is URL only (`statusListCredentialUrl`).
- There is **no explicit tenant dimension in cache key**.

Implication:
- If two tenants use the same status-list URL, they will reuse same cached decoded bitstring in the node.
- This is usually acceptable because the resource is URL-addressed and logically shared.

## 3.3 Tenant-aware persistence ownership
- Verification module relies on external services for tenant-partitioned persisted data.
- It does not own tenant DB schema itself.

---

## 4) Failure handling for DB/cache/tenant paths

## 4.1 Presentation definition resolution failures
In unified verification flow:
- if PD resolution fails (runtime/VP exceptions), component logs in debug and skips PD constraints.
- verification continues without hard failing solely due to PD lookup failure.

## 4.2 Cache/remote status-list failures
In revocation path:
- network/decoding/parsing failures throw `RevocationCheckException` at status service level.
- upper VC verification flow may treat revocation-check failure with tolerant behavior depending on path.

## 4.3 Tenant context errors
- missing/incorrect tenant values may affect PD resolution outcomes.
- component behavior remains deterministic: if no PD can be resolved, PD checks are skipped.

---

## 5) Reviewer checklist (DB/cache/multi-tenant)

Use this during review:

- [ ] Confirm there is no direct DB code in this module.
- [ ] Confirm tenant ID is passed when resolving presentation definitions.
- [ ] Confirm revocation cache is local in-memory and TTL bounded.
- [ ] Confirm cache key design (URL-based) is acceptable for tenant model.
- [ ] Confirm behavior when PD resolution fails is intentional (skip constraints vs hard fail).
- [ ] Confirm revocation failure semantics are aligned with security policy.

---

## 6) Practical summary

- **Database:** no direct DB access in verification component; uses external services that may be DB-backed.
- **Cache:** local `ConcurrentHashMap` cache for decoded status lists with 5-minute TTL.
- **Multi-tenant:** tenant-aware PD lookup via `tenantId`; tenant context propagated in public APIs; cache is URL-scoped, not tenant-keyed.

This architecture keeps verification logic lightweight while delegating persistence and tenant storage concerns to management services.
