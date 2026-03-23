# Presentation Definition (PD) Customization via Java Interface

## Current state (today)

Currently, the Presentation Definition JSON is generated/handled at code level and then consumed by OpenID4VP request creation.

In this repository, the main flow is:

1. PD is persisted and managed through `PresentationDefinitionService` (`create/get/update/delete`).
2. OpenID4VP connection stores `presentationDefinitionId` in authenticator properties.
3. At runtime, request builders resolve PD by ID and build the request payload.

So if you want users to change PD via Java instead of hardcoded JSON edits, the correct path is to **use the existing service layer** and update the referenced `presentationDefinitionId`.

---

## Recommended approach

### 1) Expose a Java-facing facade (API for your UI/backend)

Create a facade interface in your extension layer (or API component), for example:

- `createDefinition(...)`
- `updateDefinition(...)`
- `getDefinition(...)`
- `deleteDefinition(...)`
- `assignDefinitionToOpenID4VPConnection(...)`

This facade should internally call:

- `PresentationDefinitionService` for PD CRUD
- `IdentityProviderManager` for updating OpenID4VP authenticator property `presentationDefinitionId`

### 2) Keep PD as data, not code

Do not embed wallet-specific PD JSON in authenticator logic.

Instead:

- Build/validate PD using model + util (`PresentationDefinition`, `PresentationDefinitionUtil`)
- Persist PD through `PresentationDefinitionService`
- Only store the selected PD ID in connection config

### 3) Bind PD to the connection

After creating/updating a PD, update the OpenID4VP federated authenticator property:

- Property name: `presentationDefinitionId`
- Authenticator name: `OpenID4VPAuthenticator`

That makes runtime request generation automatically pick the new PD.

---

## Minimal implementation blueprint

### A) Service reference (OSGi DS)

In your Java component, inject:

- `PresentationDefinitionService`
- `IdentityProviderManager`

### B) CRUD flow

1. Receive UI/API payload (claims, issuer constraints, formats).
2. Map payload -> `PresentationDefinition` model.
3. Call `createPresentationDefinition(...)` or `updatePresentationDefinition(...)`.
4. Return `definitionId` to caller.

### C) Assign flow

1. Load the target Identity Provider (`IdentityProviderManager.getIdPByName(...)`).
2. Find `OpenID4VPAuthenticator` config.
3. Set property `presentationDefinitionId=<newDefinitionId>`.
4. Call update IDP API.

---

## Why this is the best way

- Reuses the existing validated PD lifecycle.
- Avoids code redeploys for PD changes.
- Keeps compatibility with listener synchronization behavior.
- Supports tenant-aware management cleanly.

---

## Validation checklist

Before applying PD updates from Java interface:

1. Validate `definitionId` exists for the tenant.
2. Validate PD structure via `PresentationDefinitionUtil`.
3. Validate claim paths and issuer constraints.
4. Update only the target IDP/connection.
5. Audit-log who changed PD and when.

---

## Suggested next step

If you want, the next concrete task is to add a small management facade class (for example, `PresentationDefinitionConnectionConfigService`) in the management module that does:

- PD CRUD through `PresentationDefinitionService`
- IDP authenticator property update for `presentationDefinitionId`

This gives a clean Java interface for UI/backend callers without touching runtime verifier/authenticator logic.
