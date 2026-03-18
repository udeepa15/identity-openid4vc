# OpenID4VP Identity Provider Listener Behavior (Simple Explanation)

This document explains, in simple terms, what the OpenID4VP IdP listener does when a **connection (IdP)** is created, updated, or deleted.

Listener file:
- [components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/listener/OpenID4VPIdentityProviderMgtListener.java](components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/listener/OpenID4VPIdentityProviderMgtListener.java)

---

## 1) What is this listener for?

The listener keeps **OpenID4VP connection settings** and **Presentation Definition (PD)** in sync.

In practice, it tries to ensure:
- A connection has a valid `presentationDefinitionId`.
- If needed, a PD is created automatically before saving the connection.
- Connection claim mappings are copied into PD requested claims.
- PD is removed when the connection is deleted (based on current delete logic).

---

## 2) What happens when a connection is created?

### Step A: Pre-add phase (`doPreAddIdP`)
Before the connection is saved:

1. Listener checks whether this is an OpenID4VP connection.
2. It checks if a `presentationDefinitionId` is already set in authenticator properties.
3. If ID exists:
   - It validates that PD actually exists.
4. If ID does not exist:
   - It creates a new PD automatically.
   - It writes the new ID back to connection properties:
     - `presentationDefinitionId` (new key)
     - `presentationDefinition` (legacy key)

If any of these fail, it throws an exception and stops connection creation.

### Step B: Post-add phase (`doPostAddIdP`)
After save succeeds:
- Listener syncs claim mappings from the connection into PD requested claims.
- It updates the PD only if there are actual claim changes.

---

## 3) What happens when a connection is updated?

### Step A: Pre-update phase (`doPreUpdateIdP`)
Before update:
- Same checks as create.
- If PD ID is missing, listener can create and inject one.

### Step B: Post-update phase (`doPostUpdateIdP`)
After update:
- Listener compares mapped IdP claims with PD claim lists.
- If different, PD is updated.
- If same, no update is done.

---

## 4) What happens when a connection is deleted?

### Pre-delete phase (`doPreDeleteIdP`)
Before delete:
- Listener tries to find PD by naming convention: `<IdP Name> Definition`.
- If found, PD is deleted.

### Post-delete phase (`doPostDeleteIdP`)
- Currently no extra delete logic.

---

## 5) How claim sync works

Claim source:
- `identityProvider.getClaimConfig().getClaimMappings()[].remoteClaim.claimUri`

Sync rule:
- For each requested credential inside the PD, set `claims` to the latest mapped remote claim list.

Behavior:
- Add new claims.
- Remove deleted claims.
- Keep credential type/purpose/issuer unchanged.

---

## 6) How PD is resolved

Listener resolves PD in this order:
1. `presentationDefinitionId` property.
2. Legacy `presentationDefinition` property.
3. Fallback by name: `<IdP Name> Definition`.

---

## 7) Why thread-local context is used

The listener stores minimal operation context in thread-local during pre-phase, and clears it in post-phase.
This is groundwork for compensation/rollback style handling.

---

## 8) Current limitation (important)

The base IdP listener API in this platform does not provide a true **post-exception callback** for add/update failures.

So if:
- PD is created in pre-phase,
- but connection persistence fails later,

automatic compensation delete in the same flow is limited.

That is why full transactional compensation needs either:
- core framework callback support, or
- retry/outbox orphan cleanup job.

---

## 9) In short

- **Create/Update:** PD is validated or auto-created first, then connection is saved, then claims are synced.
- **Delete:** PD is deleted by name in pre-delete.
- **Safety:** Listener is strict in pre-phase and fails fast if PD requirements are not met.
- **Gap:** Full rollback of newly-created PD on connection persistence failure needs extra framework support.
