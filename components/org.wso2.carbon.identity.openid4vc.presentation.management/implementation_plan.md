# Implementation Plan: Wallet-Aware Request Formatting with DB-Backed Presentation Definitions

## 1) Project Overview

Build a Java-based, extensible system where **Presentation Definition details are always loaded from DB**, while wallet-specific strategies only control final OpenID4VP request JSON formatting (for example, include/exclude `client_metadata`, include/exclude `nonce`).

### Goal

- Keep PD data (`claims`, `issuer`, `credential type`, constraints) sourced from DB only.
- Allow wallet-specific request-format behavior without branching logic everywhere.
- Keep OpenID4VP request generation clean and pluggable.
- Enable easy onboarding of new wallet types with minimal code changes.

---

## 2) Architecture & Design

## 2.1 Core Pattern

Use a **Strategy + Factory** design:

- **Strategy Interface**: defines wallet request-format customization contract.
- **Wallet Implementations**: each wallet has its own formatter/customizer class.
- **Factory/Selector**: resolves the correct formatter by wallet type.
- **Optional Shared Base Class**: common JSON helper/default behavior.

## 2.2 Key Components

- `WalletType` enum: canonical wallet identifiers.
- `WalletRequestFormatterInterface`: common contract.
- `AbstractWalletRequestFormatter` (optional): common logic for defaults and helpers.
- `AppleWalletRequestFormatter`, `SimpleWalletRequestFormatter`: concrete strategies.
- `WalletRequestFormatterFactory`: resolver/registry of strategies.
- `WalletRequestFormattingService`: orchestration layer used by authenticator.

## 2.3 Data Model

Use explicit request/response objects:

- `WalletRequestFormattingContextInterface`
  - wallet type
   - tenant/app metadata
   - flags (for example `includeClientMetadata`, `includeNonce`)
   - request object under construction
- `PresentationDefinition` (existing model) loaded from DB by `presentationDefinitionId`.

> **Rule:** PD content is never generated from wallet strategy. Wallet strategy only adjusts final request JSON shape.

---

## 3) Step-by-Step Implementation Plan

## Step 1: Define wallet type and formatting context

1. Create `WalletType` enum (`APPLE_WALLET`, `SIMPLE_WALLET`, ...).
2. Create a `WalletRequestFormattingContextInterface` and immutable implementation.
3. Add fields for final JSON toggles only (for example include/exclude `client_metadata`, `nonce`).

## Step 2: Define strategy interface

1. Create `WalletRequestFormatterInterface` with:
   - `WalletType getSupportedWalletType()`
   - `void apply(WalletRequestFormattingContextInterface context)`
2. Strategy must not modify DB-backed PD claims/constraints; only request envelope/output fields.

## Step 3: Add optional abstract base

1. Add `AbstractWalletRequestFormatter` with reusable helpers:
   - add/remove JSON fields safely
   - merge metadata blocks
   - shared validation
2. Keep wallet-specific rules only in child classes.

## Step 4: Implement wallet-specific formatters

1. Create `AppleWalletRequestFormatter`:
   - for example include `client_metadata`, include `nonce`.
2. Create `SimpleWalletRequestFormatter`:
   - for example include `client_metadata`, optionally omit `nonce` if required by wallet contract.
3. Ensure both only transform final JSON request structure.

## Step 5: Implement factory/selector

1. Build `WalletRequestFormatterFactory` using constructor-injected list/map.
2. Resolve generator by `WalletType`.
3. Throw explicit error for unsupported wallet type.

## Step 6: Create orchestration service

1. Create `WalletRequestFormattingService`:
   - loads PD from DB using existing `PresentationDefinitionService` and `presentationDefinitionId`
   - builds standard request JSON with DB-backed PD details
   - resolves formatter via factory
   - applies wallet-specific envelope changes
   - returns final JSON object.

## Step 7: Integrate with existing flow

1. Keep existing PD persistence flow unchanged.
2. In authenticator, continue resolving `presentationDefinitionId` and loading PD from DB.
3. Call new formatting service only for final JSON customization per wallet.

## Step 8: Testing

1. Unit test each generator class.
2. Unit test factory resolution and unsupported wallet path.
3. Integration test full flow: DB PD load -> request object build -> wallet formatter apply.

---

## 4) Example Code Snippets

## 4.1 Strategy interface

```java
public interface WalletRequestFormatterInterface {

    WalletType getSupportedWalletType();

   void apply(WalletRequestFormattingContextInterface context);
}
```

## 4.2 Wallet implementations

```java
public class AppleWalletRequestFormatter extends AbstractWalletRequestFormatter {

    @Override
    public WalletType getSupportedWalletType() {
        return WalletType.APPLE_WALLET;
    }

    @Override
   public void apply(WalletRequestFormattingContextInterface context) {
      JsonObject request = context.getRequestObject();

      ensureNonce(request, context);
      ensureClientMetadata(request, context);
    }
}
```

```java
public class SimpleWalletRequestFormatter extends AbstractWalletRequestFormatter {

    @Override
    public WalletType getSupportedWalletType() {
        return WalletType.SIMPLE_WALLET;
    }

    @Override
   public void apply(WalletRequestFormattingContextInterface context) {
      JsonObject request = context.getRequestObject();

      if (!context.isNonceRequired()) {
         request.remove("nonce");
      }
      if (!context.isClientMetadataRequired()) {
         request.remove("client_metadata");
      }
    }
}
```

## 4.3 Factory usage

```java
public class WalletRequestFormatterFactory {

   private final Map<WalletType, WalletRequestFormatterInterface> formatters;

   public WalletRequestFormatterFactory(List<WalletRequestFormatterInterface> formatterList) {
      this.formatters = formatterList.stream()
                .collect(Collectors.toMap(
                  WalletRequestFormatterInterface::getSupportedWalletType,
                        Function.identity()));
    }

   public WalletRequestFormatterInterface resolve(WalletType walletType) {
      WalletRequestFormatterInterface formatter = formatters.get(walletType);
      if (formatter == null) {
            throw new IllegalArgumentException("Unsupported wallet type: " + walletType);
        }
      return formatter;
    }
}
```

```java
// Service layer
PresentationDefinition pd = presentationDefinitionService
      .getPresentationDefinitionById(request.getPresentationDefinitionId(), tenantId); // DB source of truth

JsonObject requestObject = buildStandardRequestFromPd(pd); // includes DB-backed claims/issuer/type

WalletRequestFormatterInterface formatter = factory.resolve(request.getWalletType());
formatter.apply(context.withRequestObject(requestObject));
```

---

## 5) Best Practices & Optimizations

- Keep formatter classes **small and deterministic**.
- Use immutable request DTOs.
- Keep PD claims/issuer/type loading in one DB-backed path.
- Centralize request JSON assembly in helper utilities (avoid string concatenation).
- Keep wallet-specific constants in dedicated constants classes.
- Validate DB-loaded PD before embedding in request.
- Use feature flags if wallet behavior varies by tenant.
- Add versioning to wallet formatting rules (for backward compatibility).
- Log wallet type + PD ID (no sensitive claims payloads in logs).

---

## 6) Recommended Folder / File Structure

```text
components/
  org.wso2.carbon.identity.openid4vc.presentation.management/
    src/main/java/org/wso2/carbon/identity/openid4vc/presentation/management/
      wallet/
        model/
          WalletType.java
               WalletRequestFormattingContextInterface.java
               WalletRequestFormattingContext.java
            formatter/
               WalletRequestFormatterInterface.java
               AbstractWalletRequestFormatter.java
               AppleWalletRequestFormatter.java
               SimpleWalletRequestFormatter.java
        factory/
               WalletRequestFormatterFactory.java
        service/
               WalletRequestFormattingService.java
          impl/
                  WalletRequestFormattingServiceImpl.java
      util/
            OpenID4VPRequestBuildUtil.java
```

---

## 7) Next Steps / Extensions

1. **OpenID4VP integration**
   - Select wallet type at auth request time and apply wallet-specific JSON formatting.
2. **OpenID4VCI alignment**
   - Reuse wallet capabilities metadata to tune request envelope fields.
3. **Admin API support**
   - Expose endpoint to preview generated PD by wallet type.
4. **Template + override model**
   - Base wallet template + tenant-specific overrides.
5. **Policy engine integration**
   - Plug ABAC/policy rules for issuer restrictions and claim requirements.
6. **Rule versioning + migration**
   - Support PD generator versions to avoid breaking existing connections.
7. **Telemetry**
   - Track acceptance rates per wallet type and algorithm profile.

---

## Suggested first milestone

Implement `WalletRequestFormatterInterface`, two concrete formatters, and `WalletRequestFormatterFactory` with unit tests. Then integrate into one orchestration service that loads PD from DB and formats the final request JSON.

---

## 8) How to include this in Authenticator and replace current PD creation logic

This section explains exactly how to wire the new wallet formatting files into the authenticator component while keeping PD details DB-backed.

## 8.1 Current logic to replace

Today, request JWT building in authenticator path still contains inline conversion logic that:

- reads `requested_credentials`
- loops each credential
- calls `PresentationDefinitionUtil.buildInputDescriptorFromRequestedCredential(...)`
- builds a full PD JSON string dynamically

This exists in:

- `VPRequestServiceImpl.buildRequestObjectJwt(...)` (presentation.authenticator component)

## 8.2 Target behavior

Keep PD data retrieval from DB as the only source of truth, and move wallet-specific final JSON formatting to strategy classes in management module. Authenticator should only:

1. resolve wallet type,
2. load PD by `presentationDefinitionId` from DB,
3. apply wallet formatter to final request JSON (for envelope fields only).

## 8.3 Integration steps

### Step A: Add wallet request formatter files to management module

Add files proposed in section 6 under:

- `presentation.management.wallet.model`
- `presentation.management.wallet.formatter`
- `presentation.management.wallet.factory`
- `presentation.management.wallet.service`

### Step B: Expose a formatting service from management module

Add OSGi service interface, for example:

- `WalletRequestFormattingServiceInterface.apply(WalletRequestFormattingContextInterface context)`

Expected output:

- final request JSON object with wallet-specific envelope updates.

DB PD loading remains in existing `PresentationDefinitionService` usage.

### Step C: Register and inject into authenticator component

In authenticator DS component (for example `VPServiceRegistrationComponent`):

1. add `@Reference` for `WalletPDGenerationServiceInterface`
2. store it in `VPServiceDataHolder`

This follows the same pattern currently used for `PresentationDefinitionService` injection.

### Step D: Add wallet type resolution in authenticator

Resolve wallet type from one of:

- authenticator property (recommended: explicit `WalletType` property),
- application/connection metadata,
- fallback default (`SIMPLE_WALLET`).

Create and pass `WalletRequestFormattingContextInterface` with:

- wallet type
- request object built from DB PD
- app / tenant metadata.

### Step E: Replace inline PD build block in `VPRequestServiceImpl`

In `buildRequestObjectJwt(...)`:

1. keep DB-backed PD resolution (`presentationDefinitionId` -> DB -> PD JSON)
2. remove only wallet-specific envelope branching from this method
3. call `WalletRequestFormattingServiceInterface` for final request JSON adjustments
4. keep `presentation_definition` based on DB PD data.

Pseudo-replacement:

```java
WalletType walletType = resolveWalletType(vpRequest);
PresentationDefinition pd = presentationDefinitionService
   .getPresentationDefinitionById(vpRequest.getPresentationDefinitionId(), tenantId);

JsonObject requestObject = buildRequestFromPd(pd, vpRequest); // DB-backed claims/issuer/type

WalletRequestFormattingContextInterface ctx = buildFormattingContext(walletType, requestObject, vpRequest);
walletRequestFormattingService.apply(ctx); // only include/exclude fields like client_metadata/nonce
```

### Step F: Keep backward compatibility

If wallet formatter service is unavailable or wallet type is unknown:

1. keep DB-backed PD load path unchanged
2. skip formatting and use default request JSON

Recommended rollout:

- phase 1: dual-path with config flag (`openid4vp.wallet.request.formatter.enabled`)
- phase 2: remove old wallet-specific inline envelope logic after validation.

### Step G: Update tests

Add tests in authenticator module:

- wallet type -> formatter selection integration
- verifies `presentation_definition` claim matches strategy output
- fallback path when strategy unavailable

Add tests in management module:

- per-wallet formatter output contract
- factory resolution and unsupported wallet errors.

## 8.4 Minimal migration checklist

- [ ] add wallet formatter interfaces + implementations
- [ ] add factory + formatting service
- [ ] expose DS service from management module
- [ ] inject service into authenticator via `VPServiceRegistrationComponent`
- [ ] keep DB-backed PD loading as-is and replace only envelope formatting logic in `VPRequestServiceImpl`
- [ ] add config-based fallback
- [ ] complete unit + integration tests
