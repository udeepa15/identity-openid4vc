# Remove Warning Suppressions — VPSubmissionServlet & ServletUtil

Both files suppress SpotBugs FindSecBugs warnings instead of fixing the underlying issues. This plan replaces each suppression with a proper code-level fix.

## Proposed Changes

### VPSubmissionServlet.java

---

#### W1: `SERVLET_CONTENT_TYPE` (line 179) on [parseSubmission](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#171-201)

**Root cause:** `request.getContentType()` is used directly without validation. A malicious Content-Type could trigger unexpected code paths.

**Fix:** Validate the content type against an allowlist before branching; reject unknown content types with a 415 (Unsupported Media Type) response.

```diff
- @SuppressFBWarnings("SERVLET_CONTENT_TYPE")
  private VPSubmissionDTO parseSubmission(final HttpServletRequest request)
          throws IOException {
      VPSubmissionDTO dto = new VPSubmissionDTO();
      String contentType = request.getContentType();
+     // Normalize to lowercase for safe comparison
+     String normalizedType = contentType != null
+             ? contentType.toLowerCase(java.util.Locale.ENGLISH) : "";
-     if (contentType != null && contentType.contains(...FORM)) {
+     if (normalizedType.contains("application/x-www-form-urlencoded")) {
          parseFormEncodedSubmission(request, dto);
-     } else if (contentType != null && contentType.contains(...JSON)) {
+     } else if (normalizedType.contains("application/json")) {
          dto = parseJsonSubmission(request);
      } else {
          parseFormEncodedSubmission(request, dto);
      }
      return dto;
  }
```

---

#### W2: `SERVLET_PARAMETER` (line 254) on [getDecodedParameter](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#247-286)

**Root cause:** `request.getParameter()` returns untrusted user input that is returned directly. SpotBugs flags this because the value could be used in security-sensitive operations.

**Fix:** Sanitize the parameter value (strip control characters, limit length) before returning it.

```diff
- @SuppressFBWarnings("SERVLET_PARAMETER")
  private String getDecodedParameter(final HttpServletRequest request,
          final String paramName) {
      String value = request.getParameter(paramName);
      if (StringUtils.isNotBlank(value)) {
+         // Limit input length to prevent abuse
+         if (value.length() > MAX_PARAM_LENGTH) {
+             value = value.substring(0, MAX_PARAM_LENGTH);
+         }
          try {
              String decodedValue = URLDecoder.decode(value, ...);
              // ... existing sanitization for vp_token ...
              return decodedValue;
          } catch (Exception e) {
-             return value;
+             return sanitize(value);
          }
      }
      return value;
  }
```

Add a constant and a private [sanitize](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#1125-1137) helper that strips CRLF and control characters.

---

#### W3: `XSS_SERVLET` (line 332) on [sendSuccessResponse](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#325-358)

**Root cause:** Writing JSON to `response.getWriter()` — SpotBugs warns that user-derived data in the JSON could result in XSS.

**Fix:** The response is JSON with `Content-Type: application/json`, so XSS is not actually exploitable via browser rendering. However, the proper fix is to ensure the JSON values are constructed safely (they already are — `submission.getSubmissionId()` and `submission.getTransactionId()` are server-generated via `Gson.toJson()`). Set `X-Content-Type-Options: nosniff` to prevent browser MIME sniffing.

```diff
- @SuppressFBWarnings("XSS_SERVLET")
  private void sendSuccessResponse(...) throws IOException {
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("application/json;charset=UTF-8");
+     response.setHeader("X-Content-Type-Options", "nosniff");
      // ... build responseObj from server-generated values only ...
      try (PrintWriter writer = response.getWriter()) {
          writer.write(responseJson);
      }
  }
```

---

#### W4: `XSS_SERVLET` (line 368) on [sendErrorResponse](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#359-389)

**Root cause:** `errorDescription` could originate from user input (validation exception messages).

**Fix:** Sanitize `errorCode` and `errorDescription` before writing them into the response. Set `X-Content-Type-Options: nosniff`.

```diff
- @SuppressFBWarnings("XSS_SERVLET")
  private void sendErrorResponse(...) throws IOException {
      response.setStatus(statusCode);
      response.setContentType("application/json;charset=UTF-8");
+     response.setHeader("X-Content-Type-Options", "nosniff");
      JsonObject errorObj = new JsonObject();
-     errorObj.addProperty("error", errorCode);
+     errorObj.addProperty("error", sanitize(errorCode));
      if (StringUtils.isNotBlank(errorDescription)) {
-         errorObj.addProperty("error_description", errorDescription);
+         errorObj.addProperty("error_description",
+                 sanitize(errorDescription));
      }
      // ...
  }
```

The [sanitize](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/OpenID4VPAuthenticator.java#1125-1137) method strips HTML tags and control characters.

---

#### W5: `SERVLET_HEADER` (lines 396, 407) on [getTenantId](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#88-112) and [getTenantDomain](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#401-415)

**Root cause:** `request.getHeader("X-Tenant-Domain")` returns untrusted input.

**Fix for [getTenantId](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#88-112):** This method delegates to `ServletUtil.getTenantId` which already doesn't use headers directly (it reads from the identity framework context and request attributes). Remove the `@SuppressFBWarnings` — it's not needed.

**Fix for [getTenantDomain](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/servlet/VPSubmissionServlet.java#401-415):** Validate the header against the WSO2 tenant domain format (alphanumeric + dots).

```diff
- @SuppressFBWarnings("SERVLET_HEADER")
  private int getTenantId(final HttpServletRequest request) {
      return ServletUtil.getTenantId(request);
  }

- @SuppressFBWarnings("SERVLET_HEADER")
  private String getTenantDomain(final HttpServletRequest request) {
      String tenantDomain = request.getHeader("X-Tenant-Domain");
-     if (StringUtils.isNotBlank(tenantDomain)) {
+     if (StringUtils.isNotBlank(tenantDomain)
+             && tenantDomain.matches("^[a-zA-Z0-9._-]+$")) {
          return tenantDomain;
      }
      return "carbon.super";
  }
```

---

### ServletUtil.java

---

#### W6: `SERVLET_PARAMETER` (lines 46–49, 57, 68–71) on [isLongPollingEnabled](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#40-61) and [getTimeoutSeconds](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#62-87)

**Root cause:** `request.getParameter()` returns untrusted input compared/parsed directly.

**Fix:** The values are already validated — [isLongPollingEnabled](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#40-61) compares against `"true"`/`"1"`, and [getTimeoutSeconds](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#62-87) parses with `Long.parseLong` inside a try/catch with range validation. The actual risk is already mitigated. Simply remove the suppressions, as the fixes are already in place.

#### W7: `SERVLET_HEADER` (line 94) on [getTenantId](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#88-112)

**Root cause:** `request.getAttribute("tenantDomain")` — this is actually an attribute, not a header. SpotBugs may be over-flagging. The value is also validated through `IdentityTenantUtil.getTenantId()` which will throw for invalid domains.

**Fix:** Add a tenant domain format check before passing to [getTenantId()](file:///Users/udeepa/Desktop/VC/repos/identity-openid4vc/components/org.wso2.carbon.identity.openid4vc.presentation.authenticator/src/main/java/org/wso2/carbon/identity/openid4vc/presentation/authenticator/util/ServletUtil.java#88-112).

```diff
- @SuppressFBWarnings("SERVLET_HEADER")
  public static int getTenantId(final HttpServletRequest request) {
      String tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
      if (StringUtils.isBlank(tenantDomain)) {
-         tenantDomain = (String) request.getAttribute("tenantDomain");
+         Object attr = request.getAttribute("tenantDomain");
+         tenantDomain = (attr instanceof String) ? (String) attr : null;
      }
-     if (StringUtils.isNotBlank(tenantDomain)) {
+     if (StringUtils.isNotBlank(tenantDomain)
+             && tenantDomain.matches("^[a-zA-Z0-9._-]+$")) {
          try {
              return IdentityTenantUtil.getTenantId(tenantDomain);
```

---

## Summary

| # | Warning | File | Fix Strategy |
|---|---------|------|-------------|
| W1 | `SERVLET_CONTENT_TYPE` | VPSubmissionServlet | Normalize + compare against allowlist |
| W2 | `SERVLET_PARAMETER` | VPSubmissionServlet | Max length limit + sanitize helper |
| W3 | `XSS_SERVLET` | VPSubmissionServlet | `X-Content-Type-Options: nosniff` |
| W4 | `XSS_SERVLET` | VPSubmissionServlet | Sanitize error strings + nosniff |
| W5 | `SERVLET_HEADER` | VPSubmissionServlet | Remove (not needed) + regex validate |
| W6 | `SERVLET_PARAMETER` | ServletUtil | Remove (already validated) |
| W7 | `SERVLET_HEADER` | ServletUtil | Type-check + regex validate |

## Verification Plan

### Automated Tests
```bash
mvn compile -pl components/org.wso2.carbon.identity.openid4vc.presentation.authenticator -am
```
- Verify zero new SpotBugs warnings after suppression removal
