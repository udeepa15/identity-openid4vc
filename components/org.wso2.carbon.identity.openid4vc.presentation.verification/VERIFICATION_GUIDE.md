# Verification Service Usage Guide

This guide explains how to integrate and use the `VerificationService` from a WSO2 Identity Server authenticator (e.g., an OID4VP authenticator).

## 1. Maven Dependency

Add the following dependency to your authenticator's `pom.xml`:

```xml
<dependency>
    <groupId>org.wso2.carbon.identity.openid4vc</groupId>
    <artifactId>org.wso2.carbon.identity.openid4vc.presentation.verification</artifactId>
    <version>${project.version}</version>
</dependency>
```

## 2. OSGi Service Reference

To use the service in your authenticator, you should first register it as a reference in your Service Component class.

### Option A: Using Declarative Services (Recommended)

In your internal data holder or service component class:

```java
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;

private static VerificationService verificationService;

@Reference(
    name = "openid4vc.presentation.verification.service",
    service = VerificationService.class,
    cardinality = ReferenceCardinality.MANDATORY,
    policy = ReferencePolicy.DYNAMIC,
    unbind = "unsetVerificationService"
)
protected void setVerificationService(VerificationService verificationService) {
    AuthenticatorDataHolder.getInstance().setVerificationService(verificationService);
}

protected void unsetVerificationService(VerificationService verificationService) {
    AuthenticatorDataHolder.getInstance().setVerificationService(null);
}
```

### Option B: Manual Retrieval (If outside OSGi context)

```java
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.context.PrivilegedCarbonContext;

VerificationService verificationService = (VerificationService) PrivilegedCarbonContext
        .getThreadLocalCarbonContext().getOSGiService(VerificationService.class, null);
```

## 3. Invoking the Verification Service

### Entry Point Class
`org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService`

### Imports
```java
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
```

### Method Signature
```java
VerificationResult verify(PresentationSubmission submission, int tenantId, String vpToken) 
        throws VerificationException;
```

### Example Usage

```java
try {
    // 1. Prepare the PresentationSubmission object (usually parsed from the VP response)
    PresentationSubmission submission = new PresentationSubmission();
    submission.setDefinitionId("my-presentation-definition-id");
    
    // Add descriptor map entries matching the formats in the VP
    PresentationSubmission.DescriptorMap descriptor = new PresentationSubmission.DescriptorMap();
    descriptor.setId("credential-1");
    descriptor.setFormat("vc+sd-jwt"); // or "jwt_vp"
    descriptor.setPath("$");
    submission.setDescriptorMap(Collections.singletonList(descriptor));

    // 2. Call the verification service
    VerificationResult result = verificationService.verify(submission, tenantId, vpToken);

    // 3. Handle the results
    if (VerificationResult.VerificationStatus.VERIFIED.equals(result.getStatus())) {
        Map<String, Object> claims = result.getVerifiedClaims();
        String subject = (String) claims.get("sub");
        // Proceed with authentication...
    } else {
        // Handle failed verification
    }
} catch (VerificationException e) {
    // Handle specific verification errors (e.g., invalid signature, expired, etc.)
}
```

## 4. Understanding the Results

The `VerificationResult` object contains:

| Method | Return Type | Description |
| :--- | :--- | :--- |
| `getStatus()` | `VerificationStatus` | Returns `VERIFIED`, `FAILED`, `PENDING`, or `SUBMITTED`. |
| `getVerifiedClaims()` | `Map<String, Object>` | A map of claims that have been successfully verified against the VC. For SD-JWTs, this includes all disclosed claims. |

### Error Handling
The service throws `VerificationException` (and its subclasses `VerificationClientException` or `VerificationServerException`). You can check the error code using `e.getErrorCode()`.
