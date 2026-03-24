# OpenID4VC Presentation Common Component

The `org.wso2.carbon.identity.openid4vc.presentation.common` component serves as the foundational library for the OpenID4VP (OpenID for Verifiable Presentations) implementation within WSO2 Identity Server. 

It does not contain active services, Servlets, or business logic workflows themselves. Instead, it centralizes all shared Data Transfer Objects (DTOs), Data Models, Exceptions, Constants, and Utility functions required by the other OpenID4VP presentation components (such as `authenticator`, `did`, and `verification`).

## Directory Structure

The codebase is organized into the following key packages:

### `1. constant/`
Contains static constants used globally across the OpenID4VP feature.
- **`OpenID4VPConstants.java`**: The primary constants file. It defines strings for JSON keys, error codes, caching configurations, supported formats (e.g., `jwt_vc`, `jwt_vc_json`, `ldp_vp`), and standard OpenID4VP protocol parameters.

### `2. dto/`
Data Transfer Objects (DTOs) used for API requests, responses, and cross-component data passing. These objects map directly to the JSON payloads defined in the OpenID4VP specification.
- **`VPRequestCreateDTO.java` & `VPRequestResponseDTO.java`**: Used when initiating a new Verifiable Presentation request.
- **`VPSubmissionDTO.java`**: Represents the payload received from a digital wallet containing the Verifiable Presentation token and submission definitions.
- **`PresentationSubmissionDTO.java`**: Represents the `presentation_submission` object within a VP response.
- **`DescriptorMapDTO.java` & `PathNestedDTO.java`**: Used to map specific claims within a VP token back to the requested Presentation Definition.
- **`VCVerificationResultDTO.java` & `VPVerificationResponseDTO.java`**: Used to encapsulate the results of validating a Verifiable Credential or Presentation.

### `3. exception/`
Custom checked and unchecked exceptions for error handling.
- **`VPException.java`**: The base exception class for the OpenID4VP implementation. All other custom exceptions inherit from this or standard Java exceptions.
- **`VPRequestNotFoundException.java` & `VPRequestExpiredException.java`**: Thrown when an invalid or timed-out request ID is referenced.
- **`CredentialVerificationException.java`**: Thrown when a Verifiable Credential fails signature or status validation.
- **`DIDResolutionException.java` & `DIDDocumentException.java`**: Thrown when resolving a Decentralized Identifier (DID) fails.

### `4. model/`
Internal DOM representations of core OpenID4VP schema entities.
- **`VerifiableCredential.java` & `VerifiablePresentation.java`**: The core models parsing the W3C Verifiable Credentials Data Model. They securely hold properties like `issuer`, `issuanceDate`, `expirationDate`, `credentialSubject`, and `proof`.
- **`VPRequest.java`**: Represents an active OpenID4VP transaction within the Identity Server.
- **`VPSubmission.java`**: An internal domain model representing an incoming wallet submission.
- **`PresentationDefinition.java`**: Represents the requirements demanded by the verifier (Identity Server) from the wallet.

### `5. util/`
Shared utility classes providing common reusable logic.
- **`OpenID4VPUtil.java`**: General utility methods.
- **`PresentationDefinitionUtil.java`**: Logic for building and parsing Presentation Definition JSON strings securely.
- **`CORSUtil.java`**: Utilities for handling Cross-Origin Resource Sharing logic for OpenID4VP endpoints.
- **`SecurityUtils.java`**: Security features, typically handling XML/JSON parsing safely to prevent XXE or injection attacks.
- **`URLValidator.java`**: Utility to validate URLs and prevent SSRF vulnerabilities during presentation flows.

## How it Connects with Other Components

This component is defined as a Maven dependency in the `pom.xml` of all other presentation-focused modules:
- **`presentation.authenticator`**: Uses the `model` and `dto` classes to persist `VPRequest`s to the database and map HTTP requests to `VPSubmissionDTO` objects.
- **`presentation.verification`**: Consumes configurations from `OpenID4VPConstants`, outputs `VCVerificationResultDTO`s, and throws `CredentialVerificationException`s.
- **`presentation.did`**: Throws `DIDResolutionException`s and constructs `DIDDocument` models based on the classes provided here.

In summary, the `presentation.common` component strictly adheres to the **DRY (Don't Repeat Yourself)** principle by guaranteeing that schemas like `VerifiableCredential` and protocol constants are identical across all independently compiled OpenID4VC bundles.
