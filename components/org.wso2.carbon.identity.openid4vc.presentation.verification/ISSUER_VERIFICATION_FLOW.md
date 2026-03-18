Issuer Verification in openid4vc.presentation.verification
=====================================================

Component
---------
- Module: org.wso2.carbon.identity.openid4vc.presentation.verification
- Primary implementation: src/main/java/org/wso2/carbon/identity/openid4vc/presentation/verification/service/impl/VCVerificationServiceImpl.java

Overview
--------
Issuer verification is done in two layers:

1) Cryptographic issuer proof verification
   - The service verifies that the credential is signed by a key that belongs to the claimed issuer.
   - This is done through format-specific signature verification paths.

2) Optional policy-level issuer matching (presentation-definition driven)
   - When a presentation definition includes issuer constraints, the service checks that the VC issuer claim
     matches the trusted issuer host configured in requested_credentials.


A. Entry points that trigger issuer verification
-----------------------------------------------

A1) verify(String vcString, String contentType, int vcIndex)
    -> parseCredential(...)
    -> verifyCredentialInternal(...)

A2) verifyJWTVCIssuer(String vcJwt, String tenantDomain)
    -> validates JWT shape
    -> delegates to verify(vcJwt, "application/vc+jwt")

A3) verifyJSONLDVCIssuer(JsonObject vcJsonObject, String tenantDomain)
    -> validates issuer field exists and has supported JSON type
    -> delegates to verify(vcString, "application/vc+ld+json")

A4) verifySdJwtToken(...)
    -> parses SD-JWT
    -> verifies issuer JWT signature via verifySignature(paramCred)
    -> then performs SD disclosure + key-binding checks

A5) Unified VP entry: verifyPresentation(vpToken, submissionJson, presentationDefinitionId, tenantId)
    -> routes by detected format
    -> SD-JWT path: verifySdJwtPresentation -> verifySdJwtToken
    -> JWT/JSON-LD VP path: verifyJwtOrJsonLdPresentation -> verifyVPToken
    -> optional issuer policy check via verifyClaimsAgainstDefinition


B. Core issuer signature verification logic
-------------------------------------------
Method: verifySignature(VerifiableCredential credential)
- Dispatches by VC format:
  - JWT -> verifyJwtSignature
  - SD-JWT -> verifySdJwtSignature (issuer-jwt segment only)
  - JSON-LD -> verifyJsonLdSignature


B1) JWT / SD-JWT issuer verification: verifyJwtSignature(...)
-------------------------------------------------------------

Input assumptions:
- raw credential is compact JWT (3 dot-separated parts)

Process:
1. Parse JOSE header.
   - Reads alg (defaults to RS256 if absent)
   - Reads kid if present

2. Resolve issuer identity source.
   - Primary source: credential.getIssuerId()
   - Fallback for DID issuers: if issuerId missing/non-DID, derive issuer DID from kid when kid starts with did:

3. Resolve issuer public key and verify signature using one of these branches:

   Branch 1: DID issuer (issuer starts with "did:")
   - If kid is a DID URL with fragment (#), use didResolverService.getPublicKeyFromReference(kid)
     (ensures exact key selection in multi-key DID documents)
   - Else use didResolverService.getPublicKey(issuer, null)
   - Verify JWS signature with signatureVerifier.verifyJwtSignature(rawCredential, publicKey, alg)

   Branch 2: HTTP(S) issuer URL
   - Resolve jwks_uri using resolveJwksUri(issuer)
   - Use extendedJWKSValidator.validateSignature(rawCredential, jwksUri, alg)

   Branch 3: Unsupported issuer format
   - Throws error: issuer must be DID or HTTP(S) URL with discoverable JWKS


B2) HTTP issuer -> JWKS resolution: resolveJwksUri(...)
--------------------------------------------------------

Resolution order:
1. Try OID4VCI issuer metadata endpoint:
   <issuer>/.well-known/openid-credential-issuer
2. If missing/unavailable, try OIDC metadata endpoint:
   <issuer>/.well-known/openid-configuration
3. If metadata has jwks_uri, return it.
4. Else if authorization_servers exists:
   - take first authorization server
   - fetch its OIDC metadata
   - return jwks_uri when present
5. If nothing resolves, return null.

Transport guardrails in fetchJson(...):
- Only http/https schemes allowed
- Host must be non-null
- GET with connect/read timeouts
- Non-200 responses are treated as missing metadata


B3) SD-JWT issuer verification details: verifySdJwtToken(...)
--------------------------------------------------------------

Issuer-specific checks in this path:
1. Issuer JWT signature validity
   - Builds temporary JWT credential from SD-JWT first segment
   - Sets issuer claim from parsed JWT
   - Calls verifySignature(paramCred), which reuses verifyJwtSignature

2. Issuer JWT temporal validity
   - Checks exp and nbf against current time

3. Disclosure integrity against issuer _sd digests
   - Computes digest per disclosure
   - Reconstructs disclosed claims only for matching digests

4. Holder binding continuity to issuer token
   - Validates KB-JWT sd_hash equals hash(issuerJWT + disclosures)
   - Verifies KB-JWT signature using holder key from issuer claim cnf.jwk


B4) JSON-LD issuer verification: verifyJsonLdSignature(...)
------------------------------------------------------------

Process:
1. Reads proof.verificationMethod
2. Derives DID from verification method
3. Resolves public key via didResolverService.getPublicKey(did, verificationMethod)
4. Uses proofValue (or proof.jws fallback)
5. Verifies Linked Data proof with signatureVerifier.verifyLinkedDataSignature(...)

Note:
- This path ties trust to the DID key resolution for the verification method.


C. Policy-level issuer constraint enforcement
---------------------------------------------
Method: verifyClaimsAgainstDefinition(Map<String,Object> claims, String presentationDefinitionJson)

When presentationDefinitionJson has requested_credentials:
- Reads credentialReq.issuer as expected issuer policy value
- Reads actual issuer from claims.iss, fallback claims.issuer
- Compares by hostname only using issuerHostMatches(expected, actual)

Hostname normalization behavior:
- Full URL -> URI host extracted
- Bare host -> used directly
- did:web:<host>[:path] -> host extracted from DID method-specific identifier
- Comparison is case-insensitive

Effect:
- If hosts mismatch, verification fails even if signature is cryptographically valid.


D. What is and is not currently enforced
----------------------------------------

Enforced:
- VC signature is bound to issuer-controlled key material (DID or discovered JWKS).
- SD-JWT issuer token + disclosures + holder key binding consistency.
- Optional issuer host policy from Presentation Definition requested_credentials[].issuer.

Not explicitly enforced in these methods:
- tenantDomain-specific issuer allowlist lookup (tenantDomain parameter is currently not used in verifyJWTVCIssuer / verifyJSONLDVCIssuer).
- Strong semantic checks on issuer claim content beyond format/type and policy matching when provided.


E. Quick decision tree
----------------------

If credential is JWT:
  issuer is did:* ?
    yes -> resolve DID key -> verify signature
    no  -> issuer is http(s) ?
             yes -> discover jwks_uri -> verify signature
             no  -> fail

If credential is SD-JWT:
  verify issuer-jwt using same JWT issuer flow above
  verify exp/nbf
  verify disclosures vs _sd
  verify kb-jwt signature and sd_hash

If credential is JSON-LD:
  resolve key from proof.verificationMethod DID
  verify linked-data proof

If presentation-definition has requested_credentials[].issuer:
  normalize expected + actual issuer to host
  require host equality


F. Related classes involved
---------------------------
- VCVerificationServiceImpl
- ExtendedJWKSValidator
- DIDResolverService / DIDResolverServiceImpl
- SignatureVerifier
- PresentationDefinitionUtil / PresentationDefinitionService (for PD resolution)


G. Operational implications
---------------------------
- DID documents with multiple keys are handled more safely when kid is a full DID URL (#fragment).
- HTTP issuer verification depends on well-known metadata/JWKS availability.
- Issuer policy checks are strongest when presentation definitions include requested_credentials[].issuer.
- For strict tenant trust, an explicit tenantDomain-aware allowlist check should be added at service level.
