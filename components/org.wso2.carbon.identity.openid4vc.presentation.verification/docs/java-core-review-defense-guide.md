# Java Core Review Defense Guide (Beginner → Expert)

This guide is a practical checklist of Java knowledge to defend technical decisions in a code review.

---

## 1) Beginner Foundation (must know without hesitation)

## 1.1 Java basics
- Primitive types vs reference types
- `String` immutability and why it matters
- Operators, control flow, loops
- Methods: parameters, return values, overloading
- Packages, imports, visibility

## 1.2 Object-oriented fundamentals
- Encapsulation: private fields + controlled getters/setters
- Inheritance vs composition (prefer composition for flexibility)
- Polymorphism and interfaces
- Abstraction and contracts

## 1.3 Class design essentials
- Constructors and initialization rules
- `this` and `super`
- `static` vs instance members
- `final` for constants, classes, methods, and variables

## 1.4 Common review defense points
- Why immutable DTO returns are safer
- Why null checks exist at API boundaries
- Why input validation is done early (fail-fast)

---

## 2) Intermediate Java (review-ready engineering level)

## 2.1 Collections and generics
- `List`, `Set`, `Map` behavior and complexity basics
- `ArrayList` vs `LinkedList` tradeoffs
- `HashMap` vs `ConcurrentHashMap`
- Generic type safety and wildcard basics

## 2.2 Exceptions and error strategy
- Checked vs unchecked exceptions
- Designing domain exceptions (clear message + context)
- Wrapping lower-level exceptions while preserving cause
- Avoiding catch-all without meaningful action

## 2.3 `equals`, `hashCode`, `toString`
- Contract correctness
- Where they affect behavior (`HashSet`, `HashMap` keys)
- Defensive `toString()` for debugging/logging

## 2.4 Date/time and formatting
- Prefer modern time APIs; understand legacy `Date` interop
- UTC vs local timezone pitfalls
- Parsing tolerance and strictness tradeoffs

## 2.5 I/O and resources
- `try-with-resources`
- Stream reading safely
- Limits on payload size to prevent memory abuse

---

## 3) Advanced Java (defending architecture and correctness)

## 3.1 Concurrency and thread safety
- Race conditions and shared mutable state
- `volatile`, synchronized blocks, atomic classes
- Thread-safe collections (`ConcurrentHashMap`)
- Why immutability reduces concurrency bugs

## 3.2 JVM memory model & performance
- Stack vs heap basics
- Object allocation cost and garbage collection awareness
- Avoid premature optimization, but justify hot-path optimizations
- Big-O + practical performance reasoning

## 3.3 Functional style and streams
- Stream pipeline readability vs over-complex chaining
- Side-effect free transformations
- When classic loops are clearer than streams

## 3.4 Reflection and dynamic behavior
- When reflection is acceptable (test coverage, integration points)
- Security and maintainability caveats

## 3.5 Security-conscious Java
- Input sanitization and canonicalization
- Constant-time comparisons for sensitive data
- SSRF-safe outbound HTTP patterns
- Payload/decompression limits to prevent abuse
- Strict algorithm validation for crypto operations

---

## 4) Expert-Level Topics (strong defense in senior reviews)

## 4.1 API contract design
- Distinguish validation failures vs system failures
- Stable method signatures and backward compatibility
- Explicit behavior for null/empty/optional inputs

## 4.2 Domain modeling and boundaries
- DTO vs domain model separation
- Where to place orchestration vs utility logic
- Single responsibility per class/method

## 4.3 Failure semantics
- Recoverable vs unrecoverable failures
- Soft-fail vs hard-fail policies and why
- Propagating enough context for operators and callers

## 4.4 Testing strategy maturity
- Unit tests for deterministic logic
- Boundary and negative-path tests
- Contract tests for DTO/model behavior
- Avoiding brittle tests (implementation-detail coupling)

## 4.5 Maintainability metrics to defend
- Readability first
- Small focused methods
- Minimized duplicate parsing/work
- Defensive copying for mutable objects

---

## 5) Java language/tooling topics expected in modern code reviews

- Lambda expressions and method references
- `Optional` usage and anti-patterns
- Records, sealed classes, pattern matching (when project baseline allows)
- Maven lifecycle basics (`compile`, `test`, `verify`, `install`)
- Static analysis interpretation (SpotBugs/Checkstyle)

---

## 6) Crypto + verification specific Java knowledge (high priority for your component)

- JWS/JWT structure and signature verification flow
- Base64url decoding differences vs standard base64
- Hash algorithm mapping (`sha-256` → `SHA-256` etc.)
- Canonicalization concerns in linked-data signatures
- Public key types (`EC`, `RSA`, `OKP`) and algorithm compatibility
- Claim validation order (`exp`, `nbf`, `iat`, nonce, audience, hash linkage)

---

## 7) Code review defense script (fast, strong answers)

## Q: Why this null/blank validation?
A: Boundary validation prevents invalid state from entering deeper logic and reduces ambiguous failures.

## Q: Why custom exception types?
A: They encode domain semantics and keep caller handling explicit and predictable.

## Q: Why defensive copying in getters/setters?
A: It prevents external mutation of internal state and improves thread safety.

## Q: Why not throw immediately on every downstream failure?
A: Policy-dependent. Some checks are best-effort (e.g., optional checks), while cryptographic validity remains strict.

## Q: Why this cache?
A: To reduce repeated network/compute overhead while keeping bounded staleness via TTL.

## Q: Why constant-time comparisons?
A: To reduce timing side-channel leakage for security-sensitive comparisons.

---

## 8) Personal prep checklist (before review)

- Can explain `interface` contract vs implementation choices
- Can justify each exception path in core methods
- Can explain thread-safety assumptions for shared objects
- Can defend security controls with concrete threat examples
- Can map tests to behavior (happy path + negative path)
- Can state one known limitation and why it is acceptable

---

## 9) 30-minute revision plan

1. 5 min: OOP + collections + exceptions refresh
2. 5 min: concurrency + immutability + defensive copying
3. 5 min: JVM/performance basics + complexity reasoning
4. 10 min: crypto/JWT/JWS/claim validation order
5. 5 min: rehearse defense script Q&A

---

## 10) Final review posture

In review, keep answers in this structure:
1. **Intent** (what problem is solved)
2. **Safety** (how failures/attacks are handled)
3. **Correctness** (why logic is valid)
4. **Tradeoff** (what was chosen and why)
5. **Evidence** (tests/static checks)

If you use this structure consistently, your defense will sound senior and controlled.
