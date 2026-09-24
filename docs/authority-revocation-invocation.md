# Authenticated revocation issuer invocation

## Status and authority boundary

Source `.50` adds private original-byte signing and admission for a verifier-to-
issuer handoff, plus composition with `RevocationCapabilityIssuer`. The source
is **unbuilt and unexecuted**. No public service purpose or kernel is registered,
and no successful PostgreSQL admission, socket exchange or committed issuance
is claimed.

Source `.51` adds [private raw transport and configured service construction](authority-revocation-service-integration.md).
Public dispatch remains closed; these components do not establish end-to-end
serving or production verification.

An independently pinned verifier key authenticates the sender's historical
claims. Its signature does not prove root currentness, the physical origin of
a database clock, independent witness operation, or permission to execute a
revocation. The issuer still genuinely verifies the original capability,
witness and retained planner evidence against those claims before storage.

## Closed wire contract

The outer document preserves the existing eleven-field
`serverware.policyAuthorityInternalEnvelope/v3` schema and signing domain. Its
new fixed purpose is `issue-revocation-capability`; the legacy service purpose
allowlists do not accept it. This is not a widening of legacy admission.

The closed payload is
`serverware.policyAuthorityRevocationIssuanceInvocation/v1`. It binds the source
revision, generation sequence/digest, execution-envelope ID, accepted preliminary
witness receipt digest, original capability and witness-request transports with
exact byte counts, and fifteen historical expectations. Role keys, signer
identities, issuer pins and current policy are independently configured, not
replacement values carried by the request.

The historical map contains the existing request, capability/planner identities,
fence, reservation/deadline/evaluation times, assertion/plan-age/skew policy,
complete before-root vectors and optional approver-policy digest. Its database
instant uses exact integral UTC microseconds, not a floating-point timestamp.
The producer requires these values as caller inputs; it never recovers them
from stored evaluation-context bytes. Establishing their independent origin
and durable custody remains a service-integration requirement.

| Signed outer field | Required historical binding |
| --- | --- |
| `envelopeId` | Expected capability ID |
| `parentEnvelopeId` | Expected planner transaction ID |
| `fence` | Expected reservation fence |
| `deadlineMonotonicNs` | Original monotonic deadline |

The complete encoded wrapper is bounded by the existing 4 MiB request ceiling,
4,096 JSON nodes and the existing depth-128 signed-plan ceiling. Nested
capability and witness-request byte limits also remain in force. Decoding
rejects ambiguous/noncanonical JSON and noncanonical base64url; the wrapper
ceiling applies to the complete encoded document, not independently to each
operand. Signature verification uses the original canonical outer document.

## Producer, admission and configured issuer

```mermaid
flowchart LR
    A[Own original bytes and independent historical claims] --> S[Sign one closed invocation]
    S --> V[Authenticate original wire, configured pins and header joins]
    V --> I[Genuine capability, witness and retained-plan replay]
    I --> D[Exact SQL custody and readback before normal commit]
```

The private producer owns the input graph before key callbacks and reserves
bounded output work before signing. It signs claims for the issuer to check;
it does not replace capability production or declare supplied capability bytes
approved. No caller-selected signing or successful-verification callback is
accepted.

`RevocationCapabilityIssuer.issue_authenticated` accepts only original immutable
invocation bytes and the existing work object. It captures its eleven-setting
configuration before guarded current-clock callbacks. The configured verifier
key, configuration/generation commitments and issuer's current age/skew policy
bound raw invocation admission. Only after that succeeds can the existing real
issuer connector open. The unchanged store worker then performs its complete
verification and currentness checks, using the same remaining work.

The private test opener models an already admitted connection; it cannot prove
the real role or mTLS boundary. Normal pre-commit errors roll back, but commit or
connection-exit errors can leave an indeterminate outcome. The [issuer custody
contract](authority-revocation-issuance.md) records those transaction limits.

## Required remaining integration

The legacy internal verifier returns only payload and cannot substitute for
this original-byte, header-bound admission. Actual service transport dispatch
and its role/purpose gates still need coordinated integration. The existing
server parses JSON before dispatch; its byte-preserving helper also parses
before returning. Integration therefore needs bounded framing-only ingress
before this module's strict raw admission, not reconstruction of a parsed
request. The legacy service also issues a capability before reserving its
execution envelope; the successor must reserve that envelope before genuine
capability production and issuance.

The sender also needs independently admitted complete root inventory and an
authenticated planner-cutoff handoff. Private [original-byte admission](authority-revocation-handoff.md)
now authenticates that cutoff claim using the existing v4 signature and replays
the retained evidence; serving integration remains required. A business-only
root reader, a root list
copied from a signed plan, or matching database observations do not establish
that authority.

Original invocation bytes and independent historical inputs need durable retry
custody; this component does not add a journal or authorize re-signing on
restart. Post-plan witness binding of the actual capability, current-state
one-use execution and atomic terminal publication remain open. Production
Nitro/KMS, signing and independently operated witness infrastructure remain
unprovisioned. The source-freeze and single preparation/sequential no-build
workflow in [goal.md](../goal.md) still applies.
