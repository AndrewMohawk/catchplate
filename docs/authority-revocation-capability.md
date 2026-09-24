# Original signed revocation capability

## Status and boundary

Source `.45` adds an inactive original-byte capability verifier and PostgreSQL
custody schema. The source is **unbuilt and unexecuted**. It does not install a
successor issuer or executor, grant issuer table privileges, open a public
revocation route, or establish an independently operated witness service.

Source `.47` adds a private producer that signs only after genuine retained and
witness verification, plus original witness-request preservation in the service;
see [original-byte signing](authority-revocation-signing.md). The producer is
not a configured issuer or storage path, and does not open these gates.

The private verifier accepts original signed capability, signed planner,
evaluation-context, execution-request and signed preliminary witness-request
bytes. It authenticates the capability and both witness documents, replays the
genuine retained plan exactly once, and compares the complete capability to
that result. A returned Python observation is not a reusable approval input.

## Non-circular approval order

```mermaid
flowchart LR
    W[Signed preliminary witness reservation] --> P[Signed retained plan]
    P --> E[Exact execution-request reservation]
    E --> C[Signed capability binding plan and request]
    C -. required future step .-> B[Witness binds actual capability digest]
    B -. required future step .-> X[Current-state admission and one-use execution]
```

The capability preserves the original preliminary `reserve` receipt. It does
not relabel that receipt as post-plan approval. A separate future witness
plan-binding step must commit the actual capability digest, retained record,
root transition and exact execution request before execution. Making the
capability signature depend on a witness signature that already commits the
same capability would create a circular dependency.

## Wire contracts

[`authority_revocation_capability.py`](../serverware/authority_revocation_capability.py)
defines a closed five-field signed envelope:

```text
schema, sourceRevision, signerIdentity, payload, signatureBase64Url
```

Its schema is `serverware.signedPolicyAuthorityDatabaseCapability/v4`. The
signature covers the four unsigned fields, including source and signer
identity, using the NUL-domain-framed canonical document digest. Identity is
the existing three-field session/measurement/attestation identity.

The payload uses `serverware.policyAuthorityDatabaseCapability/v4`: the
existing thirty-two capability fields with the new schema, plus
`planProtocol`, `retainedRecordDigest`, `rootTransitionDigest` and
`exactRequestBytesDigest`. The protocol is `revocation-v4`, and the operation
is only `webauthn.credential.revoke`.

The verifier derives all plan commitments and the exact five-field execution
wrapper from genuine retained replay. The wrapper's original SHA-256 is
distinct from the typed operation's semantic request digest. Original issuance
times are tied to the retained reservation: epoch issuance is its reservation
epoch; monotonic issuance is the monotonic deadline minus the reserved epoch
interval. No current clock is sampled or inferred from stored context.

All inputs must be exact immutable `bytes`. Capability and execution wrapper
are bounded by 4 MiB each; the original signed witness request by 64 KiB;
planner envelope and evaluation context retain their 64 MiB and 512 KiB limits.
Capability/witness JSON is bounded to 4,096 nodes and depth 16. Canonical ASCII
wire spelling, duplicate decoded keys and token types are checked before the
respective signatures. These ceilings do not grant another invocation budget:
capture, scans, copies, encoding, comparisons, hashes and retained proof replay
spend the same existing cumulative work allowance.

### Witness and WebAuthn compatibility

The sixteen-field original signed witness request and twenty-one-field receipt
retain their v2 schemas. The original request is necessary to authenticate the
configuration commitment, which the receipt alone does not expose. The
verifier checks request/receipt identities, generation, operation, deadline,
fence, canonical request digest, witness head and both real Ed25519 signatures.
An independently accepted full receipt digest pins the preliminary reservation;
valid historical signatures are not evidence of current witness state.

An independently admitted authority-verifier signer key authenticates the
capability and original witness request; a separately admitted witness key
authenticates the receipt. Retained planner/assertion keys keep their own
independent inputs. The component does not enroll these keys or prove their
live service roles from signature validity.

The capability preserves the existing nineteen-field
`serverware.policyAuthorityWebAuthnReceipt/v1`. That receipt is reconstructed
from genuine retained assertion evidence and proved OLD challenge/credential
rows; it is not the full signed assertion-evidence document. The thirteen-field
credential binding retains the historical **length-prefixed domain** recipe,
whereas challenge-row, receipt and capability digests use NUL-domain framing.
Two SQL consumers now use the existing length-domain helper to match the
unchanged service producer; accepting both digest recipes is not permitted.

## Immutable custody

The verifier returns a seventeen-field retained-capability header and its
domain-framed record digest, original transports, independently admitted key
fingerprints, genuine retained observation and per-phase/cumulative metrics.
The original signed capability and original signed witness-request byte hashes
are distinct from their semantic document commitments.

| Stored boundary | Binding | Limitation |
| --- | --- | --- |
| Writer capability and immutable sidecar | Symmetric deferred five-column keys: capability ID, protocol, record digest, planner transaction, execution envelope | Does not verify signatures |
| Sidecar and retained planner record | Deferred transaction/protocol/record-digest key | Planner capability ID still needs genuine verifier/issuer comparison |
| Sidecar and execution envelope | Deferred envelope primary-key reference | Mutable execution bindings still need comparison on every use |

`policy_authority_revocation_retained_capabilities` stores twenty closed
columns, including original canonical base64url transports, their counts and
byte digests. Its UPDATE and DELETE guards preserve all original columns.
The writer parent gains `capability_protocol` (legacy default `v3`) and
`capability_record_digest`. Every v4 status requires its retained record; v3
must not have one. Protocol cannot change after insertion.

For v4 parents, thirty-five initial identity fields are immutable. Reservation
token/time/transaction fields freeze once set. Issued rows can reserve, commit,
expire or fail; reserved rows can commit or expire. Committed rows may become
reconciled by status-only change; reconciled, expired and failed lifecycle
data are terminal. Legacy v3 lifecycle behavior is unchanged. SQLite refuses
successor custody. Existing stores require a separately reviewed migration;
missing original evidence cannot be synthesized or recovered by dropping rows.

## Authored controls and remaining work

The pure fixture independently constructs real signed documents, genuine
retained proofs, the service-compatible receipt and original-byte digests. It
does not run a witness journal, authenticate a physical hardware key, enroll
production identities or establish a post-plan witness approval.

Four native component methods use the actual production DDL and guards with
explicitly opaque transport bytes. They cover deferred bindings, closed
protocol/transport shapes, immutable identity and lifecycle/rollback behavior.
They are not cryptographic admission, live ACLs or top-level commit evidence.
The existing serializer method additionally pins the credential-binding recipe
against the real SQL helper. All controls remain authored and unexecuted.

The next private issuer boundary must preserve original signed transport and
establish its serializable writer transaction before the first database read.
Source `.46` corrects the existing connector's pre-read transaction setup and
the installed-five-argument versus granted-four-argument mismatch; see the
[issuer database boundary](authority-issuer-database-boundary.md). The connector
still forbids direct table authority, and the planner-writer-only retained
reader is not an issuer API. Narrow source-fixed definer load/store functions
still need coordinated signature/owner/search-path/EXECUTE admission, without
table grants. Successor lock order
must reconcile the current executor's fence/capability/execution/planner order
with the private reservation's planner/execution order before activation.

Configured successor issuance/storage/replay boundaries, post-plan witness binding,
current roots and deadlines, mixed-root SQL execution, atomic terminal
publication and public operation admission remain required. The closed
`webauthn.trust.stage`, `webauthn.trust.complete`,
`webauthn.registration.finalize` and `webauthn.credential.revoke` gates are not
opened by this checkpoint. Follow the freeze/preparation/verification workflow
in [goal.md](../goal.md); neither source review nor a fixture count is a release.
