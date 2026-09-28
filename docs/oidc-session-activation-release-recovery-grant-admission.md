# Recovery grant original admission

`serverware/oidc_session_activation_release_recovery_grant_admission.py` is a
pure receiving boundary for one fresh recovery grant triple. It does not change
the existing LIVE profile, access a private outcome store, open a token, perform
an exchange, or authorize retries.

## Exact interface

`_verify_on_work` receives `response_originals`, `request_originals`, the four
independent originals `issuer_policy_bytes`, `release_custody_bytes`,
`proof_enrollment_bytes`, `intent_enrollment_bytes`, and the actual
`root_public_key`, `live_window`, `transport_deadline_ns`, `work`, with optional
restrictive `_continuity`. No successful material or decoded claims can replace
these inputs.

The response is exactly `(clientAuthorization, serverBootstrap, outcomeOriginal)`
with respective 16 KiB, 16 MiB and 64 KiB bounds. The request is the fixed recovery
prefix7: recovery purpose, signed proof, proof enrollment, signed intent, intent
enrollment, ephemeral old-token64, and encrypted envelope100. It contains no
candidate outcome. The shared original-only derivation authenticates historical
intent/proof/custody and old-token possession, then reconstructs the canonical
outcome and compares its identity with the independently signed policy pin.
Only then does it form the genuine recovery raw8 and request identity.

The receiver reuses that derivation, requires exact enrollment originals and
byte-equal returned outcome, and genuinely verifies the root-signed client and
nested server/storage/recovery originals. The independent expected client
scope17 fixes the RECOVERY profile, exact server original, actual raw8 identity,
producer/caller/client identities, target, state receipt, outcome and endpoint.
It additionally compares the entire storage scope (checkpoint record count one),
recovery scope, launch-resource pins and original custody. Client/server signed
intervals must remain within the independent policy interval; the original
delivery expiry is still a hard ceiling.

The immutable `_RecoveryGrantMaterial` returns the three exact response originals,
actual client and policy materials, and narrowed window/deadline/live guard.
It has no request or old-token field and is not accepted as authority input.
The original request is not retained by the returned closure.

## Bounds and continuity

Before nested admission, the receiver reserves all held originals, decoded
custody/storage/recovery originals, both independently decoded planner paths,
their state enrollments and complete-root vectors, and the reconstructed outcome.
Decoded sizes are capped by their actual enclosing signed-original byte lengths;
identical immutable input references count once for retained-byte capacity.
The fixed nested-original maxima total less than 17 MiB, while the fixed incoming
original maxima total less than 25 MiB, leaving more than 22 MiB of the unchanged
64 MiB ceiling before additional capture/comparison reservations.

A further conservative reservation covers eight custody-original sizes, four
other request/independent-original sizes, and two response-original sizes plus
the nested originals. Shared derivation separately reserves its read-only
outcome/raw8 path; it does not generate another server or client grant. The
signing producer alone reserves generated-grant output and readback capacity.
Measured finite scope graphs reserve comparison encodings before client/server
admission. Consequently some individually valid large originals are refused;
no maximum is increased and no new work allowance is created. This is a bounded
logical original/capture inventory, not a claim about Python allocator overhead.
Actual processing is still charged separately to the same cumulative work ledger.

The returned guard retains genuine policy/history and client/server children.
Nested verification receives only the ancestor `lifetime.continuity`, avoiding a
cycle through its own attached guard. All clocks and bounds only narrow; there
is no fresh processing window or recovered permission.

## Remaining authority boundary

A reconstructed outcome and a root-signed checkpoint-one expectation prove
neither that a private record exists nor that an earlier release completed.
The eventual genuine recovery owner must independently read and match its
protected durable outcome. This module does not supply independent policy
issuance, a cold acquisition service, durable response retention, protected
exchange, fresh current-auth, or guarded cookie delivery. Earlier-stage recovery
without a retained release intent also remains separate. See
[public recovery boundaries](oidc-session-activation-public-recovery.md).

This checkpoint is source-only: no build, execution, provisioning, or runtime
readiness evidence is claimed.
