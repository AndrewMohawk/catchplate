# Original-only committed-consumption verification

This source slice verifies original committed consumption for the future release
path. It is **unbuilt and unexecuted**. It neither releases a token nor bridges
completion-purpose keys into release authority. Fresh release intent, this
committed-original admission, the distinct release-purpose proof, durable exact
outcome and guarded plaintext egress remain separate obligations.

## Independent inputs, one genuine replay

`authority_oidc_session_activation_release_committed._verify_on_work` accepts
only original packet/completion/ACK bytes, independently held expectations and
pins, actual public keys, the actual completion custodian and fixed commit
reader, and the caller's current work/window/deadline. Its keyword-only inputs
are:

```text
packet_bytes, completion_request_bytes, state_receipt_bytes,
expected_consume_binding, expected_release, expectations,
planner_public_key, operation_public_key, root_public_key,
authorization_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
current_root_enrollment_bytes, configuration_digest,
expected_authorization_digest, expected_database_id, expected_generation_digest,
expected_pending_sequence, expected_pending_head_digest, expected_fence,
historical_custody, commit_reader, live_window, transport_deadline_ns, work
```

The bounded input helper owns all external graphs before callbacks. The seven
supplied byte originals have their actual per-format limits and a combined
64 MiB ceiling before decoding. The independently expected six-field release
scope is the same shape as [release intent](oidc-session-activation-release-intent.md);
its five `consumeBinding` identities must equal the separately supplied binding.
Neither expected data nor a successful result object substitutes for originals.

The verifier follows this fixed sequence:

1. Require the exact process-bound completion custodian at UID/GID 65497, bind
   its genuine root/current-root enrollment, and preserve its fresh current
   allowance. The existing release custodian and live SQL/grant roles cannot
   stand in for this owner.
2. Decode the dedicated consume packet under independent packet and pending
   identities. Match its retained state, grant and caller enrollment originals
   and caller authorization byte-for-byte to independently supplied originals.
3. Invoke genuine consume completion admission **once**: actual historical
   caller/grant/plan/state/provenance/private effects and pending originals are
   replayed. Match the complete stored packet, vectors, result and effects to
   that same-call admission.
4. Read through the real fixed `CurrentRootCommitReader` configuration. Its
   read-only observation returns only after normal connection/cursor closure.
   Match the actual immutable marker and complete after-vector bytes and digest
   to the genuine replay. A supplied marker or reader callback is not accepted.
5. Verify the original complete control and state ACK signatures, exact request
   identity and independently held pending ancestry. Match every shared
   completion/marker field and the exact canonical inner observation to the
   same candidate; do not call the whole completion-response verifier or replay
   the private originals again.
6. Compare all five derived consumption identities to independent pins. Only
   then compare the authenticated packet's target/effects to the expected
   release scope, and join all four full predecessor-provenance values: actual
   activation request digest, delivery ID, delivery-scope digest and encrypted
   delivery-envelope digest. A deterministic truncated delivery ID alone cannot
   establish the full activation request's provenance.

The target helper performs ordinary data comparisons, not admission. Its inputs
are useful only here after genuine original replay, custody matching and actual
commit/ACK joins. It opens no ciphertext and performs no second semantic replay.

## Current processing, historical facts

The supplied opening sample and cumulative work are never replaced. The
custodian and enrolled control policy may only narrow the processing window
and deadline. Sticky guards retain the original and narrower clock histories,
check the exact owner/process and immutable reader configuration throughout,
and cover the final result. Historical plan/completion intervals remain
authenticated historical data, not invented current clock samples or renewed
execution authority. An acknowledged head is not an off-host latest-head
witness or proof of present session state.

The private result `_CommittedOriginals` contains only `consume_binding`,
`release_binding`, original `completion_request_bytes`, original
`state_receipt_bytes`, the genuine `state_receipt_digest`, and a current-only
`live` guard. These are ordinary same-call outputs; this verifier accepts no
such result as an input proof. It accepts neither a signing key nor a release
AES key, writes no SQL or outcome store, and grants no retry or plaintext egress.
The distinct completion-to-release proof, durable outcome/recovery and cold
handoff remain later work. Nothing is installed, provisioned or runtime-verified
by this source change.
