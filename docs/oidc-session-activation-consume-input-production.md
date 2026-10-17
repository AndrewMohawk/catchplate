# Original-only consume-input issuance

`authority_oidc_session_activation_consume_input_production._produce_on_work`
produces exactly two root-signed originals: the consume planner bootstrap,
then its history-custody original. This is an issuance library, not an issuer
service, key owner, resource provisioner, public acquisition route or planner.
The implementation is source-only: unbuilt, unexecuted and unprovisioned.

## Independent authority and original request

The issuer receives its own root key pair, a signed
[consume-input issuer policy](../catchplate/oidc_session_activation_consume_input_issuer_policy.py),
and the exact historical activation planner bootstrap pinned by that policy.
The policy fixes the dedicated consume planner, history receiver and key
digests, database/read/TLS/state resources, launch pins, and independent
activation predecessor. A request cannot choose or override those inputs.

The request suffix is immutable raw16:

- Actual activation raw13: acknowledged completion raw4, signed activation
  plan, encrypted original bundle, reserve request, reserve ACK, snapshot,
  signed caller authorization, grant, caller enrollment and grant enrollment.
- Canonical original activation expectations and original complete before-vector.
- The exact old-token possession bytes, used ephemerally and never emitted,
  journaled or logged by this library.

The fixed transport adds its source-selected purpose to form raw17. Neither
framing nor an earlier successful admission object supplies authority.

## Genuine derivation and signing

The producer re-admits the fresh policy and its historical activation planner
original. It independently joins the expected subject and policy fields, exact
before-vector, signed caller authorization and known activation plan. The
actual historical grant verifier authenticates enrollment/signatures and the
exact caller, plan, encrypted frame and vector commitments.

The actual reservation records verifier authenticates reserve, snapshot and
ACK against the policy's predecessor. Signed COMPLETE and its state ACK are
joined to those originals, the exact canonical signed marker observation and
the full post-activation vector. An unsigned SQL observation is not an input
and cannot substitute for any of these checks.

Old-token possession must match the authenticated activation commitment. The
actual request-commitment and deterministic-ID algorithms derive the fixed
consume operation, delivery ID, typed request and six-field activation scope.
The genuine history-custody producer signs first; its exact original identity
then becomes the history pin in the genuine consume planner bootstrap producer.
Both originals receive genuine signature/readback admission before return.

The signed output interval is deterministic from the independent policy's
issue/expiry and the source/activation maximum-age caps. Historical activation
intervals remain original evidence; they are not refreshed or made live.
Processing separately intersects the original caller allowance with policy and
output limits. It never reopens a clock window or replaces the work meter.

## Receiving composition and boundaries

The private `_derive_on_work` helper performs the same original-only admission
without a signing key. It returns same-call data and a restrictive lifetime,
not reusable permission. `_bind_history_on_work` only adds the actual history
original's byte count and digest; it does not authenticate that original.
Receiving must independently verify both returned signed originals and compare
their complete derived payloads. Configuration comparison preserves the real
finite-float canonical grammar.

The complete original/output inventory is bounded within 64 MiB. Actual work
charges and sticky epoch/monotonic maxima survive nested policy, historical
caller, history and planner admissions through restrictive floor-only hooks.
The original first clock samples remain fixed, limits can only narrow, and the
final return remains under those checks.

Public signed controls do not replace private encrypted-original replay or
current delivery-row proof. Those remain mandatory inside the genuine consume
planner, including actual delivery expiry and possession checks. This library
opens no AES/history key, decrypts no token, writes no SQL/state, runs no worker,
and claims neither consume commit nor credential release. The separate
[one-shot issuer](oidc-session-activation-consume-input-issuer-service.md) and
[durable acquisition client](oidc-session-activation-consume-input-acquisition.md)
are now source-connected. Explicit issuer launch v2 also connects
[exact-pair worker staging](oidc-session-activation-consume-dynamic-delivery.md).
Actual resource provisioning remains open; signed originals and a staged ACK
alone do not close the public flow or prove a service ran.
