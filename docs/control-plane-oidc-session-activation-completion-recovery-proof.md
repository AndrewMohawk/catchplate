# Completion-recovery release proof

`catchplate/control_plane_oidc_session_activation_completion_recovery_proof.py`
consumes the actual sealed [intent continuation](control-plane-oidc-session-activation-completion-recovery-intent.md).
`_proof_on_intent` spends the root orchestrator's one-use proof latch at entry,
including on read-only reuse. `_require_proof` checks the privately constructed
result's exact intent association and full original current guard. No token,
release profile, store checkpoint, SQL retry or cookie is produced here.

## New setup and proof exchange

New effects require the independently configured root proof-setup service. The
intent path checks this before its claim/signing, and a retained intent requiring
a new proof checks it before the proof claim or contact. A deployment with only
a preprovisioned proof service cannot start this new acquisition lane.

After genuine live admission of the exact intent and independent proof signer,
scope and setup policy, the existing consume-family proof claim is durably spent.
One configured setup exchange sends raw4 `(purpose, completion, ACK, intent)`.
The bounded raw1 reply is retained before genuine root bootstrap admission. Its
intent, enrollments, completion/ACK, release scope, caller and worker launch must
match the independent input and issuer policy, not expectations copied from the
reply. Setup admission and its original launch guard remain live.

One configured proof exchange then sends raw3 `(purpose, intentDigest, old64)`.
The socket helper performs its normal close and returns raw4
`(status, custody, proof, proofEnrollment)`. The exact bounded reply is retained
as data before the status/signature branch. Transport/framing failures do not
manufacture a response record. A spent claim without a retained response cannot
resume setup or proof contact, and records cannot be replaced.

Success requires genuine root custody and proof signatures. Checks join the
original activation planner, intent, activation/consume requests, encrypted
delivery envelope, delivery scope, receiver, configuration/generation/runtime
closure, completion receipt and independent proof enrollment. Neither unsigned
status nor setup ACK is proof authority. Existing pure verifiers are used with
the original work ledger and floor-only nested continuations.

## Retained originals and guards

An existing proof record takes the read-only branch: no claim, append, setup
socket or proof socket. Its exact original proof and custody are genuinely
historically admitted against the same independent expectations. An existing
LIVE proof without a setup record is allowed only on this read-only branch.
Original intent/proof signature intervals are historical evidence, not renewed
authority; the original delivery expiry still constrains the call.

In `.229` retained-only preparation, the root, proof enrollment and exact
planner original come from the independently selected retired RI authority,
not the response's enrollment or the current signing configuration. The intent
stage first matches the full retained tuple to the pre-actor prefix commitments.
The proof stage genuinely re-admits the original enrollment, custody and proof,
requires the custody's exact independently held planner original, and checks the
signed proof interval is contained in the selected RI authority interval. It
does not require a retired private key or re-admit an old setup as fresh launch
authority. An absent proof refuses before any claim or service contact, including
when the retained intent is still within its signed lifetime. Retired-RI delivery
is separately gated; this preparation result is not fresh LIVE/RECOVERY authority.

The proof lifetime's ancestor samples the actual intent continuation, which
retains the actual input/actor guards. Nested setup, issuer and proof admissions
refer only to this lifetime's base; their full guards are attached downstream,
never fed back into their own ancestor. Narrowing intersects the live intent
with the already narrowed proof-enrollment window. The root retains the final
guard separately through normal actor/trust cleanup while the actor is live;
no ordinary closed-actor fallback is introduced.

## Separate release-only readmission

`_readmit_on_intent` accepts only the actual intent continuation belonging to a
fresh actor with sealed purpose `release` or `retained-release`. The separate delivery orchestrator's
one-use proof hook is required even for this read-only call. Its existing proof
claim and raw4 must already be present; absence refuses before setup, proof
contact or publication. It uses the same genuine historical custody/proof
admission, original delivery expiry, sealed original tuple and full current
guard. The preparation entrypoint explicitly refuses a release-purpose actor.

The root owner may consume the identity-sealed `_originals` raw4 as original
data; it is not an independently sufficient success or permission object. The
owner must genuinely re-admit current intent/proof and independently root-signed
LIVE/checkpoint-zero client/server originals for `release`, or genuine historical
evidence under fresh independent RECOVERY/checkpoint-one policy and grants for
`retained-release`, before the respective protected exchange.
This helper makes no checkpoint choice, infers no private-store absence and
provides no RECOVERY fallback. Expired authority is not renewed. No preparation
permission or closed actor is reused.

## Bounded capacity and remaining boundary

All proof work uses the original, pre-reserved 8 MiB future representation lane.
Fixed request/enrollment/intent/framing reservations and conservative setup and
proof representation factors determine smaller response caps before either
socket allocates a body. The setup cap also reserves the subsequent custody and
proof reply; it is intentionally much smaller than the per-file protocol maxima.
Larger otherwise valid deployments may therefore fail closed.

Before each custody claim or append, `_io_capacity` subtracts the simultaneously
held fixed representations, setup copies (or its admitted representations), and
the raw proof reply from this same lane. The directly metered journal then
preflights its own selected rereads and publication copies against the remaining
capacity. Signature admission has a separate full representation preflight.
There is no second 8 MiB allowance, new ledger, arbitrary object traversal or
Python heap/RSS guarantee.

This source-only connection is unbuilt, unexecuted and unprovisioned. A verified
intent/proof is not token release or outcome-store existence. Independently
admitted LIVE/checkpoint-zero versus RECOVERY/checkpoint-one authority and the
subsequent current-auth/cookie continuation remain separate. Missing local
intent or outcome does not establish non-execution.
