# Original-bound release preparation inputs

The private `control_plane_oidc_session_activation_completion_recovery_intent_inputs`
module derives release-intent expectations only inside an actual fresh consume
completion actor. Preparation uses purpose `release-intent-proof`; read-only
admission for token release uses a separate fresh actor with purpose `release`
or `retained-release`. These are distinct action-bound permissions.
It accepts the exact sealed historical controls and exact raw6/receiving guard
associated by the matching source orchestrator's one-use `_require_inputs_call`.
The receiving guard is retained; a caller-supplied successful result or callback
cannot replace that association.

The helper reselects the original activation claim and prepared raw5 using the
bounded fixed loader. It historically admits the activation caller, its original
signed plan and opaque ciphertext commitments against the actual parent's root,
planner/operation keys and enrollment originals. The eight activation/consume
argument joins include the assertion digest, actual finalization subject,
credential record and challenge. Existing genuine consume controls and the
historical receiving guard retain the original signed marker, complete/ACK,
pending tuple and after-vector bindings. No old interval is renewed.

Packet/effects, encrypted envelope and original dates from raw6 hints remain
**expected data**, not proof of committed consumption or private outcome
existence. The delivery ID is independently regenerated from the signed activation
request; the old-token original is hashed against the signed arguments. Original
delivery expiry and the signed activation TTL only tighten the continuing
processing window. Later genuine intent/proof admission must independently match
the expectations. This helper neither opens a token nor signs an intent.

`_admit_on_controls(selected, *, response_originals, receiving_current)` remains
preparation-only. `_admit_for_release_on_controls` has the same keywords but
requires the distinct release actor and the actual
`control_plane_oidc_session_activation_completion_recovery_delivery` provenance
hook. `_admit_for_retained_release_on_controls` uses the same private owner hook
but requires the separate literal `retained-release` actor. All three return
only the source-private sealed `_IntentInputs`; its literal
purpose is sealed and must continue matching the original actor. Fixed graph
snapshots, original references, actor association and cold pins are checked by
`_require_inputs` and `current()`. `window`, `deadline_ns`, `narrow()` and
`continuity()` retain the same work and nondecreasing clock floors. Child
continuations call the original ancestor only; no later intent/proof guard is
fed back into its own parent. The object is unusable after actor cleanup, and its
old-token reference is live-call-only, never a journal or public response field.

The orchestrator reserves `INPUT_RESERVATION_BYTES` (4 MiB) before the actor's
first selected history body, alongside the separate signer/proof and receiving
reservations. That future reservation is already included in the target and
controls totals and is not added again here. Before the second activation read,
the helper reserves bounded projections and actual-size capture copies, then
tightens the loader's metadata preflight to the remaining lane. Oversized inputs
are refused before body allocation. These are source-defined representation
bounds under the original 64 MiB aggregate, not a general Python heap bound.

`reconciliation_digest` is `None` for actual original completion/hints or the
exact separately retained reconciliation-record digest supplied by the private
orchestrator. This provenance selects the existing immutable custody association;
it does not replace either original record or create execution authority.

This source connection grants no SQL retry, completion retry, release checkpoint,
private store access, token exchange or cookie delivery. Missing retained intent
or a reconstructed expected outcome proves neither private-outcome presence nor
absence. A closed preparation actor cannot become a release actor. The separate
release owner must independently admit the appropriate original evidence and
root-signed authority: LIVE/checkpoint zero for `release`, or a fresh independent
RECOVERY/checkpoint-one policy and grants for `retained-release`. These inputs
select no profile or fallback and create no intent or proof on either read-only
release path.
No runtime, resource provisioning or production-readiness evidence is claimed.
