# Original-only recovery grant acquisition

`control_plane_oidc_session_activation_release_recovery_grant_acquisition.py`
connects one fixed issuer exchange to genuine original admission. It is an
internal bounded function, not a public recovery actor, configured parent owner,
HTTP route, durable attempt claim or token-release operation.

`_acquire_on_work` takes `request_originals` (recovery prefix7), four independent
originals (`issuer_policy_bytes`, `release_custody_bytes`,
`proof_enrollment_bytes`, `intent_enrollment_bytes`), `root_public_key`,
`endpoint`, `live_window`, `transport_deadline_ns`, `work`, and optional
restrictive `_continuity` and `_additional_original_bytes=0`. The endpoint must independently select the fixed
recovery-grants socket and root peer. It is not the policy's separate
`release.sock` endpoint and cannot be learned from the reply.

Before contact, the function genuinely verifies the independent
[recovery issuer policy](oidc-session-activation-release-recovery-issuer-policy.md),
historical custody and enrolled keys. It byte-joins request enrollments to those
independent originals. The same work/window and retained policy guard cover
exactly one [raw8/raw3 exchange](oidc-session-activation-release-recovery-grant-transport.md).
The response then enters the actual [.203 triple admission](oidc-session-activation-release-recovery-grant-admission.md):
historical intent/proof and current old-token possession re-derive the canonical
outcome against independent signed pins, bind the actual recovery raw8 identity,
and authenticate fresh client/server/storage/recovery originals. No response
supplies its own expected scope, key or resource authority.

Only the actual immutable `_RecoveryGrantMaterial` is returned, retaining its
genuine narrowed original guard. No new owner/success DTO is fabricated, no
request or old-token field is returned, and no token is opened. The ancestor-only
continuity avoids a cycle through attached child guards. There is no refreshed
clock allowance or fallback after any transport/admission uncertainty.

Before policy admission or contact, a conservative 64 MiB inventory reserves
sixteen custody-original sizes and eight other input-original sizes for both
policy/history admissions and their captured originals, plus fixed wire buffers.
At most one eighth of the remainder is available for the response. The source
transport enforces that tightening cap from the length header before allocation;
this is local capacity, not a peer-negotiated larger grammar. The shared
derivation/receiver impose their own additional caps and charge all actual work.
Large individually valid originals may therefore fail closed. No Python
allocator-overhead or performance guarantee is implied.

`_additional_original_bytes` must be an exact nonnegative integer below 64 MiB.
It reserves upstream held originals and graphs before either policy admission
or wire contact, subtracting from the same aggregate and response capacity.
It can only tighten the existing bound, not supply authority, widen a grammar
or renew work. The [actor-owned acquisition context](control-plane-oidc-session-activation-recovery-acquisition.md)
uses it for its held parent, actor/history-result, selected originals and
additional policy admission. That later-phase integration does not fix the
separately documented earlier finalization loader preallocation gap.

One call performs at most one exchange, but this helper does not create durable
cross-call retry authority. The separate actor-owned context now composes actual
parent configuration, fresh actor admission and a durable policy-keyed attempt,
then retains the exact raw3 **after** this helper's genuine admission. This helper
does not offer a pre-admission retention callback; failure may leave only the
spent attempt. Recovery dispatch ownership remains separate work.
The issued server bootstrap is **not staged into a release worker in this
slice**. A reconstructed outcome or signed checkpoint-one expectation does not
prove that the private store contains it. Genuine protected-store observation,
release exchange, current-auth and guarded cookie delivery remain open; neither
activation nor SQL may be repeated. See [public recovery boundaries](oidc-session-activation-public-recovery.md).

This is source-only, unbuilt, unexecuted and unprovisioned.
