# Historical recovery target inspection

`control_plane_oidc_session_activation_recovery_history._inspect_on_owner`
accepts the actual cold owner, a local finalization locator, request-local old
token bytes and the original work/window/deadline/current guard. It is called
freshly before recovery options and again before fresh assertion admission.
No incoming successful subject or previous options result can replace it.

The inspector genuinely replays the retained finalization association and its
acknowledged completion against the [independently selected historical finalization
scope](control-plane-registration-finalization-historical-recovery.md), enrollments
and pending pins. Only then does a narrow selector read the unique
activation/consume association and exact retained release-intent original.
It does not load an activation prepared ciphertext bundle or open private AES.
Absence of a retained intent does not establish nonexecution or select an
alternate action. The distinct pre-intent completion path needs its own fresh
permission and original admission.

With parent v19 `activationHistory` configured, the bounded original's
configuration/generation/enrollment locators select exactly one independently
admitted archived scope. They are untrusted selectors, never authority. The
shared `control_plane_oidc_session_activation_history` resolver verifies the
original enrollment, intent signature and scope, and requires the signed intent
interval to lie within its independent archived interval. Unknown or ambiguous
cohorts refuse; the current intent configuration is not a fallback. The explicit
legacy configuration path remains only when no activation-history material is
configured. Original source labels and signed bytes are unchanged; explicit
older-source adapters remain separate work.

The dedicated target-only intent helper then authenticates the selected old root,
original enrollment, scope6, caller public key, measurement and forbidden-key
separation, and repeats the historical intent signature check. The independently
replayed user/session/credential must equal its signed delivery target. Actual
old-token possession is checked against the signed digest, not used to look up
or authenticate a current browser session. Activation operation and delivery
ID consistency are checked, and the original delivery expiry must remain live.
Original intent issue/expiry are authenticated historical interval algebra;
this does not renew the old intent or turn it into present permission.

The other signed release/consume fields remain opaque historical evidence.
They are not copied into the full verifier as independent expectations. This
path proves neither activation/consume execution nor completion, outcome-store
contents, delivery, or permission to release a token. Full recovery requires
separate fresh root authority and genuine original outcome admission.

The private `_RecoveryTarget` contains the genuine subject8, local activation
authorization association digest, exact intent original/digest, delivery
scope11, old-token digest and retained narrowed lifetime/guard. The association
digest is only an opaque local selector bound into fresh WebAuthn, not
cryptographic execution authority. No old-token original is returned, journaled,
logged or retained by the result's guard.

Its two byte fields make retained capacity explicit. `original_bytes` counts the
shared cold originals and selected intent original, not the old token.
`original_reservation_bytes` includes the original caller's additional reservation,
the measured sealed parent once, shared archive/configuration captures and replay
headroom, subject/claim metadata, key/token headroom and eight selected-original
footprints. These fields are pinned by the returned live guard. The later actual
actor/acquisition path retains that full reservation once and adds only its
newly created captures/key headroom; it does not add another parent/intent reserve.

The supplied guard remains upstream of the historical guard. Original work,
PID/thread, owner/configuration/key references and nondecreasing clock floors
remain bound; no new allowance is opened. The next actor step must freshly
check the authenticated target's current user/session, sole credential, trust
and explicit RBAC, with session/provider expiry only tightening the original
delivery deadline. A distinct fresh recovery assertion and any required
two-person authority remain separate from this evidence inspection.

The archive's cold-only lifetime is rooted in the original upstream guard.
After finalization ACK verification, the inspector drops the full replay result
and keeps its narrow cold continuity before reading intent records. The selected
intent-scope guard and target/possession guard are siblings over that ancestor;
neither is inserted into the callback it calls. Both remain live through the
returned target, avoiding a cyclic child check or a resurrected old permission.

The [actor-owned acquisition context](control-plane-oidc-session-activation-recovery-acquisition.md)
now composes this evidence with fresh actor authority, independent parent
originals, a policy-keyed durable attempt, admitted grant retention and one-shot
server-original staging. A staged ACK is not worker readiness or store proof. This
inspector itself still grants no issuance or exchange permission. Its finalization
replay uses the [combined historical reader](control-plane-registration-finalization-completion-history.md),
which preflights the selected metadata before the first body read. Already-held
request/token/archive captures tighten the subject's parent/enrollment/replay
reservation. The later three-record selector also receives a remaining-capacity
limit: `3 * ((64 MiB - held_reservation) // 8)`. It reserves three actual encoded
footprints plus 16 KiB before its first body, leaving the additional footprints
needed for original admission. The target's final conservative sum is checked
again. One work/window and the unchanged 64 MiB ceiling cover the phases; this is
representation accounting, not a measured heap/RSS guarantee.

This increment is source-only historical target/possession integration, not
closure of activation's complete H05 scope. Downstream consume, proof, grant and
release authority still needs its own independently selected historical scope;
current-pinned consumers may refuse older originals. Existing public recovery
and cookie continuations do not turn target inspection into that authority.
Independent resource provisioning and runtime verification remain open.
The private [protected exchange](control-plane-oidc-session-activation-recovery-exchange.md)
uses the actual live actor context; historical inspection alone still grants
no token access or permission to send a response.
