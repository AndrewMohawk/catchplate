# Historical recovery target inspection

`control_plane_oidc_session_activation_recovery_history._inspect_on_owner`
accepts the actual cold owner, a local finalization locator, request-local old
token bytes and the original work/window/deadline/current guard. It is called
freshly before recovery options and again before fresh assertion admission.
No incoming successful subject or previous options result can replace it.

The inspector genuinely replays the retained finalization association and its
acknowledged completion against the actual owner's independent configuration,
enrollments and pending pins. Only then does a narrow selector read the unique
activation/consume association and exact retained release-intent original.
It does not load an activation prepared ciphertext bundle or open private AES.
Absence of a retained intent does not establish nonexecution; recovery before
that stage remains open.

The dedicated target-only intent helper authenticates the actual cold root,
original enrollment, scope6, caller public key, measurement and forbidden-key
separation, then verifies the historical intent signature. The independently
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

The supplied guard remains upstream of the historical guard. Original work,
PID/thread, owner/configuration/key references and nondecreasing clock floors
remain bound; no new allowance is opened. The next actor step must freshly
check the authenticated target's current user/session, sole credential, trust
and explicit RBAC, with session/provider expiry only tightening the original
delivery deadline. A distinct fresh recovery assertion and any required
two-person authority remain separate from this evidence inspection.

The [actor-owned acquisition context](control-plane-oidc-session-activation-recovery-acquisition.md)
now composes this evidence with fresh actor authority, independent parent
originals, a policy-keyed durable attempt, admitted grant retention and one-shot
server-original staging. A staged ACK is not worker readiness or store proof. This
inspector itself still grants no issuance or exchange permission. Its finalization
replay now uses the [combined historical reader](control-plane-registration-finalization-completion-history.md),
which preflights the selected metadata before the first body read. Already-held
request/token/intent inputs tighten the subject's parent/enrollment/replay
reservation. The exact original sum remains a second check; later acquisition
uses its separate phase reservation on the same work. This is representation
accounting, not a process-heap guarantee.

This is source-only, not completion of public recovery. Prior-stage recovery,
protected exchange and public cookie completion, independent resource
provisioning and runtime verification remain separate work.
