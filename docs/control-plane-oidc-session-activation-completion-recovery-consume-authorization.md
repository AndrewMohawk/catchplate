# Fresh consume caller authorization

`control_plane_oidc_session_activation_completion_recovery_consume_authorization`
adds one caller-signing stage to the actual private fresh-consume owner. Its
`_authorize_on_active(active)` accepts only the source-owned `_ConsumeAttempt`
and invokes the owner's irreversible authorization latch once. The actor remains
the distinct fresh `consume` purpose with the activation profile; no ordinary
`_ActivationPermission` is constructed, relaxed or revived.

The input is the exact [private prepare/export continuation](control-plane-oidc-session-activation-completion-recovery-consume-planning.md):
prepared request/scope/journal originals, exported signed plan and opaque
ciphertext, and the genuinely admitted before-vector. Independent
`parent.consume_execution` supplies the caller/current-root/grant enrollments,
configuration and public key pins. Caller/current-root and planner joins are
checked against the independent activation policy, not learned from the plan.

The actual owner must still hold the dedicated consume private key at FD206
with its original descriptor identity. Its public key must match that private
key and differ from the actual HTTP response and activation caller keys.
Original owner/FD, provisioned HTTP-key, actor, resource and plan guards remain
live throughout signing, admission, publication and downstream normal cleanup.
This stage neither opens another key nor borrows the response signer.

The lower genuine caller producer authenticates the original plan/enrollment
controls and signs the fresh bounded authorization. The returned original is
then captured and admitted again by the actual caller signature/fact verifier.
Its narrowed window and full current guard remain part of the continuation.
Fresh signing cannot backdate or extend the original plan or delivery expiry.
Ciphertext is not privately replayed here; this authorization is neither a
consume grant nor evidence that SQL or token delivery occurred.

The raw1 signed authorization is durably published through the guarded custody
append before the helper returns `_ConsumeAuthorization`. That private sealed
object binds the actual owner, signed original, exact common inputs,
expectations, before-vector and genuine same-call verifier results. Mutable
expectation graphs and original references remain snapshot-checked. Downstream
dispatch must independently admit the signed original; the result is not an
external authority input. No old-token plaintext is added to custody records.

The same original work, clock opening, monotonically retained floors and
only-narrowing bounds continue through all stages. Child clocks receive only
the new lifetime's base continuity, whose ancestor is the original plan.
The genuine verified-authorization child is kept separately; neither it nor a
later dispatch/completion child is called by its own ancestor. The private
result cannot outlive the actual actor or owner.

Before decoding or signing, a length-only conservative inventory reserves
actual raw2, request/scope/journal, before-vector and enrollment captures plus
bounded authorization/canonical representations. Its retained reservation is
the prior held base plus this capture inventory, not the entire execution
lane. It must leave at least the source-fixed 4 MiB completion reservation in
the shared 8 MiB execution lane; dispatch must still fit its own remaining
inventory. The lane was reserved before the initial historical target read
inside the unchanged 64 MiB whole-call representation bound. Large valid inputs
can be rejected. This is not a new allowance or a process-heap guarantee.

This helper itself performs no grant, reservation, SQL, completion, public
success or cookie effect. Unknown effects do not authorize retry, new windows
or a second signing call. Source only: unbuilt, unexecuted and unprovisioned;
all independent deployment and production acceptance gates remain separate.
