# Same-call consume authorization

[`control_plane_oidc_session_activation_consume_authorization.py`](../serverware/control_plane_oidc_session_activation_consume_authorization.py)
connects the actual retained consume prepare/export continuation to a distinct
root-enrolled caller signer. This is source-only, unbuilt, unexecuted and
unprovisioned. It adds no consume grant request, reservation, SQL execution,
completion, token opening, public route or active-session cookie. Activation
step 22 remains incomplete and production acceptance remains 0/6 verified.

## Original live context only

The actual permission context exposes `authorize_consume() -> bytes`. There
are no request arguments, response tuples, work/window replacements or
successful-result inputs. Its parent facade delegates only to the exact
currently active permission slot. The original owner, PID/thread, locks and
allowance must still be active after acknowledged activation completion and
[consume prepare/export](control-plane-oidc-session-activation-consume-planning.md).
An escaped context or read-only journal loader cannot resume the operation.

The real prepare path internally seals its exact prepared raw6 and exported
raw7, the independently checked post-activation complete vector used as the
consume before-vector, and its actual current/narrowing continuations. The
original cookie possession, root planner/history opening brackets, signed
plan interval and earlier activation authority remain restrictive. Only this
source-owned state permits signing; a caller cannot supply a replacement
plan, vector, scope, callback or prior completion observation.

The authorization latch is spent before key or signing callbacks. Failure
revokes the context; there is no automatic retry or restored signing permission.

## Dedicated cold key, not fresh permission

The explicit parent `/v8` consume-execution lane retains root-signed current
state, consume-grant and consume-caller enrollment originals. Its dedicated
caller private key occupies FD 206 and remains in the actual UID/GID 65532
owner. The configured public planner key is the original activation `/v4`
consume planner key, and the operation public key is the actual runtime root.
This cold configuration does not itself establish present user permission.

Signing requires that original key object, descriptor and descriptor identity
to remain unchanged. The real owner continuity checks the inherited resources
and runtime receipt; the existing activation scope also checks the actual
provisioned HTTP-response key. The consume signer must differ from that key
and the activation caller key. The genuine consume enrollment admission
independently enforces its own root, planner, state and grant-key exclusions.
No HTTP, activation, history or AES key is borrowed to sign.

## Produce, authenticate, retain

The fixed composition reconstructs typed request/scope/journal expectations
from its held original raw6 and supplies only the exact exported plan and
encrypted bundle raw2, actual consume before-vector, original enrollments and
held root/configuration keys to the existing producer. The whole held-original
bound reserves the signed output before signing; all work remains charged to
the original cumulative ledger.

The genuine producer admits the known plan signature, request and scope,
enrollments and caller key pair before producing a fresh post-plan signed
authorization. The coordinator then authenticates that returned original
through the actual signature/fact verifier. It narrows the original expiry and
age/skew policy to the authorization; it never opens a new processing window.
Public plan/ciphertext binding is not private decryption or semantic replay.

The producer's optional private continuity seam retains clock floors in both
directions with the actual owner. It cannot reduce previous epoch/monotonic
observations, reset work, widen the original bracket or cross the producer's
currently narrower deadline. The final context check still uses the actual
narrowed clock/skew policy, preserves root-original lifetimes and checks the
held key/cookie identities. Standalone producer behavior is unchanged when
that private composition seam is absent.

After genuine output admission, the actual custody journal appends the exact
signed raw1 as the fourth consume-planning file, following claim, prepared and
exported originals. The claim remains bound to the retained finalization
target and original activation authorization identity. I/O is precharged;
actual live guards surround publication/readback and the final return. Only
then may the method return the signed bytes. No old/new token, cookie,
assertion or private key is journaled. Recovery remains read-only, and a local
record digest is not new permission or grant authority.

Post-activation root issuance and matching private workers are still external
provisioning prerequisites. A later genuine consume grant/dispatch connection
must authenticate originals under the remaining same-call authority; this
slice does not call the grant service or claim the release handoff is complete.
