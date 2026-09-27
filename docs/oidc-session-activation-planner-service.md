# Private activation planner exchange

This is source-only cold planning, not session activation. The fixed service
authenticates original root bootstrap bytes, constructs the actual read planner,
encrypted original journal and configured plan owner, and handles one accepted
connection. It does not accept an already-verified material or transition object.
The [cold delivery guide](oidc-session-activation-planner-delivery.md) describes
the root entrypoint, launcher and uninstalled systemd templates.

## Closed wire

`authority_oidc_session_activation_planner_transport.py` fixes the endpoint to
`/run/serverware/oidc-session-activation/planner.sock`, an integer timeout of
1–30 seconds and root-activated listener peer `0:0`. Every client exchange
requires an inherited absolute monotonic deadline. The service admits peer
`65532:65532` before reading a frame or body.

Request magic `SWOAPQ01` precedes exactly eight length-prefixed originals:

1. Literal `oidc.session.activate`.
2. Original assertion bytes, 2–128 KiB.
3. Original pending token, exactly 64 URL-safe ASCII bytes.
4. User ID, at most 1,024 characters / 4,096 UTF-8 bytes.
5. Session ID, at most 128 characters / 512 UTF-8 bytes.
6. Canonical unpadded base64url credential ID, 1–1,024 decoded bytes.
7. Credential record ID, at most 1,024 characters / 4,096 UTF-8 bytes.
8. Challenge ID, at most 1,024 characters / 4,096 UTF-8 bytes.

No request selects policy, key, roots, database configuration or time allowance.
The five IDs remain claimed subjects until actual original assertion and row
replay; peer authentication is not public permission or retained-finalization
admission.

Response magic `SWOAPR01` precedes exactly six originals:
`(prepared, request, scope, signedPlan, planDigest, journalDigest)`, or
`(uncertain, empty, empty, empty, empty, empty)`. The request is bounded to 4 MiB,
scope to 2 MiB, plan to 16 KiB and each locator to a canonical 71-byte SHA-256
identifier. All lengths and group limits are checked before body allocation;
the combined exchange is bounded to 64 MiB. Both directions require exact EOF;
the client half-closes after its request. The transport neither parses nor
authenticates returned plan originals and has no retry or callback hook.

## Cold process and one request

`authority_oidc_session_activation_planner_service.py` exports
`initialize_from_environment()`, `require_started()` and `close()`; its private
owner's `serve_once()` returns false only for an idle poll. The fixed runner
exits after the first accepted connection, including an invalid peer or frame.
A separate spent latch is set before actual planning. Uncertainty never permits
another request, token generation or signature in this launch.

UID/GID `65507` runs with no supplementary groups and the exact eight-variable
environment. FDs `198–204` respectively hold root key, original bootstrap,
listener, planner signing key, delivery key, journal key and journal directory.
Root admission precedes key/TLS/journal use. The actual key helper verifies the
planner pair/SPKI and the distinct raw32 delivery/journal key digests. TLS bytes
are checked against signed pins during admission; later checks preserve exact
file metadata/path identity, not an off-host witness.

Construction uses the bootstrap's original clock opening, clipped to the real
planning policy. Each accepted request opens one work allowance and live window
before peer/frame/body processing; the effective deadline is the minimum of
that window, the original launch bound and the signed request timeout. No later
stage reopens the window. PID, literal environment, sealed originals, actual
owners, listener/journal paths and TLS continuity are rechecked through response.

The actual [cold composition](oidc-session-activation-cold-planning.md)
reauthenticates the original bootstrap and projects its complete root vector.
It joins the held owners and calls the [configured plan owner](oidc-session-activation-plan-owner.md),
which genuinely acquires/replays/signs and durably encrypts exact originals
before returning immutable token-free request/scope/plan bytes and locators.
The journal digest is a storage locator, not proof of currentness or execution.

Ordinary planning failures can return only empty uncertainty. Publication may
already be durable; absence, retry permission and a safe new signature are not
inferred. Malformed input, disconnects or expired lifetime can simply close the
connection. Cancellation is not converted into a successful result. Closing
drops key references and closes owned resources; it does not claim Python
memory zeroization.

## Remaining boundary and deferred verification

The root-signed vector is independently provisioned input, not fresh latest-head
or off-host action-time authority. Present-caller permission, genuine retained
finalization admission, protected execution, token delivery and session
activation remain separate. Packaging is uninstalled; key/TLS/DB/journal
provisioning, socket DAC and restricted database egress are still external.
There is no public route or automatic recovery/retry in this service.

Planned frozen verification, **not run**: reject altered root/FD/key/path/env
before resource use; reject wrong peers, subject encodings, lengths and trailing
bytes; verify genuine planning plus durable original retention; preserve one
accepted connection and original bounds across errors/late expiry; confirm
token-free responses, uncertain durable outcomes and no automatic retry.
