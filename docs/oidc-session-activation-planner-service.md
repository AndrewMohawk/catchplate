# Private activation planner exchange

This is source-only cold planning, not session activation. The fixed service
authenticates original mandatory-v3 root bootstrap bytes, constructs the actual
read planner, encrypted original journal, separate execution-bundle store and
configured plan owner, and handles one accepted connection. It does not accept
an already-verified material or transition object.
The [cold delivery guide](oidc-session-activation-planner-delivery.md) describes
the root entrypoint, launcher and uninstalled systemd templates.

## Closed wire

`authority_oidc_session_activation_planner_transport.py` fixes the endpoint to
`/run/serverware/oidc-session-activation/planner.sock`, an integer timeout of
1–30 seconds and root-activated listener peer `0:0`. Every client exchange
requires an inherited absolute monotonic deadline. The service admits peer
`65532:65532` before reading a frame or body.

Request magic `SWOAPQ02` precedes exactly eight length-prefixed originals; the
request bodies are unchanged:

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

Response magic `SWOAPR02` precedes exactly seven originals:
`(b'prepared', request, scope, signedPlan, planDigest, journalDigest, encryptedOriginalsBundle)`,
or `b'uncertain'` followed by six empty bodies. The returned request is bounded
to 4 MiB, scope to 2 MiB, plan to 16 KiB and each locator to a canonical 71-byte
SHA-256 identifier. The seventh body is only the original encrypted execution
bundle, never plaintext private-journal bytes, pending/new tokens or keys.

All lengths and group limits are checked before body allocation. The 64 MiB
whole-exchange ceiling is unchanged: response admission conservatively reserves
the worst-case sum of `REQUEST_LIMITS` plus both wire headers before reading
response bodies. The standalone bundle codec's larger framing ceiling does not
enlarge this transport budget. Both directions require exact EOF; the client
half-closes after its request. The transport neither parses nor authenticates
returned plan originals and has no retry or callback hook. Old response framing
is not silently accepted as the new ciphertext-bearing protocol.

## Cold process and one request

`authority_oidc_session_activation_planner_service.py` exports
`initialize_from_environment()`, `require_started()` and `close()`; its private
owner's `serve_once()` returns false only for an idle poll. The fixed runner
exits after the first accepted connection, including an invalid peer or frame.
A separate spent latch is set before actual planning. Uncertainty never permits
another request, token generation or signature in this launch.

UID/GID `65507` runs with no supplementary groups and the exact eight-variable
environment. FDs `198–206` respectively hold root key, original bootstrap,
listener, planner signing key, delivery key, journal key, journal directory,
bundle key and separate execution-store directory. Root admission precedes
key/TLS/journal/store use. The actual key helper verifies the planner pair/SPKI
and all three pairwise-distinct raw32 delivery/journal/bundle key digests. Both
private directories must match their independently signed paths, device/inode,
owner, mode and quotas; journal and store must be distinct. At idle inventory
boundaries the service holds these nine inherited descriptors plus three owned
descriptors: its listener duplicate and independent journal/store descriptions.
An accepted connection adds one descriptor. TLS bytes are checked against signed
pins during admission; later checks preserve exact
file metadata/path identity, not an off-host witness.

Construction uses the bootstrap's original clock opening, clipped to the real
planning policy. Each accepted request opens one work allowance and live window
before peer/frame/body processing; the effective deadline is the minimum of
that window, the original launch bound and the signed request timeout. No later
stage reopens the window. PID, literal environment, sealed originals, actual
owners, listener/journal/store paths and TLS continuity are rechecked through
response.

The actual [cold composition](oidc-session-activation-cold-planning.md)
reauthenticates the original bootstrap and projects its complete root vector.
The actual owner's mandatory configuration retains the original state enrollment,
independent root key and complete-vector bytes. Before planning, a fresh random
challenge and exact subject/input/vector context are sent to the fixed state
endpoint. Genuine original verification requires a live signed matching vector
and no pending action. The original work/window remains unchanged; the signed
plan is additionally clipped to the observation's original expiry.

The composition joins the held owners and calls the
[configured plan owner](oidc-session-activation-plan-owner.md), which genuinely
acquires/replays/signs and durably encrypts exact originals. The actual private
export then authenticates the original plan and bound journal bytes, replays the
originals and either reopens the first retained ciphertext or seals and durably
publishes it in the [separate store](oidc-session-activation-execution-store.md).
It preserves the same work/window and original plan/head expiry through return.
The local result is `PreparedActivationExport(plan, encrypted_originals_bytes,
expires_at_epoch_ns)`, ordinary same-call output rather than an accepted proof
token. The service additionally clips the response-send deadline to that genuine
original expiry; retention does not permit a late successful response.

Original enrollment/vector/query/observation bytes remain within private retained
originals and the encrypted bundle; they are not exposed as plaintext response
fields or accepted as successful proof objects. The journal digest remains a
storage locator, not proof of currentness or execution.

Ordinary planning failures can return only empty uncertainty. Publication may
already be durable in either journal or store; absence, retry permission and a
safe new signature are not inferred. Malformed input, disconnects or expired
lifetime can simply close the connection. Cancellation is not converted into a
successful result. Closing
drops key references and closes owned resources; it does not claim Python
memory zeroization.

## Remaining boundary and deferred verification

The root-signed vector is independently provisioned input; the separate fresh
head is a signed sampled observation, not an atomic reservation or action-time
authority. Present-caller permission, genuine retained
finalization admission, protected execution, token delivery and session
activation remain separate. Generic execution remains closed; receiving-side
independent execution custody and integration remain unfinished. Packaging is
uninstalled; key/TLS/DB/journal/store provisioning, socket DAC and restricted
database egress are still external.
Ciphertext retention survives validated cold starts, but there is no public or
automatic lost-response recovery/retry endpoint in this service. A later launch
does not itself authorize another planning action or protected execution.

State-service v4 admits UID 65507 only for the head exchange; previous reserve,
completion and lookup peers are unchanged. The root-created listener is pinned
to kernel peer `0:0`. Its pathname is owned by `65516:65516` with mode `0660`, so
separate provisioned ACL/DAC access for planner UID 65507 is required; these
sources do not grant it.

Planned frozen verification, **not run**: reject altered root/FD/key/path/env
before resource use; reject wrong peers, subject encodings, lengths and trailing
bytes; verify genuine planning plus both durable original and first-ciphertext
retention; preserve one accepted connection and original bounds across errors/late
expiry; confirm no-plaintext-token responses, uncertain durable outcomes and no
automatic retry. New head cases include altered enrollment/generation/database association, wrong
challenge/context/vector, non-null pending state, stale observations, reversed
clocks and observation expiry after retention. Export cases include key reuse,
store/journal aliasing, wrong signed quotas, changed first ciphertext, combined
request/header/response overflow, and original expiry before/during send. No
verification was executed.
