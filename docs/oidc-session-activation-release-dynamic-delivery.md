# Dynamic root delivery of an issued release bootstrap

This source-only receiver stages one newly issued release server bootstrap and
continues the existing finite release worker in the same process. It does not
provision resources, publish or replace a bootstrap file, install a service or
establish runtime readiness. The old fixed-bootstrap `--root-delivery` path is
unchanged. The dynamic launcher is a separate source-selected executable.

## Fixed public inputs and activated listeners

The public-only trust directory is
`/run/catchplate/oidc-session-activation-token-release-dynamic-trust`, with fixed
`root-public-key.pem`, `issuer-policy.json` and `proof-bootstrap.json` originals.
Files must be root-owned mode 0444 with link count one. Protected root-owned
ancestors and leaves are opened without following symlinks; bytes and metadata
are checked under the original work/current guard. No runtime root-signing key
is present in this receiver.

Exactly two initial descriptors, 3 and 4, must have the two distinct names
`catchplate-oidc-session-activation-token-release-bootstrap` and
`catchplate-oidc-session-activation-token-release`. Each name maps to its actual
descriptor and independently checked socket path and metadata; only the two valid
permutations are accepted. Cross-unit descriptor order is unspecified by
[systemd's socket documentation](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.socket.xml),
so numbering alone never assigns a socket's purpose.

The staging endpoint is
`/run/catchplate/oidc-session-activation-token-release/bootstrap.sock`, pathname
owner 0:65496 and mode 0660. Only the actual issuer peer 65496:65496 may send the
bounded staging request. The release endpoint remains
`/run/catchplate/oidc-session-activation-token-release/release.sock`, pathname
owner 65502:65532 and mode 0660. Its signed listener device/inode pins must match
the actual activated listener. The dedicated dynamic socket/service templates
are an alternative to, not a silent replacement for, the fixed-bootstrap service.

## Admit first, stage exact originals

One construction work ledger and original clock bracket start before public-file
I/O or waiting. Genuine .192 issuer-policy/proof admission occurs before accept
or body reading. The service sends no policy, proof bootstrap, resource path or
directory claim to be accepted from the socket. The exact request is the fixed
staging purpose and newly issued server-bootstrap original.

The receiver reserves the actual held public/decoded originals, framing, ACK and
key allowance against the existing 64 MiB aggregate before body allocation. It
passes a tightening-only `maximum_bootstrap_bytes` to the actual transport,
never exceeding the server's 16 MiB cap. The separate proof original retains its
48 MiB bound; root and policy originals are each capped at 16 KiB. The peer is
checked before framing or body allocation. One accepted connection is terminal;
idle waiting does not renew time or allow another peer after failure.

The original-only delivery admission receives the exact server bootstrap,
independent policy/proof originals, runtime root and the same work/window/bound.
It genuinely rejoins signatures, source, fixed LIVE profile, root-authorized
release launch, exact proof-associated custody, caller/producer/receipt/target and
checkpoint-zero policy. An incoming verified-result object is never authority.
The root receiver retains both actual pre-wait and receiving guards and their
sticky epoch/monotonic observations; inner admission can only restrict them.

Only after this admission does the receiver open the existing digest-derived
outcome slot under `/var/lib/catchplate/oidc-session-activation-release-outcomes`
and the fixed raw32 delivery key at
`/run/secrets/catchplate-oidc-session-activation-token-release-delivery-key`.
No slot is created. Actual directory/listener pins are compared to signed pins,
and the actual AES key digest is checked against genuine release custody before
acknowledgment. No token is opened during staging.

The exact received bytes are sealed into the existing inherited bootstrap FD199.
Final descriptors remain the existing five: root198, bootstrap199, deliveryAES200,
outcome directory201 and release listener202. Originals stay in sealed memfds with
CLOEXEC; no bootstrap path is written, replaced, renamed or unlinked. Cleanup
tracks exact descriptor identities, never blindly closes replaced numbers and
never retries an uncertain close.

## The ACK is staged, not ready

The response is exactly `(b"staged", bootstrapIdentityASCII71)`, using the actual
client server-bootstrap framed original identity. It is sent only after the exact
received original and all five resource descriptors are held and checked. It is
not a signature, an empty-directory observation, a storage-recovery receipt,
worker-readiness proof, token-delivery claim or retry authorization.

After sending, the receiver closes the staging connection and staging listener,
checks the exact five-descriptor inventory, and installs only the existing literal
release environment. Existing `_intake_from_delivery_on_work` genuinely rechecks
the sealed originals/resources, permanently drops to UID/GID65502 and retains the
original guard. The same actual owner enters `_run_with_resources`; there is no
post-drop exec, fork, detached worker, fresh allowance or second intake. The
private release connection may queue or fail before that continuation is ready.

The fixed dynamic launcher path is
`/runtime/authority-bootstrap/oidc_session_activation_release_dynamic_launcher.py`,
invoked by `/runtime/python/bin/python3 -I ... --root-delivery`. Standalone worker
renewal is absent. Failure messages contain no token, key or original payload.
Independent resource provisioning and actual deployment/end-to-end evidence remain
separate; staging does not close the public HTTP or cookie flow.
