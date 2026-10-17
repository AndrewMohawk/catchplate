# Activation execution reserver bootstrap

[The fixed bootstrap](../catchplate/oidc_session_activation_execution_reserver_bootstrap.py)
authenticates the original cold scope for the dedicated activation reserver.
It does not provision keys/directories, reserve state, authenticate a current
pending head, execute SQL or release a token. This is source-only implementation;
no build, runtime or production acceptance is claimed.

## Independent original authority

The closed root-signed envelope uses
`catchplate.signedOidcSessionActivationExecutionReserverBootstrap/v1`; its
payload and launch schemas are
`catchplate.oidcSessionActivationExecutionReserverBootstrap/v1` and
`catchplate.oidcSessionActivationExecutionReserverLaunch/v1`. The signed schema
is also the signature domain. The role original is bounded to 4 MiB.

Admission verifies the independent role signature, the separate
[receiving-custody original](oidc-session-activation-execution-custody-bootstrap.md)
for consumer `reserve`, its embedded genuine
[planner bootstrap](oidc-session-activation-planner-bootstrap.md), and all three
original current-root, successor-grant and activation-caller enrollments.
Returned material is never accepted instead of these originals.

`receivingCustody` contains only `byteCount` and `bytesDigest`, binding the
external original (at most 8 MiB) by actual raw SHA-256. Each enrollment retains
`base64Url`, `byteCount`, `bytesDigest` and `identityDigest`, under its actual
128 KiB / 16 KiB / 16 KiB module limit. Configuration, generation, runtime closure,
database, enrollment identities and audience/key scope must join genuine
admissions. The current-root enrollment byte-matches the planner's state
enrollment. The caller enrollment has the distinct activation execution purpose,
actual dedicated planner key and root operation key; no registration fallback.

## Fixed reserve role and eight descriptors

Role/process mode is `oidc-session-activation-execution-reserver`, operation
`oidc.session.activate`, UID/GID `65505:65505`, request peer `65532:65532`.
The listener is `/run/catchplate/oidc-session-activation-execution/reserver.sock`,
with activation name `catchplate-oidc-session-activation-execution-reserver`.

| Launch field | FD | Original/resource |
| --- | --- | --- |
| `rootPublicKeyFd` | 198 | Root public key |
| `bootstrapFd` | 199 | Independent role bootstrap |
| `listenerFd` | 200 | Original activated listener |
| `custodyFd` | 201 | Separate receiving-custody original |
| `bundleKeyFd` | 202 | Private bundle AES key |
| `deliveryKeyFd` | 203 | Private delivery AES key |
| `signingKeyFd` | 204 | Enrolled computation private key |
| `journalDirectoryFd` | 205 | Separate reservation journal directory |

The inherited inventory is exactly 198–205 in order. Launch pins also bind the
listener socket/path device and inode, integer request timeout 1–30 seconds,
journal device/inode and `journalMaximumRecords`. The journal path is fixed to
`/var/lib/catchplate/oidc-session-activation-execution-reservations`.
These are authenticated pins; actual descriptor/path ownership, sealing,
private-key pairing and close/drop lifecycle remain cold-delivery obligations.

The independent launch-owned `receiverIdentity` must match the genuine receiving
statement, and its measurement must match the enrolled computation measurement.
The computation public key comes from genuine current-root enrollment, not an
arbitrary launch-supplied PEM. Enrollment separates it from state and completion
keys; this profile also excludes the actual root, caller, grant, dedicated planner,
generic-role and admitted enrollment/evidence/transition signing keys. The
service UID/GID cannot alias a configured generic role.

Receiving admission supplies separate bundle/delivery pins. Actual AES bytes
are loaded and checked by dedicated delivery/custody, never serialized into
request expectations. Sharing the same admitted bundle/delivery purpose bytes
with the sender is intentional; planner-signing/journal-key substitution and
ambient-key fallback are not permitted.

## Independent predecessor and local checkpoint

`statePredecessor` is exactly `{sequence, headDigest, nextFence}`;
`reservationCheckpoint` is exactly `{sequence, headDigest}`. Both are independent
root assertions, never learned from a returned acknowledgment. Their sequences
must fit the actual enrolled capacity. At sequence zero, each head must equal
the genuine current-root enrollment digest; genesis predecessor fence is one.
`journalMaximumRecords` must exactly equal enrollment `maxRecords`. The
[durable owner](oidc-session-activation-reservation-delivery.md) independently
requires exact local recovery and space for request/ack; producer admission also
requires state capacity for reservation and completion.

The state endpoint is fixed to `/run/catchplate/current-root/state.sock`,
integer timeout 1–30, state-service UID/GID `65516:65516` and original
root-created listener peer `0:0`. Material retains all six fields separately;
the worker identity is not substituted for the listener's kernel peer identity.
State-peer admission and socket DAC remain separate from this signed launch.

The state owner must actually compare its current predecessor/fence and publish
the reserve atomically. Neither a signed launch snapshot, a valid journal prefix
nor a signed acknowledgment establishes independently latest pending scope or
off-host/action-time authority. Receiving pending admission must use separately
admitted sequence/head/fence, not adopt the acknowledgment as its own expectation.

## APIs and original lifetime

`_verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
live_window=None, transport_deadline_ns=None)` returns private same-call
`_ReserverMaterial`. `_produce_on_work` takes the same cold custody/root/work
scope plus `payload` and `root_private_key`, and repeats genuine original
admission before signing. `_fresh(interval, work, opening=None)` retains the
original launch bracket.

Material includes original role/custody/enrollment bytes; genuine configured
planner/root/computation public keys and computation pins; launch-owned receiver
identity; configuration/generation/runtime/database pins; caller age/skew limits;
`state_predecessor` tuple3, `reservation_checkpoint` tuple2 and `state_endpoint`
tuple6; original interval/opening and launch. It is ordinary private data, not
a portable admission token.

The positive role interval is at most 300 seconds and contained in the original
receiving interval, itself contained in the planner interval. Supplied work,
processing window and inherited deadline are preserved through all admissions
and return; limits do not open or renew a request window. `trustMode` is
`trusted-host-local`; hardware, native-stage-zero, HSM, TEE and external-witness
flags must all be false.

Deferred verification must cover signature/schema/enrollment/key substitutions,
cross-role and descriptor mismatches, checkpoint/genesis/capacity failures and
original lifetime exhaustion. None was executed for this source batch.
