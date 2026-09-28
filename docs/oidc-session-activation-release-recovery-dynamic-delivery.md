# Recovery-only dynamic worker delivery

This source path stages one exact recovery server bootstrap and continues into
the existing private release worker in the same process. It is separate from
LIVE delivery, which remains unchanged. Source only: no unit was installed,
resource provisioned, runtime started or recovery/token delivery demonstrated.

The isolated launcher is
`oidc_session_activation_release_recovery_dynamic_launcher.py --root-delivery`.
It calls the matching dynamic entrypoint as root; no post-drop exec, fresh work
ledger or renewed processing allowance is available.

## Independent originals and listeners

The protected root-owned trust directory is
`/run/serverware/oidc-session-activation-release-recovery-dynamic-trust`.
Its five regular, single-link, root-owned mode 0444 files are:

- `root-public-key.pem` (16 KiB maximum).
- `issuer-policy.json` (64 KiB).
- `release-custody.json` (8 MiB).
- `proof-enrollment.json` and `intent-enrollment.json` (16 KiB each).

The receiver opens its clock/work allowance before reading these originals and
genuinely admits the independent policy before waiting for a request. Historical
custody is provenance, not renewed execution authority. Incoming bytes cannot
choose their own policy, outcome, target, launch pins or clock.

Exactly two systemd descriptors arrive at 3/4 in either name order:

| Descriptor name | Fixed pathname | Path ownership/mode |
| --- | --- | --- |
| `serverware-oidc-session-activation-release-recovery-bootstrap` | `/run/serverware/oidc-session-activation-token-release/recovery-bootstrap.sock` | root:65532, 0660 |
| `serverware-oidc-session-activation-token-release` | `/run/serverware/oidc-session-activation-token-release/release.sock` | 65502:65532, 0660 |

Both are root-created listeners. The first accepted staging peer must be kernel
UID/GID 65532 before bytes are read. There is one accepted request and no alternate
peer, reconnect, status/error response or automatic retry. The wire is the fixed
purpose plus one server original; its ACK is `staged` plus the exact framed
bootstrap identity. See the [delivery transport](oidc-session-activation-release-recovery-delivery-transport.md).

## Exact resource handoff

The original-only [delivery admission](oidc-session-activation-release-recovery-delivery-admission.md)
reauthenticates the candidate against the four separately provisioned policy and
history originals. It requires RECOVERY, checkpoint 1 and the exact independently
pinned outcome digest, scopes and launch. Only then does the receiver open the
already provisioned digest-derived slot and private 32-byte delivery key. It checks
actual directory/listener pins and genuine key binding before ACK.

The unchanged resource layout is root public key 198, exact server bootstrap 199,
delivery key 200, outcome slot directory 201 and release listener 202. Public
originals/key are sealed; every retained descriptor is identity-checked and
non-inheritable. The slot is opened, never created, rewritten or asserted empty.
No outcome file is read or appended by this receiver, and no signer is present.

ACK means only exact bytes and observed resources have been staged. It precedes
normal close of the accepted staging socket and staging listener, the sole
permanent UID/GID 65502 drop, actual store recovery and serving. It is not
worker readiness, durable-record existence, completed exchange or token proof.
Only successful normal closes permit continuation. Cleanup closes actual owned
identities once; a reused or uncertain descriptor is not retried.

After ACK and close, the receiver passes the original work/window/deadline and
held-byte reserve to `resources._intake_from_delivery_on_work`, then the actual
existing runner. The resource layer re-admits sealed originals before private
use, drops privileges in the same PID, and selects genuine recovery handling.
The eventual worker must independently observe the exact existing checkpoint 1
record. No outcome-store creation or LIVE append branch is authorized here.

## Lifetime and capacity

The signed request timeout is clipped against the original pre-I/O sample,
including time spent admitting policy and waiting. The original limits, running
metrics, epoch and monotonic floors survive every stage. An outer receiver guard
retains the actual policy and delivery guards plus PID/thread identity. Their
nested callbacks reach only the receiver's base clock guard. Resources, startup
and store guards are downstream and never occur inside their own ancestor.

Before incoming body allocation, the 64 MiB representation allowance reserves the
held cold originals/material, repeated independent admission, fixed framing/key
and recovery-operation capacity, plus forty candidate-size footprints covering
framing/sealing, nested/canonical/capture representations and later resource
re-admission. This tightens the 16 MiB per-bootstrap cap. Concrete known original
fields and finite configuration graphs are measured after admission; the whole
held reserve is passed into resource intake before its rereads. No arbitrary
object graph, key serialization or claimed Python heap/RSS ceiling is involved.
The original cumulative work charges still apply independently.

## Opt-in packaging boundary

Three new uninstalled units form this path:
`serverware-oidc-session-activation-release-recovery-bootstrap.socket`,
`serverware-oidc-session-activation-release-recovery-dynamic.socket` and
`serverware-oidc-session-activation-release-recovery-dynamic.service.in`.
They conflict with the static and LIVE release service/socket owners; there is
never a second owner of `release.sock`. The service template binds the five-file
trust directory, existing key and outcome base read-only. Its substitutions are
`@RELEASE_WORKER_ROOT@`, `@RELEASE_RECOVERY_DYNAMIC_TRUST_DIR@`,
`@RELEASE_DELIVERY_KEY@` and `@RELEASE_OUTCOME_BASE_DIR@`.

Independent resource provisioning, platform read-only recovery/fsync behavior,
actual protected recovery exchange, public recovery HTTP/cookie completion and
runtime validation remain separate. A staging ACK does not close those gates.
