# Activation execution reserver cold delivery

This is source packaging for the dedicated activation reserver, not deployment,
provisioning or successful runtime evidence. The units remain unrendered and
uninstalled. No account, key, directory, enrollment, checkpoint or socket ACL is
created. The flow is the fixed isolated
[launcher](../serverware/oidc_session_activation_execution_reserver_launcher.py)
→ root [entrypoint](../serverware/oidc_session_activation_execution_reserver_entrypoint.py)
→ permanently unprivileged
[runner](../serverware/oidc_session_activation_execution_reserver_runner.py).

## Fixed originals and resources

The admitted complete release supplies protected root-owned `/runtime/python`,
`/runtime/authority-bootstrap`, `/vendor` and `/app`. The launcher requires
isolated Python and one fixed `--root-delivery` or `--run` entry, never a
caller-selected module or environment-supplied credential path.

The root-owned trust directory
`/run/serverware/oidc-session-activation-execution-reserver-trust` contains
`root-public-key.pem`, `bootstrap.json` and `custody.json`. They are independent
originals: the role launch is not a substituted receiving statement. Bounds are
16 KiB for the root public key, 4 MiB for the role bootstrap and 8 MiB for the
external receiving-custody original.

| FD | Original or resource |
| --- | --- |
| 198 | Sealed root public key |
| 199 | Sealed independent reserver role bootstrap |
| 200 | Fixed activated listener |
| 201 | Sealed receiving-custody original |
| 202 | Sealed bundle AES key, exactly 32 bytes |
| 203 | Sealed delivery AES key, exactly 32 bytes |
| 204 | Sealed enrolled computation Ed25519 private key, at most 4096 bytes |
| 205 | Signed, independently provisioned reservation journal directory |

Only the purpose-bound bundle and delivery keys share the existing fixed paths
`/run/secrets/serverware-oidc-session-activation-bundle-key` and
`/run/secrets/serverware-oidc-session-activation-delivery-key`. The computation
key is independently supplied at
`/run/secrets/serverware-oidc-session-activation-execution-computation-key`.
This role receives no caller, grant-authorizer, planner or completion private
signing key and no planner-journal encryption key. Private source files are
root-owned mode `0400`, single-link regular files with protected root-owned
ancestors; all fixed originals are opened without following symlinks and
checked against their pathname and descriptor before and after reading.

The journal is fixed to
`/var/lib/serverware/oidc-session-activation-execution-reservations`, owned by
`65505:65505`, mode `0700`. `_journal(fd)` joins its actual directory and fixed
pathname; `_journal_directory(device, inode)` opens only that existing signed
identity. Neither helper creates, clears or chooses a checkpoint from storage.
Actual durable record recovery and first-exact publication belong to the
reservation delivery owner, not this root FD handoff.

## Original admission before private access

Root delivery owns exactly one activated listener, reserves the eight fixed FD
slots and seals the three trust originals first. Actual
`oidc_session_activation_execution_reserver_bootstrap._verify_on_work` verifies
the original role, receiving custody, embedded planner and all purpose
enrollments before a private key or journal directory is opened. The kernel
listener and its separate pathname identity must match the signed role launch.
The independent receiver identity comes from that separately signed launch,
not a successful caller-supplied material object.

The entrypoint then seals the two raw AES keys and dedicated computation key.
`_keys_on_work(material, work)` compares actual key hashes to genuine receiving
pins and the actual computation key pair to its enrolled public key, returning
`(bundle_key, delivery_key, computation_private_key)` only to private startup.
The journal device/inode and exact descriptor inventory are checked before
the permanent real/effective/saved UID/GID drop to `65505:65505`, with no
supplementary groups. Listener, journal, sealed identities and the original
launch interval are rechecked before exec into the fixed runner.

The child receives only the literal eight-variable environment. Startup repeats
original admission and uses the same independently pinned enrollment,
predecessor/fence and journal checkpoint. No successful DTO is accepted as
authority. The root/local assurance flags remain false for hardware, native
stage-zero, HSM, TEE and external witness; protected paths and signed identity
assertions do not establish measured runtime or hostile-host anti-rollback.

## Uninstalled service inputs

The [socket](../ops/systemd/serverware-oidc-session-activation-execution-reserver.socket)
is `/run/serverware/oidc-session-activation-execution/reserver.sock`,
UID `65505`, group `65532`, mode `0660`, backlog one, `Accept=no`. Its activated
FD is nonblocking. Recreating it invalidates the original signed inode pins.

The [service template](../ops/systemd/serverware-oidc-session-activation-execution-reserver.service.in)
uses these independent provisioning placeholders:

- `ACTIVATION_RESERVER_RELEASE_ROOT` and `ACTIVATION_RESERVER_TRUST_DIR`;
- `ACTIVATION_RESERVER_COMPUTATION_KEY`, `ACTIVATION_RESERVER_BUNDLE_KEY` and
  `ACTIVATION_RESERVER_DELIVERY_KEY`;
- `ACTIVATION_RESERVER_JOURNAL_DIR`.

Trust, private keys, the fixed listener directory and current-root socket
directory are read-only binds; only the reservation journal is writable.
There are no DB, TLS, planner-journal or execution-bundle-store mounts. AF_UNIX
is the only allowed address family and IP traffic is denied. Existing root-drop
capability restrictions, no-new-privileges, protected system/home/kernel state,
private temporary/device/IPC state and resource limits remain in place.

The independently operated state service must admit the signed
[v5 activation reserve profile](current-root-activation-reserver-peer.md):
UID/GID `65505` may only reserve signed `oidc.session.activate`. State remains
UID/GID `65516` while its root-created listener peer is `0:0`; startup retains
those distinct signed identities. State-socket DAC/ACL access must be
independently provisioned. A bind mount or root-signed profile supplies no ACL,
and the planner's `65507` head-only access is not reserve permission.

The runner stops after one accepted request, including rejected or uncertain
delivery. `Restart=no`, infinite start-limit interval and burst one prevent
automatic launch repetition. Original launch/request deadlines remain binding;
the 300-second runtime cap and cooperative termination are not a hard syscall
watchdog or cryptographic readiness proof. A failure does not establish that
no pending reservation was published. Explicit exact-original receipt recovery
does not authorize regeneration, automatic resend or renewed execution.

This path does not execute SQL, complete the activation, expose a public caller
permission, release a token or claim currentness. Those remain separate
authority, implementation and production-verification work. No runtime,
container, parser or test verification has been performed for this source batch.
