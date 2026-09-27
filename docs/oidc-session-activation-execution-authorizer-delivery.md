# Activation grant authorizer cold delivery

This is source packaging for the dedicated activation execution grant
authorizer, not an installation, deployment or successful runtime check. The
socket and service templates are unrendered/uninstalled; no account, key,
listener, enrollment, root pin or filesystem authority is provisioned here.

The fixed source path is the isolated
[`launcher`](../serverware/oidc_session_activation_execution_authorizer_launcher.py)
→ root [`entrypoint`](../serverware/oidc_session_activation_execution_authorizer_entrypoint.py)
→ permanently unprivileged [`runner`](../serverware/oidc_session_activation_execution_authorizer_runner.py).
The launcher is copied into the production image's fixed bootstrap directory,
and both source units are copied into its uninstalled systemd template inventory.
The image remains unbuilt; packaging is not evidence that this path has run.

## Exact originals and descriptors

The independently admitted release provides `/runtime/python/bin/python3`,
`/runtime/authority-bootstrap`, `/vendor` and `/app` under protected root-owned
directories. The launcher requires isolated Python and a fixed entry mode; it
does not import a caller-selected module or execute a checkout path.

The root trust directory is
`/run/serverware/oidc-session-activation-execution-authorizer-trust`, containing
the fixed required original names `root-public-key.pem`, `bootstrap.json`
and `custody.json`. The role and receiving originals remain separate files,
bounded at 4 MiB and 8 MiB respectively; the root public key is at most 16 KiB.

| FD | Original/resource |
| --- | --- |
| 198 | Sealed root public key |
| 199 | Sealed independent role bootstrap |
| 200 | Fixed activated listener |
| 201 | Sealed receiving-custody original |
| 202 | Sealed bundle AES key, exact32 bytes |
| 203 | Sealed delivery AES key, exact32 bytes |
| 204 | Sealed enrolled grant-authorizer Ed25519 private key, at most 4096 bytes |

Private source files are root-owned mode0400, single-link regular files under
protected ancestors, opened without following symlinks. Their fixed destinations
are `/run/secrets/serverware-oidc-session-activation-bundle-key`,
`/run/secrets/serverware-oidc-session-activation-delivery-key` and
`/run/secrets/serverware-oidc-session-activation-execution-authorizer-key`.

Only the purpose-specific bundle and delivery encryption keys are shared with
the admitted planner custody path. They are distinct raw32 keys whose actual
hashes must match the genuine receiving statement. This role receives neither
the planner signing key nor its journal encryption key. Its grant signing key
must match the actual separately enrolled authorizer public key; it is not a
caller, planner or current-root signing key. No key enters JSON or the socket
response.

## Admission before private access

Root delivery first owns the one activated listener and seals the three trust
originals. It then invokes the actual
[role bootstrap verifier](oidc-session-activation-execution-authorizer-bootstrap.md),
which verifies role, receiving, planner and purpose-enrollment originals on
one work object. The actual listener descriptor and pathname identities must
match the role's signed pins before any private key is opened.

Only then are private originals opened, sealed, checked against genuine AES
pins and the actual signing-key pair, and assigned to fixed descriptors.
FD/path identities and original launch bounds are checked before exec. Root
permanently clears supplementary groups and drops real/effective/saved GID/UID
to 65506:65506. The exact seven-descriptor inventory survives; an occupied or
additional descriptor fails closed. The child receives a literal minimal
environment, not caller-selected module, credential or secret settings.

The unprivileged startup repeats original admission and constructs the actual
[receiving custody owner](oidc-session-activation-execution-custody.md). Its
independent receiver identity comes from the separately signed role launch,
not a copy of the receiving statement's returned identity. All original
intervals and supplied request work/window/deadline remain binding. Local
file protection and matching signed measurements are not TEE, HSM, hostile-host
custody or independent anti-rollback evidence.

## Uninstalled systemd inputs

The [socket](../ops/systemd/serverware-oidc-session-activation-execution-authorizer.socket)
is fixed to `/run/serverware/oidc-session-activation-execution/authorizer.sock`,
UID65506/GID65532, mode0660, backlog1 and `Accept=no`. The activated FD is
nonblocking. Recreating the socket changes independently signed resource pins.

The [service template](../ops/systemd/serverware-oidc-session-activation-execution-authorizer.service.in)
uses only these independent provisioning placeholders:

- `ACTIVATION_AUTHORIZER_RELEASE_ROOT` — the admitted complete release;
- `ACTIVATION_AUTHORIZER_TRUST_DIR` — the three fixed trust originals;
- `ACTIVATION_AUTHORIZER_SIGNING_KEY` — the dedicated grant private key;
- `ACTIVATION_AUTHORIZER_BUNDLE_KEY` and `ACTIVATION_AUTHORIZER_DELIVERY_KEY` —
  the separately pinned private encryption originals.

The trust directory, three key files and fixed UDS directory are read-only
binds. There are no DB, TLS, state-socket, journal or writable store mounts.
Address families are restricted to AF_UNIX with IP traffic denied. The unit
retains the existing root-drop capability limit, no-new-privileges, protected
system/home/kernel interfaces, private temporary/device/IPC state, disabled
core dumps and bounded process/memory/FD resources.

The runner accepts at most one connection per cold launch, including rejection,
then stops. `Restart=no`, an infinite start-limit interval and burst1 prevent
automatic launch repetition. A failed or lost response does not establish that
no grant was produced; there is no automatic retry or fabricated denial claim.
The 300-second runtime cap and cooperative stop escalation are not a hard
syscall watchdog, cryptographic readiness proof or delivery acknowledgment.

This source slice exposes no public caller route, reserve/SQL role composition,
historical completion/recovery, session activation or token release. Those
remain independent authority, implementation and production-verification work.
