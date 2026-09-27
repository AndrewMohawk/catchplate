# Consume SQL cold delivery

The dedicated entrypoint, isolated launcher and finite runner deliver only the
`oidc-session-activation-delivery-execution-sql` role at UID/GID `65498`, with no
supplementary groups. They continue in the same isolated process after a
permanent root-to-service drop. No other activation, grant, reserve or generic
SQL profile is widened. The private service admits control-plane peer
`65532:65532`; this is not a public endpoint.

## Fixed originals and resources

The listener is
`/run/serverware/oidc-session-activation-delivery-execution/sql.sock`, activated
under the exact name `serverware-oidc-session-activation-delivery-execution-sql`.
Its nonblocking AF_UNIX stream listener and pathname must match the signed
device/inode pins. The path is `65498:65532`, mode `0660`; kernel peer `0:0`
reflects the root-created socket, not an assertion that requests run as root.

| FD | Original or resource | Ceiling |
| --- | --- | --- |
| 198 | Independent root public key | 16 KiB |
| 199 | Signed consume SQL role bootstrap | 4 MiB |
| 200 | Fixed listener | Not a byte original |
| 201 | SQL-issuer receiving-custody original | 16 KiB |
| 202 | Consume-planner bootstrap original | 4 MiB |
| 203 | Planning-history custody original | 8 MiB |
| 204 | Separate SQL receiving-history custody original | 8 MiB |
| 205 | Consume execution-bundle AES key | Exactly 32 bytes |
| 206 | Historical activation-bundle AES key | Exactly 32 bytes |
| 207 | Activation-delivery AES key | Exactly 32 bytes |
| 208 | Existing SQL attempt journal directory | Not a byte original |

The six trust files live below
`/run/serverware/oidc-session-activation-delivery-execution-sql-trust/`:
`root-public-key.pem`, `bootstrap.json`, `custody.json`, `planner-bootstrap.json`,
`planner-history-custody.json`, `receiving-history-custody.json`.
The AES paths use the prefix
`/run/secrets/serverware-oidc-session-activation-delivery-execution-sql-`
with suffixes `execution-bundle-key`, `historical-bundle-key`, `delivery-key`.
All are actual independently pinned bytes, not newly generated replacements.
No signing key or current-root state-service socket is delivered.

The fixed attempt directory is
`/var/lib/serverware/oidc-session-activation-delivery-execution-sql-attempts`,
mode `0700`, owner/group `65498:65498`. No-follow descriptor and pathname checks
join its actual device/inode to the signed scope; they do not create, reset or
adopt an attempt checkpoint. Actual journal recovery is a startup responsibility.

Five TLS originals live below
`/run/serverware/oidc-session-activation-delivery-execution-sql-tls/`:

| Purpose | Filename | Ceiling | Owner and mode |
| --- | --- | --- | --- |
| CA | `ca.pem` | 64 KiB | root, `0444` |
| Issuer certificate | `issuer.crt` | 64 KiB | root, `0444` |
| Issuer private key | `issuer.key` | 16 KiB | root:`65498`, `0440` |
| Executor certificate | `executor.crt` | 64 KiB | root, `0444` |
| Executor private key | `executor.key` | 16 KiB | root:`65498`, `0440` |

These fixed protected files remain available for libpq reopening after the
drop; they are not additional inherited descriptors. The actual
[SQL bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md)
derives separate deterministic issuer/executor DSNs from closed admitted
endpoint scalars, source-fixed roles and these paths: literal `hostaddr`,
`sslmode=verify-full`, `passfile=/dev/null`, `gssencmode=disable`. It independently
pins each TLS identity plus query and structure manifests. Exact environment
replacement removes ambient libpq settings; no caller chooses a DSN, password
file, TLS path or SQL text through delivery.

## Original-bound admission and lifecycle

`_construction_on_work(work)` opens the real processing bracket before root,
key or TLS file I/O. Fixed-path ancestors must be protected and root-owned;
files are opened without following symlinks and checked for type, owner,
single link, size and path/descriptor continuity. Every read charges its actual
validated length first. Original read/seal allocation is also precharged.
Trust and raw32 AES originals are copied into immutable fully sealed memfds;
private AES sources must be root-owned mode `0400`.

Root admission genuinely verifies the role and four detached
receiving/planning/history originals, independent receiver identity,
enrollments, source/configuration cohort, independent predecessor/current
pending pins and attempt checkpoint before any AES or TLS key is opened.
`_keys_on_work(material, work)` returns only the three AES originals after real
pairwise separation and root-pinned digest joins. A key or caller-provided
successful material object is not accepted as request authority.

`_tls_identity(tls_files, *, work)` captures all five pin records before file
access, validates each actual size against its pin, charges that size and one
hash, then uses a guarded native read/hash without changing work metrics inside
the callback. It returns only name, original metadata and digest. Later
`_tls_unchanged(identity)` calls check fixed-path metadata without rereading
private bytes. These trusted-host-local checks do not protect against malicious
root writers or a pathname replacement after the final observation.

The entrypoint joins listener, journal, TLS and all eleven descriptor identities,
permanently drops UID/GID, empties supplementary groups, verifies loss of
privilege and replaces the environment with exactly eight source-fixed entries.
Descriptors retain close-on-exec. There is **no post-drop exec, new construction
ledger or renewed window**, and standalone `--run` is rejected. The runner's
`_run_on_work(*, work, live_window, transport_deadline_ns)` supplies the original
objects to mandatory startup admission; actual sealed originals are verified
again rather than adopting a material carrier. Signed-launch freshness remains
separate and may narrow, never renew, the original allowance.

No privileged process-bound custody owner is constructed before dropping.
The final SQL role needs all held AES/TLS secrets; this same-process design
does not erase Python/OpenSSL copies or create hardware/hostile-host isolation.
Idle polling remains bounded by live startup authority. The first accepted
exchange is terminal even if rejected or uncertain; `close()` runs on every
runner exit. Delivery failure closes owned descriptor reservations and
duplicates. No automatic SQL retry, reissue, reseal or attempt reset is added.

## Deployment boundary

The socket, service and tmpfiles files are uninstalled source templates.
`CONSUME_SQL_RELEASE_ROOT`, `TRUST_DIR`, `TLS_DIR`, `EXECUTION_BUNDLE_KEY`,
`HISTORICAL_BUNDLE_KEY`, `DELIVERY_KEY` and `JOURNAL_DIR` are rendering inputs,
not runtime path overrides. The service binds trust, TLS, AES and ingress paths
read-only and permits writes only to the attempt directory. It uses
`Restart=no`, one-start limiting, backlog one and a finite lifetime. Network
families are limited to AF_UNIX/AF_INET/AF_INET6; independent host egress policy
must restrict PostgreSQL traffic to the admitted endpoint. No state socket is
mounted, and cooperative termination is not a hard kernel syscall watchdog.

Actual [startup and service](oidc-session-activation-delivery-execution-sql-service.md)
must compose independent current-pending admission, protected original replay,
the dedicated issuer, IDs-only executor and irreversible attempt owner. This
delivery layer neither treats an ACK as currentness nor substitutes a response
marker for a committed-original proof. Completion, historical reconciliation,
public permission and exact plaintext token release remain separate paths.

All source is unbuilt, unexecuted and unprovisioned. No account, key, TLS file,
database, permission, journal content or production acceptance was created or
verified by authoring these files.
