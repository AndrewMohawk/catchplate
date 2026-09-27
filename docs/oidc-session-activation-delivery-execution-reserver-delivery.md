# Consume reservation cold delivery

The fixed entrypoint, isolated launcher and finite runner deliver the dedicated
`oidc-session-activation-delivery-execution-reserver` role. They do not relabel a
grant authorizer or widen an existing activation, registration or SQL role.
The same isolated process permanently drops from root to UID/GID `65499`, with
empty supplementary groups, and admits only control-plane peer `65532:65532`.

## Fixed originals and descriptors

The listener is
`/run/serverware/oidc-session-activation-delivery-execution/reserver.sock`, under
the socket-activation name
`serverware-oidc-session-activation-delivery-execution-reserver`. Its pathname
must be owned by `65499:65532`, mode `0660`; root creates the kernel listener.
Kernel listener peer `0:0` denotes socket-activation provenance, not the UID of
the process serving a request.

| FD | Original or resource | Byte ceiling |
| --- | --- | --- |
| 198 | Independent root public key | 16 KiB |
| 199 | Signed reserver role bootstrap | 4 MiB |
| 200 | Fixed nonblocking AF_UNIX stream listener | Not a byte original |
| 201 | Separate reserve receiving-custody original | 16 KiB |
| 202 | Consume-planner bootstrap original | 4 MiB |
| 203 | Planning-history custody original | 8 MiB |
| 204 | Separate reserve-history custody original | 8 MiB |
| 205 | Consume execution-bundle key | Exactly 32 bytes |
| 206 | Historical activation-bundle key | Exactly 32 bytes |
| 207 | Activation-delivery key | Exactly 32 bytes |
| 208 | Enrolled current-root computation private key | 4096-byte Ed25519 PEM |
| 209 | Existing reservation journal directory | Not a byte original |

The six root trust files are below
`/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/`:
`root-public-key.pem`, `bootstrap.json`, `custody.json`, `planner-bootstrap.json`,
`planner-history-custody.json`, `receiving-history-custody.json`.
The four private paths use the fixed prefix
`/run/secrets/serverware-oidc-session-activation-delivery-execution-reserver-`
and suffixes `execution-bundle-key`, `historical-bundle-key`, `delivery-key`,
`computation-key`. The actual AES bytes must match the independently admitted
purpose pins; this is not permission to generate replacement keys.

The journal directory is
`/var/lib/serverware/oidc-session-activation-delivery-execution-reservations`,
owned by `65499:65499`, mode `0700`. Its no-follow path and descriptor must match
the signed device/inode pins. Opening it does not create, reset or adopt a
journal checkpoint. No grant signer, planner signer, journal encryption key,
database or TLS credentials are delivered.

## Original allowance through the permanent drop

`_construction_on_work(work)` obtains the real construction bracket before root
original or key I/O. The root path uses one actual ledger, live window and
absolute deadline for bounded reads, original admission and key-pair joins.
Every read charges the actual validated file size before reading; original
read/seal allocation is charged before either allocation. The paths are fixed,
opened without symlinks through protected root-owned ancestors, and checked
for file type, owner, link count, size and unchanged path identity. Private
sources are root-owned mode `0400`. Only immutable fully sealed copies survive
at the fixed material descriptors.

The actual [role bootstrap](oidc-session-activation-delivery-execution-reserver-bootstrap.md)
authenticates the role, four detached receiving/planning/history originals,
enrollments, independent receiver identity and state/journal scope before keys
or the journal are opened. `_keys_on_work(material, work)` returns the three
AES keys and computation private key only after genuine root-pinned key joins
and the actual enrolled Ed25519 private/public pair check. It does not accept
a caller-supplied success flag or turn key possession into request authority.

After checking the twelve descriptors and resource identities, the process
drops UID/GID permanently, empties supplementary groups, checks loss of
privilege, and replaces its environment with the exact eight source-fixed
entries. It **does not exec or reopen a construction window after the drop**.
The fixed descriptors retain close-on-exec; no private descriptor export to a
child process is needed or enabled by this handoff.
The fixed runner's `_run_on_work(*, work, live_window, transport_deadline_ns)`
passes the original objects into the actual
[startup service](oidc-session-activation-delivery-execution-reserver-service.md).
Standalone `--run` is rejected. Startup reauthenticates the sealed originals
and narrows the inherited allowance; a later signed-launch opening sample
never renews the original processing deadline or ledger. Launch freshness is
checked separately from this original processing bound.

No process-bound privileged custody owner is constructed before the drop.
The same Python process retains only public-root admission data and secrets
already required by the final reserver role, never a root private signing key.
This is a trusted-host-local confinement design, not a hostile-host isolation,
memory-erasure, TEE or hardware-custody claim.

The runner polls only while no request has been accepted and the actual startup
authority remains live. The first accepted request is terminal, including
failure or uncertain delivery. Every exit closes the actual service; root
delivery tracks and closes its owned descriptor reservations and duplicates on
failure. No automatic resend, re-signing, journal rollback or retry is added.

## Uninstalled deployment inputs and boundaries

The `.socket`, `.service.in` and dedicated `.tmpfiles.conf` are source templates,
not installed configuration. The unit binds trust and key paths read-only,
exposes the existing state socket directory read-only, and permits writes only
to the admitted reservation journal. It allows AF_UNIX only and uses
`Restart=no`, a single-start limit, backlog one and a finite process lifetime.
The fixed command is the isolated launcher with `--root-delivery`.
`CONSUME_RESERVER_RELEASE_ROOT`, `TRUST_DIR`, `COMPUTATION_KEY`,
`EXECUTION_BUNDLE_KEY`, `HISTORICAL_BUNDLE_KEY`, `DELIVERY_KEY` and `JOURNAL_DIR`
are explicit rendering placeholders, not runtime path overrides.

Installing these templates, accounts, keys, immutable release, journal content,
signed pins and host permissions remains independent provisioning. The
[state v8 profile](current-root-delivery-reserve-peer.md) and explicit access to
the state socket for UID `65499` are separate prerequisites; a bind mount does
not grant access or broaden the reserve-only consume purpose. A sampled head
or static predecessor is not action-time authority. Actual signed computation,
locked state transition and first-exact durable ACK remain required.

This delivery source is unbuilt and unexecuted. It does not establish production
readiness, SQL one-use consumption, completion, public permission, recovery or
plaintext token release. Cooperative process timeouts are not a hard kernel
syscall watchdog. Independent cold SQL pending admission remains a separate
consumer of the exact reservation originals.
