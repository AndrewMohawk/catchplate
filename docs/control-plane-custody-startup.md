# Cold control-plane custody startup

Source `.127`; implementation only, unbuilt and unexecuted. This documents the
trusted-host-local provisioning and descriptor handoff, not a Nitro/TEE storage
or deployment guarantee. It supplies one actual caller client/journal owner;
it does not provision the independent authority services or admit a public
business workflow.

## Provisioned inputs

The root `authority_fd_entrypoint` uses two fixed custody locations:

- Startup configuration: `/run/serverware/authority-trust/control-plane-custody.json`.
- Journal directory: `/var/lib/serverware/control-plane-custody`.

The separate [enrollment bootstrap](control-plane-enrollment-startup.md) is now
also mandatory for that root entrypoint, including explicitly disabled enrollment.
Its sealed bootstrap and optional private-key descriptors must already belong
to the same exact root-signed inherited inventory.

The configuration is a root-owned, single-link regular file, not group/world
writable. It must be exact canonical ASCII JSON: sorted keys, compact separators,
no extra whitespace, duplicate/unknown fields or non-JSON constants. Its complete
size is 2..16384 bytes and its exact ten fields are:

| Field | Required value or bound |
| --- | --- |
| `schema` | `serverware.controlPlaneCustodyStartup/v1` |
| `sourceRevision` | The actual current `authority_contract.SOURCE_REVISION` |
| `configurationDigest` | Canonical SHA-256 identity matching admitted runtime trust |
| `directoryFd` | Exact integer 32..1023, an unoccupied inherited slot |
| `device` | Actual directory device, unsigned 64-bit range |
| `inode` | Actual directory inode, 1..2⁶⁴−1 |
| `uid` | Exactly 65532 |
| `gid` | Exactly 65532 |
| `quotaBytes` | Exact integer 1..8 GiB |
| `maximumRecords` | Exact integer 1..4096 |

These are independently provisioned values, not sample pins to copy or values
learned from a retained plan. The configuration is not a signed receipt. Root
delivery, sealing, actual directory identity and the separate runtime-root trust
admission supply its startup boundary.

The directory must already exist with the pinned device/inode, UID/GID 65532
and exact mode 0700. The entrypoint opens `/`, `/var`, `/var/lib` and
`/var/lib/serverware` component by component with `O_NOFOLLOW`; each ancestor
must be root-owned and not group/world writable. It opens and checks the final
directory without creating it or changing ownership. Journal files retain the
private mode/identity, lease, quota and recovery requirements in the
[journal contract](control-plane-custody-journal.md).

Production Compose requires an explicit host source:

```yaml
- type: bind
  source: ${SERVERWARE_CONTROL_PLANE_CUSTODY_DIR:?preprovision private custody journal uid 65532 gid 65532 mode 0700}
  target: /var/lib/serverware/control-plane-custody
  bind:
    create_host_path: false
```

The startup JSON is delivered through the existing read-only authority-trust
directory mount. Neither Compose nor the entrypoint supplies `mkdir`, `chown`,
default storage, fabricated identity values or automatic quota expansion.

## Exact descriptor handoff

Before dropping privilege, the root entrypoint reads the bounded configuration
without following its final symlink and seals its original bytes into a
root-owned memfd. Seal, shrink, grow and write seals are all required. The
configuration receives its own inherited FD in 32..1023, distinct from
`directoryFd`; occupied slots are rejected, never overwritten.

The child receives `SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD` as canonical
decimal text. The directory path is fixed by the entrypoint; its identity and
FD slot come from the sealed document, not a caller-selected path environment
variable. The root-signed runtime trust
inventory must **already exactly include both retained descriptors**, together
with the existing runtime-root and runtime-trust descriptors and any other
independently admitted inherited descriptors. Delivery does not extend that
  signed inventory automatically.

The cold client performs actual runtime-root signature, current
configuration/source, process/identity, attestation and exact inherited-FD
admission before the journal opens its private directory handle. The document's
configuration digest must match that admitted runtime configuration. Opening an
extra private handle before admission would change the inventory and is not a
supported workaround.

## Startup and lifetime

```text
root FD delivery -> drop to UID/GID 65532 -> cold runner
    -> sealed config + actual runtime admission + journal lease/recovery
    -> enrollment startup reuses the admitted root and original FD inventory
    -> application/server imports and database startup gates
    -> ASGI requires the existing shared owner -> serve
    -> close shared owner on startup failure or server exit
```

`control_plane_runner.main` initializes `control_plane_custody_startup` before
importing the application/database configuration or HTTP runtime. Admission
completes once and retains the real `ControlPlaneCustodyClient`, including its
admitted runtime client, actual root public key, immutable original FD inventory
and journal. Enrollment initialization reuses those retained pins without
re-running runtime admission after the journal opens its private handle.
ASGI startup calls both owners' `require_started`;
a legacy PID environment marker cannot replace this owner. Error paths and normal
server return close it, preserving the original failure if cleanup also fails.

Only unconfigured `dev`, `development`, `local` or `test` may opt out. Production
without the handoff fails. Any explicit custody `_FD` or `_PATH` setting,
including an empty value or partial configuration, requires strict admission;
only the fixed configuration-FD setting is accepted. Environment drift, failed
admission or shutdown cannot trigger in-process reinitialization.

The owner is PID-bound and singleton. Forked use, multiple workers sharing it,
automatic retries and implicit credential/receipt refresh are not supported.
Original runtime-attestation lifetime checks remain live through requests; a
stored owner does not renew them. Close before forking; an inherited private FD
can otherwise keep the parent's lease alive until the child exits or closes it.

Existing legacy dispatch reuses the actual admitted runtime client with its
unchanged operation allowlist and response verification. That compatibility
path is **not journal-protected** and does not gain successor execution authority.
Custody forwarding and reconciliation remain explicit separate client actions.
A successful fresh readback may retain its first unsigned local observation;
stored observation metadata is never fresh proof, a terminal business state,
permission to reset an attempt or authority to resend.

## Remaining deployment work

This source integration has not been built or exercised. Operators still need
independent directory/configuration/descriptor provisioning and the separately
admitted runtime relay, verifier, planner, writer and supporting infrastructure.
Public preparation/invocation, complete business successor orchestration and
execution, cross-source historical replay, and frozen build/runtime validation
remain unfinished. Host-local filesystem durability and a returned local owner
are not substitutes for those release requirements.
