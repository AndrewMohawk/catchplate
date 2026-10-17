# Cold control-plane custody startup

Source `.127`; implementation only, unbuilt and unexecuted. This documents the
trusted-host-local provisioning and descriptor handoff, not a Nitro/TEE storage
or deployment guarantee. It supplies one actual caller client/journal owner;
it does not provision the independent authority services or admit a public
business workflow.

## Provisioned inputs

The root `authority_fd_entrypoint` uses two fixed custody locations:

- Startup configuration: `/run/catchplate/authority-trust/control-plane-custody.json`.
- Journal directory: `/var/lib/catchplate/control-plane-custody`.

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
| `schema` | `catchplate.controlPlaneCustodyStartup/v1` |
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
`/var/lib/catchplate` component by component with `O_NOFOLLOW`; each ancestor
must be root-owned and not group/world writable. It opens and checks the final
directory without creating it or changing ownership. Journal files retain the
private mode/identity, lease, quota and recovery requirements in the
[journal contract](control-plane-custody-journal.md).

Production Compose requires an explicit host source:

```yaml
- type: bind
  source: ${CATCHPLATE_CONTROL_PLANE_CUSTODY_DIR:?preprovision private custody journal uid 65532 gid 65532 mode 0700}
  target: /var/lib/catchplate/control-plane-custody
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

The child receives `CATCHPLATE_CONTROL_PLANE_CUSTODY_CONFIG_FD` as canonical
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

## Configuration versus writer admission, 2026-10-11

The ordinary startup gate previously called `db.require_atomic_release_writer`
directly from the hot control-plane process. That guard correctly requires a
measured executor context, so it prevented startup from reaching the installed
external reconciliation facade. Both startup call sites now use
`db.require_atomic_release_storage_configuration` instead. The helper checks
configured PostgreSQL backends and matching nonempty DSNs only; it does not
connect, verify schema/connectivity, acquire writer authority or establish
readiness. The privileged writer guard is unchanged.

Startup still dispatches reconciliation and audit draining through the actual
installed facades, before CA material and the final PID marker. Exceptions still
abort startup. This is a handoff repair, **not completed atomic startup**: the
current `release.reconcile` kernel requires an attempt identifier, while the
startup facade supplies only `limit`, `now_epoch_ms` and `actor_id`. A genuine
bounded candidate-selection/reconciliation adapter is still missing. The audit
kernel has an empty-candidate result, but that does not repair reconciliation
or establish that the entire backlog is empty. Neither a fabricated candidate
nor a synthetic successful transport response is acceptable production proof.

The complete real transition registry and planner now import successfully.
Older registration tests incorrectly expected six missing recovery programs;
those operations are explicitly disabled, absent from planning, and denied by
the current contract. Updated tests use the actual registry for positive
closure, then remove enabled entries or insert disabled ones for negatives.
Registry closure does not make disabled recovery available or prove execution.

Run the offline configuration, facade and registration controls with
`make verify-control-plane-startup-dispatch`; set `TEST_PYTHON_RUN` to an existing
dependency-equipped Python runner to reuse it without a build. These controls
do not start a pilot, PostgreSQL or a provider connection. Their synthetic
transport boundary is not measured authority, native startup or live app proof.
The cached, network-disabled dependency image passed all 27 controls in that
target, plus all 19 existing startup/service-credential controls. The standalone
startup suite now explicitly selects its required control-plane process mode.
The broader script is not green: a bounded run was stopped without a final
suite result, then two targeted typed-planner controls reproduced an expected
error mismatch (`typed transition query identity changed`) and a test call to
`_read_root_set` missing `deadline_epoch_ns`. Those failures were not repaired or
counted as passes in this batch.
No running app deployment, DNS record or retained pilot state was changed by
this source/test batch.

### Follow-up verification and remaining implementation seams

The two targeted typed-planner fixtures were subsequently repaired and passed
together (2/2, 6.794 seconds in the same cached, network-disabled image). The
revocation test now verifies that the real successor-only operation refuses the
legacy entry before clock/SQL access, then independently exercises the original
missing-complete-acquisition denial with actual kernel-generated queries. The
root-reader comparison supplies one finite epoch/monotonic deadline to every
read; no read renews it. Neither repair changes a production guard.

The next fail-fast run passed those two and failed the inter-store tamper test
before its intended callback. Its 4,347,128-byte signed fixture exceeds the
unchanged 64 MiB / 1,000,000-node cumulative verification limits while encoding
the payload. Independent existing cost oracles predict 260,493,088 byte-work
units for the first persistence and 570,170,986 for the joined two-store flow;
those are predicted work, not a successful execution or memory measurement.
The affected-only run also failed (9.369 seconds). Its existing tamper and
rollback assertions remain unchanged. Reducing the fixture's approval scope or
increasing production ceilings would not establish the required full workflow.
Raw proof replay, original deadlines and audit effects must survive any work
reduction. The broader suite remains unverified, not passing.

The identified repeated work is raw decoding in `authority_revocation_wire`,
decoded-graph recapture and envelope/payload encodings in
`authority_revocation_plan`, then base64 materialization and repeated SQL-value
copy/comparison in `authority_store/revocation_retention`. Both stores must keep
independent genuine replay. The next optimization should reuse only privately
owned representations inside one invocation, with actual stored-row readback,
signature/proof verification and currentness checks retained. A cross-call
successful-result cache or a public prevalidated flag is not an acceptable fix.
No such optimization or successful full-budget execution is established yet.

Source tracing also rules out an attempt-ID-only reconciliation repair:

1. Due-candidate selection needs authenticated expiry ordering, range/cardinality
   and primary-row proofs, transactional index maintenance, and explicit empty
   or remaining-work evidence. The challenge-maintenance implementation is a
   reference pattern, not a release-table adapter.
2. The release receipt consumer exists, but a purpose-bound reconciliation
   producer and admission path do not. Existing WebAuthn evidence admission
   cannot be relabelled. Real JIT/quota components, current rows and the original
   cutoff/window must bind the receipt, which must be consumed once.
3. The operation contract already permits durable budget and traversal writes;
   the narrower release kernel does not acquire or validate those child changes.
   Reserved v2 attempts must abort all children atomically; expired dispatched
   attempts must retain charged uncertainty. Adding table names to the kernel
   allowlist alone is insufficient.
4. The measured owner must join candidate acquisition, evidence and all v1/v2
   mutations with fresh current-root/CAS checks, bounded continuation and outcome
   recovery after an uncertain commit. Startup needs actual completed maintenance
   and audit delivery, not a synthetic success or one empty candidate selection.

These are pending source/runtime joins. No production operation was enabled,
no receipt or writer context was invented, and no live pilot was restarted.

## Remaining deployment work

This source integration has not been built or exercised. Operators still need
independent directory/configuration/descriptor provisioning and the separately
admitted runtime relay, verifier, planner, writer and supporting infrastructure.
Public preparation/invocation, complete business successor orchestration and
execution, cross-source historical replay, and frozen build/runtime validation
remain unfinished. Host-local filesystem durability and a returned local owner
are not substitutes for those release requirements.
