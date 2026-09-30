# Native pilot process coordinator

`scripts/run_native_pilot_coordinator.py` owns one real conductor process and
relays its ordered public machine exchanges to an independent supervisor. It
does not approve requests, hold signing keys, provision private credentials, or
automatically run the authority/install commands. This is an implemented
process-and-transport connection, not a running or accepted pilot.

The separate `scripts/run_native_pilot_authority_coordinator.py` now connects
the same real process owner to fixed signing/publication jobs. It requires a
distinct independent approval exchange for every job; it does not make those
decisions itself. The transparent relay above is unchanged. Neither command has
been executed as evidence of pilot readiness.

## Prerequisites and fixed command

The coordinator runs as root under independently protected source and Python
dependencies, with isolated/no-bytecode Python. Its stdin and stdout must be two
distinct root-owned machine pipes, respectively read-only and write-only, under
the exclusive independent supervisor. They are not an interactive terminal or
shell command stream. Stderr carries bounded, sanitized status, not originals.

```text
python3 -I -B scripts/run_native_pilot_coordinator.py --run-native-pilot --runtime-inventory-fd 3 --runtime-inventory-sha256 sha256:INDEPENDENTLY_APPROVED_INVENTORY_DIGEST
```

The placeholder is deliberately invalid. FD 3 supplies an existing protected
`serverware.nativePilotConductorRuntime/v1` inventory, at most 16 MiB, whose
literal bytes match the independently approved SHA. It is not a path selector,
an embedded archive, or an assertion that JSON owns a process. The package stores
this object as `package.json`'s `inventory`; use that object's canonical no-LF
bytes, matching its `inventorySha256`, not the whole package/build report. The
independent provisioner supplies the protected FD and approves the pin before
launch; extracting an object does not approve it. The corresponding
runtime must already be installed at its fixed absolute paths; the owner checks
actual installed records, bytes, modes and their source-manifest association.
The [runtime packaging route](native-pilot-build.md) produces source/package
observations; neither a locally computed pin nor this inventory creates release
approval, dependency approval or permission to launch.

The only conductor argv is:

```text
/runtime/python/bin/python3 -I -B /app/scripts/native_pilot_runtime_entrypoint.py --run-native-pilot
```

The installed Python 3.11 bootstrap requires that exact interpreter and argv and
adds only `/vendor` and `/app` before running `/app/scripts/run_native_pilot.py`.
The complete `/app/serverware` package and the two fixed scripts are bound to
`/usr/share/serverware/source-manifest.json`. No caller-supplied executable,
module, environment import path or shell fragment is accepted. No authority-key
FD passes to the child. The existing driver control/configuration/window and
all separate native pilot artifacts, service resources and provisioning remain
required; this command installs none of them.

## One process, eleven exact phases

The concrete owner is
`serverware.native_pilot_coordinator_process.ConductorProcess`:

```text
prepare(runtime_inventory_fd=..., runtime_inventory_sha256=...) -> owner
owner.start()
owner.receive() -> retained Request
owner.reply(request, inputs)
owner.close() -> terminal result
```

`Request` exposes sequence, phase, copied payload, exact raw request bytes and
the original BOOTTIME deadline. The entrypoint follows the actual
`native_pilot_operator_channel.STAGES` once, in this order:

| # | Phase | Required independent handoff |
| --- | --- | --- |
| 1 | `bootstrap-admission` | Approve/sign/publish the actual prepared bootstrap admission. |
| 2 | `endpoint-precreation` | Install the approved fixed precreation originals before acknowledging. |
| 3 | `endpoint-inputs` | Supply approved public preparation inputs and actual object-directory reference. |
| 4 | `endpoint-deliveries` | Supply the three endpoint C9 deliveries; the conductor then obtains the real intake/genesis result. |
| 5 | `service-originals` | Supply the later service/grant/launch originals bound to those real results. |
| 6 | `bridge-runtime` | Install approved public runtime/outgoing files before resource allocation. |
| 7 | `bridge-delivery` | Supply the launch pin after C9 binds the actual bridge activation inventory. |
| 8 | `release` | Supply endpoint release, phase-two scope and public bundle originals. |
| 9 | `constructed-admission` | Approve/sign/publish the exported constructed census/public-original binding. |
| 10 | `generation-origin` | Request the existing actual installed-generation observation; do not supply a success verdict. |
| 11 | `shutdown` | Reply with the fixed stop action, then await actual cleanup. |

The relay verifies that the child's raw canonical request exactly equals the
envelope emitted upstream. Replies bind the request SHA, sequence and phase;
the same approved `inputs` then go back to that retained child request. No
projection changes the hash or removes the original deadline. Frames are
canonical ASCII JSON plus one LF, at most 32 MiB each, with the existing 128 MiB
aggregate channel budget. These transport checks do not approve the payload.
There is no skipped phase, unsolicited future reply, automatic retry or new
startup window. See [authority commands](native-pilot-authority-commands.md) for
the separate purpose-specific producers and restricted public installers.

## Authority coordinator: separately approved jobs

The authority coordinator runs **60 fixed jobs** across those same eleven phases
and accepts **42 fixed key-purpose selectors**. Its invocation synopsis is:

```text
python3 -I -B scripts/run_native_pilot_authority_coordinator.py --run-native-pilot --runtime-inventory-fd N --runtime-inventory-sha256 SHA --authority-key PURPOSE=FD [repeat for every fixed purpose]
```

This is a synopsis, not a ready-to-run command. `N`, `SHA` and every key FD must
come from independent provisioning. The exact selector inventory is
`native_pilot_phase_execution.KEY_PURPOSES`; all selectors are required once:

| Selector family | Fixed selections | Count |
| --- | --- | --- |
| Driver/cohort | `driver-bootstrap`, `driver-constructed`, `cohort-precreation`, `cohort-release`, `driver-scope` | 5 |
| `native-delivery-<role>` | The ten endpoint roles in the operator-input guide, plus `bridge` | 11 |
| `ordinary-delivery-<role>`, `ordinary-generation-<role>` | Each of the five ordinary roles | 10 |
| `native-service-<operation>` | `ingress`, `ledger`, `terminal`, `dispatchBarrier`, `activeEffectBarrier`, `activeEffectCommit`, `retrieval`, `commitRequest`, `persistence`, `trustedTime` | 10 |
| Generation/dispatch | `native-generation-install-grant`; `ordinary-dispatch-durable-recovery-store`; `ordinary-dispatch-current-signature-authority` | 3 |
| Ordinary spool | `ordinary-head`, `ordinary-cleanup`, `ordinary-current` | 3 |

Each supplied key FD is an already provisioned root:root `0400`, sealed 32-byte
Ed25519 memfd. The existing purpose producer verifies the selected authority;
the selector itself grants no permission. The coordinator consumes the supplied
FDs, retains private CLOEXEC duplicates, and starts the conductor with
`close_fds=True`. No key or key FD enters its request/reply protocol or the
conductor. These software-key controls are not measured/non-exportable custody.

The [separate authority runtime package](native-pilot-build.md#authority-coordinator-runtime-package)
supplies these scripts and dependencies, but still needs an independently
protected installation. They are **not** included in the conductor runtime's
two-script package. Native artifacts, private service
credentials, protected directories and the independently operated supervisor
still must be provisioned; this command generates none of them.

The separate job channel uses `serverware.nativePilotAuthorityJobRequest/v1`
and `serverware.nativePilotAuthorityJobReply/v1`. Each request binds its global
exchange `sequence`, `conductorSequence`, `conductorRequestSha256`, `phase`,
`jobIndex`, fixed `job`, and original `deadlineBoottimeNs`. The first job of a
phase includes the actual `conductorRequest`; subsequent jobs use that retained
binding. `previousResult` exposes only the preceding actual public output or
installation result. The source-selected job order is not a caller job list.

For each job the independent supervisor must approve the complete next input
and install these two new files before replying:

```text
/etc/serverware/native-pilot-authority/<phase>/<job>.approval.json
/etc/serverware/native-pilot-authority/<phase>/<job>.input.json
```

Names come only from the fixed source job table. Both files must be protected
root:root `0400`, single-link regular originals, opened read-only/no-follow under
protected root-owned ancestors. No path is accepted in the reply. The approval
original is canonical ASCII JSON without LF, at most 8 KiB, with exactly:

```text
apiVersion = serverware.nativePilotAuthorityJobApproval/v1
conductorSequence, conductorRequestSha256, phase, jobIndex, job,
deadlineBoottimeNs, inputSha256
```

The job reply has exactly these ten fields:

```text
apiVersion = serverware.nativePilotAuthorityJobReply/v1
sequence, conductorSequence, conductorRequestSha256, phase, jobIndex, job,
requestSha256, approvalSha256, inputSha256
```

`requestSha256` binds the complete canonical job request without LF. The two
approved hashes identify the exact protected files; the approval's input hash
and original deadline must match. The input retains its existing purpose-specific
grammar and byte ceiling. Job frames remain canonical ASCII plus one LF, bounded
to 32 MiB each and 128 MiB aggregate; retained job originals are also bounded
to 128 MiB. A pipe or matching hash alone does not establish independent approval
provenance: the separately operated supervisor and its protected-install
capability are mandatory external prerequisites.

The supervisor can use `scripts/install_native_pilot_approval.py` for that
protected-install step. It takes the actual job-request original and the
**already independently approved** literal approval/input originals on three
distinct protected FDs, plus independently authenticated approval/input hashes.
It accepts only the existing fixed job table, checks the original request,
sequence, deadline and complete-input binding, and publishes input first and
approval last at the two paths above. Both destinations must be absent; parents
must already be protected and provisioned. Actual exclusive creation, fsync,
readback and retained-file checks precede the returned exact ten-field job reply.
This is not atomic: any partial pair remains, with no replacement or retry.

The [installer invocation](native-pilot-authority-commands.md#per-job-approval-installation)
belongs to the independently protected supervisor environment, not either
runtime package's entrypoint. It creates neither an approval policy nor an
approval service. Its root-owned pipe output is canonical JSON without LF; the
supervisor must capture successful completion and the full reply before adding
the channel's one LF and forwarding it. The existing coordinator still binds
that reply to its actual pending request and independently opens the originals.
Neither publication nor a matching hash establishes an independent decision.

Later inputs may embed signatures just produced by earlier jobs. Each therefore
gets a **new independent approval of its complete bytes after the actual prior
output exists**. The executor does not fill placeholders, infer permission from
child observations, or treat one phase approval as permission for future inputs.
It calls the existing purpose producers/installers and constructs conductor
replies only from successful actual publication results or independently pinned
existing originals it opened. The original startup/lifetime and cleanup reserve
remain unchanged throughout all jobs; there is no per-job renewal.

Any failed or partial operation fences the attempt. New files remain in place;
there is no rollback, replacement or automatic signing/publication retry.
Retained authority inputs and key capabilities are released only after the real
conductor's terminal cleanup result and reap, or proof no child was started.
Unknown cleanup retains the owners for external supervision.

## Cleanup and evidence boundary

The owner retains the actual child, PIDFD and pipes. After normal completion or
failure, the coordinator makes one cleanup attempt. A spawned child's clean
result requires its genuine stderr terminal original, terminal PIDFD, actual
reap and a matching exit status. The child result is
`serverware.nativePilotOperatorResult/v1`; the coordinator emits its own
`serverware.nativePilotCoordinatorResult/v1` summary (or
`serverware.nativePilotAuthorityCoordinatorResult/v1` for the authority caller).
Neither substitutes for
the other's process evidence. Closing before start returns the distinct
`serverware.nativePilotCoordinatorNotStarted/v1`, never workload-cleanup proof.

Cleanup may signal that retained PIDFD once with SIGTERM and wait only within
the original cleanup reserve/lifetime. Unknown cleanup raises while retaining
the owner; the coordinator reports `cleanup-unknown-owner-retained` and waits
for external supervision instead of killing, restarting or discarding it.
Repeated SIGINT/SIGTERM is ignored during that retained cleanup boundary.
An external watchdog remains necessary for unbounded kernel/filesystem stalls.

Exit zero requires the actual `stopped-cleanup-complete` result after all phases.
Both `pilotAcceptanceVerified` and `productionReleaseEligible` remain false,
including on that exit. Process cleanup is not ordinary application allow/deny
acceptance, request-evidence validation, or production readiness.

Fixed signing/install execution is connected by the authority caller; independent
approval decisions and provisioning remain external. The transparent relay still
executes no authority jobs. Neither path establishes production acceptance, and
no coordinator or pilot was executed while this implementation and guide were
authored.
