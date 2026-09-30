# Native pilot process coordinator

`scripts/run_native_pilot_coordinator.py` owns one real conductor process and
relays its ordered public machine exchanges to an independent supervisor. It
does not approve requests, hold signing keys, provision private credentials, or
automatically run the authority/install commands. This is an implemented
process-and-transport connection, not a running or accepted pilot.

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

## Cleanup and evidence boundary

The owner retains the actual child, PIDFD and pipes. After normal completion or
failure, the coordinator makes one cleanup attempt. A spawned child's clean
result requires its genuine stderr terminal original, terminal PIDFD, actual
reap and a matching exit status. The child result is
`serverware.nativePilotOperatorResult/v1`; the coordinator emits its own
`serverware.nativePilotCoordinatorResult/v1` summary. Neither substitutes for
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

The independent approval/signing/install orchestration is still external.
Supplied authority commands do not make that policy decision, and the relay
does not assemble artifacts or provision services/private inputs. No coordinator
or pilot was executed while this implementation and guide were authored.
