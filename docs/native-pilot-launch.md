# One-bridge native pilot composition

`serverware.native_pilot_launch.NativePilotLaunch` connects the actual retained
launch owners. It is a privileged, same-process operator API, not a JSON
configuration loader, a credential source or a readiness command. This source
connection still requires the consolidated build and connected pilot acceptance.

The [signed-input receiving APIs](native-pilot-signed-inputs.md) now let its real
ordinary/native resource and driver owners admit independent signatures without
loading authority private keys into the launcher. The [fixed resource owners](native-pilot-resource-owners.md)
now join Retrieval, GenerationInstall, CommitRequest and the real production/
proof resources. A complete executable conductor is still required; this class
alone is not an operator launch command.

The selected topology is one measured `DriverBootstrap` bridge, ten native
endpoint children and five ordinary custody services. Configuration/v7 selects
the endpoint-only cohort; the existing fixed-eleven configuration/v6 is unchanged.
There is no second bridge process whose identity must be mistaken for the first.

The gate selects native startup/v22 and its separately pinned, independently
signed [workload trust authorization](native-workload-trust-authorization.md).
The pilot wrapper neither issues that grant nor substitutes for the actual
startup/TLS admission. The full configuration and launch originals remain its
scope; their original deadlines are not extended by any staged caller.
The fixed native-enclave image entrypoint takes `--workload-trust-v22`; the
direct gate selector is `--native-workload-trust-startup-v22`. Both pass the same
configuration, launch and separate trust-original paths and independent pins.

## Real phases, unchanged deadlines

| Phase | Actual caller | Required independent input |
| --- | --- | --- |
| Measure driver | `NativePilotLaunch.start()` | Protected bootstrap configuration/v4, image, window and installed supervisor |
| Start endpoint and ordinary owners | `start_endpoints()` | Cohort configuration/v7 and signed precreation bound to the driver observation that now exists; protected ordinary-effects configuration |
| Allocate resources | `prepare_resources()` | Actual gate binding, existing protected business configuration and fresh, provisioned resource directories |
| Allocate bridge clients | `prepare_bridge_connections()` | All real endpoint paths and an independently installed outgoing runtime bound to the observed journal identity |
| Observe bridge and admit launch | `bridge_activation()` then `prepare_operational_inputs(...)` | Independent C9/launch originals for the exact sorted 41-descriptor inventory; no caller-supplied FD map |
| Admit live originals | Existing methods on `driver`, `cohort`, `generation_inputs`, `business_resources` and `spool_inputs` | Actual gate binding, independently approved C9 deliveries, grants, service histories and phase-two scope; real resource producers supply retained descriptors |
| Release once | `release(...)` | Genuine `OperationalInputs`, ten endpoint transfers and exact signed endpoint-release/phase-two originals |
| Retire | `close()` | Actual driver subtree termination, endpoint cleanup and ordinary-service reaps |

The caller retains the same live `NativePilotLaunch` instance between phases.
Configuration/v7 cannot be precomputed with a guessed driver PID or observation
hash. The independent authority step after driver measurement must complete
within the existing signed startup window; this API does not make time for a
human approval by extending it. Both native parents start before the ordinary
five-service watcher creates a Python thread. No later Python fork is added.

The returned phase owners are the real objects, not serialized copies. Their
existing methods perform the actual resource allocation, independent-signature
checks and one-use transfers. The wrapper supplies no signing keys or permissive
default policy, and cannot import an unsigned observation as authority.

`release` requires the operational input owner returned by this pilot's own
`prepare_operational_inputs`; it cannot replace the prepared bridge resources
with an unrelated inventory. It first consumes the real generation transfer for the ordinary five.
The retained driver association and actual signed peer originals are checked
before the ten endpoints are released, and all five authenticated final-role
listening notices must be present. Only then does the same cohort invoke the
existing driver continuation, exactly once. The returned construction notice
does not establish generation installation, successful proxy traffic or pilot
readiness. Generation-origin delivery remains the existing explicit operation
after genuine installation.

## One external bridge, separate cleanup

The initial cohort binding carries exactly the actual supervisor PIDFD, driver
PIDFD and retained sealed executable, plus the exact bootstrap configuration,
window and observation originals. The Rust parent checks real lineage, process
starts, executable identity and measurement. It does not construct fake SCM
credentials or treat a supplied PID dictionary as a process owner.

Signed cohort configuration/precreation pins those originals. The new release,
cleanup, terminal and result contracts also bind the exact external-driver
original. The unchanged 32 KiB control frame and 128-rights aggregate release
limits remain in force. Older profiles do not acquire this binding implicitly.

The cohort owns and reaps only its ten endpoint children. `DriverBootstrap`
owns its measured driver subtree. On normal close, the wrapper retires the
driver, then the endpoint cohort, then the ordinary five and their resources.
If driver cleanup is uncertain, the wrapper may stop its local endpoints and
ordinary children but retains shared spool, transfer and business originals.
It does not convert a failed cleanup into a fresh invocation or retry it.
Persistent files remain available for explicit operator reconciliation.

See [artifact assembly](native-pilot-build.md), the
[v7 wire schema](../schemas/native-shadow-proof-cohort.v7.schema.json) and the
[existing driver lifecycle](native-shadow-driver-lifecycle.md).
