# Source-bound v12 runner execution limits

## Status and scope

This checkpoint makes execution bounds part of the admitted v12 runner
identity and checks the created container before repository execution. It is
source implementation, not evidence that a controller, image or workload has
been built, installed or run. The workflow and independent authority
requirements in [goal.md](../goal.md) remain unchanged.

The change applies to the actual v12 repository runner, not merely to example
Docker commands or the separate service-container resource contract. It does
not implement a PostgreSQL cluster lifecycle or turn native component reports
into controller or release authority. See
[native PostgreSQL verification](native-postgres-verification.md) for those
remaining prerequisites.

## Mandatory identity, not a launcher default

`RunnerIdentity.executionBounds` is required source-owned plan data. Its
nonroot user and group, CPU limit, memory limit with no swap, PID limit,
open-file limit, shared-memory size and private writable-mount limits must be
present and validated. Missing bounds are rejected; there is no legacy
unbounded default and no environment-variable override.

The closed `RunnerExecutionBoundsV12` object uses the JSON fields `userUid`,
`userGid`, `cpuQuotaMicros`, `cpuPeriodMicros`, `memoryBytes`, `pids`,
`openFiles`, `shmBytes`, `runTmpfsBytes`, `tmpTmpfsBytes` and
`privateDataBytes`. The CPU period is fixed at 100,000 microseconds. Numeric
types, finite source limits and checked memory summation are enforced by the
source validator; unknown fields or omitted required fields are not defaults.
No-swap is a fixed rendering requirement, not a caller-selected opt-out.
Previously serialized v12 runner identities without these fields are rejected
and must be deliberately reissued; the controller must not fill in bounds on
behalf of an older signed identity. The source definition is in
[plan_protocol.rs](../data-plane/decision-gate-rs/src/plan_protocol.rs).

The complete runner identity participates in the canonical preparation digest and
the surrounding admitted plan commitments. Changing a bound changes that
identity and requires a newly admitted source-signed plan. Merely constructing
the data, validating its shape, or supplying a new digest does not grant plan
signing authority. The installed controller must still verify the appropriate
signatures, source and executable closure, image identity and one-use phase.

User identity is profile-specific. The Python image uses UID/GID
`10001:10001`; the Rust runner uses `65532:65532`. This change must not replace
all runner users with the Python account, inherit an image's unspecified user,
or permit UID or GID zero. Both the signed identity and the observed container
must agree on the exact numeric user and group.

## Writable storage and resource mapping

The controller renders the admitted bounds into the actual Docker create
request, then checks Docker's inspect result against that request before
start. The required mapping is:

| Bound | Actual execution control |
| --- | --- |
| Nonroot UID/GID | Explicit numeric container `User` |
| CPU | Explicit `CpuQuota` and fixed `CpuPeriod` |
| Memory, no swap | Explicit `Memory`; `MemorySwap` equal to `Memory` |
| Process count | Explicit `PidsLimit` |
| Open files | Exact soft and hard `nofile` limits |
| Shared memory | Explicit `ShmSize`, private IPC |
| Runtime scratch | Bounded private `/run` tmpfs |
| Temporary scratch | Bounded private `/tmp` tmpfs |
| Private workload data | Bounded private `/var/lib/serverware-runner` tmpfs |

The private tmpfs mounts are writable only within their declared limits and
use the admitted UID/GID, mode `0700`, and `nosuid,nodev,noexec`. Source and
artifact mounts and the container root filesystem stay read-only. The
controller-allocated per-lane output directory is the distinct writable result
path; a writable output bind is not an implicit database scratch allowance.
That bind is **not aggregate-byte-quota-limited by this checkpoint**. A runner
can write more output than the accepted result-file limit; bounded result
reads and private tmpfs caps do not bound arbitrary writes to this separate
bind. A controller-enforced output-storage quota remains necessary for a
fully bounded native profile.

`/var/lib/serverware-runner` is the fixed private-data mount, not a caller-
selected host path. The separate source-owned PostgreSQL lifecycle creates its
fresh `PGDATA` child there. It must not put the database or WAL in the host's root-backed `/tmp`,
silently enlarge `/run` or `/tmp`, or fall back to an unbounded writable root
filesystem. The tmpfs ceilings and shared-memory allowance must fit inside
the declared memory ceiling; that arithmetic is not proof that every admitted
workload will complete within it. Resource exhaustion fails the workload, not
the bound.

These limits complement, rather than replace, the existing read-only mounts,
capability drop, no-new-privileges, private IPC and lane-specific network
policy. A future native PostgreSQL runner requires network mode `none`; no
host Docker or database socket is exposed to repository code.

## Fresh output and pre-start admission

Before a lane starts, its output directory must be fresh, controller-owned
during preparation and assigned to that lane's exact admitted nonroot user
and group. A pre-existing directory, substituted path or ownership mismatch
must not be accepted by repairing it after repository execution has begun.
This avoids both stale result reuse and assuming that a root-owned bind is
writable by the declared runner user.

The implementation creates an exclusive mode-`0700` `runner-output-<ordinal>`
directory directly below the privileged mode-`0700` generation parent, then
sets the child ownership through its open descriptor. The parent is never
made worker-writable. Each lane has a separate child, including when profiles
use different users. The controller's original OCI export directory remains
separate; this does not change the signed output destination inside the
container or move controller-generated OCI archives into worker ownership.

Creation is not successful admission by itself. Before the start request, the
controller checks the exact created container identity, owner labels, image,
command and environment, user, mounts, network/isolation settings and resource
bounds. Missing required fields, widened or substituted values fail closed.
The first inspect follows creation; a second inspect immediately precedes the
actual repository-body start. The controller retains the expected create
document, command digest, output-directory identity and both inspect hashes.
Docker create warnings are denied, including a missing warning-set field;
unsupported limits must not become a silent downgrade.

The pre-start observation is consumed before the start request. Only Docker
HTTP `204` is accepted for that request: `304` is not a successful resumed
execution, and an already-consumed runner cannot be started again through
this path. On failure the ordinary abort and owned-resource cleanup path
remains responsible for the created resource. The actual source wiring is in
[dind_lifecycle.rs](../data-plane/decision-gate-rs/src/dind_lifecycle.rs).

The closed Engine API 1.45 readback rules are in
[runner_isolation_v12.rs](../data-plane/decision-gate-rs/src/runner_isolation_v12.rs).
Only explicitly enumerated empty/default serialization forms are equivalent;
unknown configuration fields fail closed. Image-inherited environment,
labels, healthcheck behavior, volumes, exposed ports or shell settings are
not silently discarded. A prepared image and its signed command must fit the
closed profile; this checkpoint does not establish that existing image
artifacts already do. The fixed Docker log driver has an 8 MiB single-file
rotation bound, which is not a substitute for complete bounded fixture-log
capture by the separate, unexecuted native runner.

The result reader retains an output-directory descriptor across execution
and rechecks its device, inode, ownership and mode identity. It reads one of
the two existing fixed result basenames relative to that descriptor; only
`ENOENT` for the lane-specific name permits the legacy fixed-name fallback.
Symlinks, special files, wrong ownership/group, group/other permissions,
multiple links, empty or oversized files, and metadata/content-length changes
during the bounded read are rejected. `O_NONBLOCK` prevents a supplied FIFO
from blocking before the regular-file check. The expected result file is
owned by the admitted runner user, not by the privileged controller. Its
canonical plan/lane/body/observed-exit bindings are still checked afterward.

Inspect equality establishes only the source-level admission rule and, when
actually exercised, the daemon's reported configuration. It is not independent
proof of kernel enforcement, complete executable identity, successful work,
or teardown. The external controller still owns the full resource inventory
and terminal `DESTROYED` receipt.

## Native PostgreSQL example, not an enabled lane

A candidate Python native-PG profile is:

| Setting | Value |
| --- | ---: |
| UID/GID | `10001:10001` |
| CPU quota / period | 200,000 / 100,000 microseconds (2 CPUs) |
| Memory | 4 GiB |
| Swap allowance | 0 additional bytes |
| PIDs | 128 |
| `nofile` soft/hard | 1024 / 1024 |
| Shared memory | 64 MiB |
| `/run` | 64 MiB |
| `/tmp` | 256 MiB |
| `/var/lib/serverware-runner` | 2 GiB |

The listed memory-backed capacities total 2,432 MiB, below the 4,096 MiB
memory ceiling, leaving capacity for process memory and other charged kernel
memory. This is a bounded example, not a measured sizing result or a prepared
PG16 image identity or a complete native resource profile. PostgreSQL `fsync`
on a tmpfs does not establish survival of host power loss or storage loss.

The separate [native cluster manager](native-postgres-verification.md) and its
bounded local log capture are now source-implemented but unexecuted. Fixed PG16
toolchain/image closure, output-storage quota, controller report-consumer
integration and authenticated cleanup are still required. The ten suite deadlines total
3,600 seconds before startup and
cleanup; the existing Unit deadline is 900 seconds. Adding execution bounds
does not change that deadline, omit suites to fit it, remove their exclusions,
waive changed-test coverage, or authorize verification before the complete
preparation prerequisites are satisfied.
