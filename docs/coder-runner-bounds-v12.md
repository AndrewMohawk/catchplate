# Source-bound v12 runner execution limits

## Status and scope

This checkpoint makes execution bounds part of the admitted v12 runner
identity, checks the created and running container, and holds the actual gated
supervisor before releasing repository execution. It is
source implementation, not evidence that a controller, image or workload has
been built, installed or run. The workflow and independent authority
requirements in [goal.md](../goal.md) remain unchanged.
These root-controller resource limits are not native/TEE assurance or proof
against a compromised privileged host.

The change applies to the actual v12 repository runner, not merely to example
Docker commands or the separate service-container resource contract. It does
not implement a PostgreSQL cluster lifecycle or turn native component reports
into controller or release authority. See
[native PostgreSQL verification](native-postgres-verification.md) for those
remaining prerequisites.

## Mandatory identity, not a launcher default

The container entrypoint is now the [fixed body supervisor](controller-body-launch.md),
with exactly one additional controller-owned read-only launch-directory bind.
The original context and subsequent one-use release occupy that same directory;
neither is an independent observer signature.
Payload argv/environment/cwd stay in the unchanged signed command; pre-start
inspect rejects a direct payload entrypoint or an inherited container environment.

`RunnerIdentity.executionBounds` is required source-owned plan data. Its
nonroot user and group, CPU limit, memory limit with no swap, PID limit,
open-file limit, shared-memory size, private writable-mount limits and aggregate
output byte/inode limits must be present and validated. Missing bounds are
rejected; there is no legacy unbounded default and no environment-variable override.

The closed `RunnerExecutionBoundsV12` object uses the JSON fields `userUid`,
`userGid`, `cpuQuotaMicros`, `cpuPeriodMicros`, `memoryBytes`, `pids`,
`openFiles`, `shmBytes`, `runTmpfsBytes`, `tmpTmpfsBytes`,
`privateDataBytes`, `outputBytes` and `outputInodes`. `outputBytes` must be
16 MiB–1 GiB in whole-MiB increments; `outputInodes` must be 64–65,536. The
CPU period is fixed at 100,000 microseconds. Numeric types, finite source
limits and checked memory summation are enforced by the
source validator; unknown fields or omitted required fields are not defaults.
No-swap is a fixed rendering requirement, not a caller-selected opt-out.
The cgroup v2 create path omits `MemorySwappiness` and requires `null` in both
inspect states; the no-swap commitment remains exact `MemorySwap == Memory`.
Previously serialized v12 runner identities without these fields, including
identities that predate the aggregate output limits, are rejected
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
| Private workload data | Bounded private `/var/lib/catchplate-runner` tmpfs |
| Aggregate lane output | Fresh controller-owned tmpfs with exact byte and inode caps, bound into the fixed output destination |

The private tmpfs mounts are writable only within their declared limits and
use the admitted UID/GID, mode `0700`, and `nosuid,nodev,noexec`. Source and
artifact mounts and the container root filesystem stay read-only. The
controller-allocated per-lane output is a distinct fresh tmpfs with the admitted
aggregate `outputBytes` and `outputInodes` caps, private mount propagation and
fixed `noswap,nodev,nosuid,noexec`. The writable bind exposes that bounded
filesystem, not an ordinary unbounded host directory or database scratch allowance. Its
aggregate capacity is separate from the accepted result-file read bound;
filling either output capacity fails the workload, not the limit. There is no
fallback when the host cannot admit the required mount options or caps.

The byte cap limits allocated tmpfs file data, not sparse logical file lengths
or all kernel metadata. The inode limit also accounts for extended-attribute
consumption. `noswap` disables this mount's swap use; it does not turn tmpfs
into durable storage. See the primary [Linux tmpfs documentation](https://docs.kernel.org/filesystems/tmpfs.html).

`/var/lib/catchplate-runner` is the fixed private-data mount, not a caller-
selected host path. The separate source-owned PostgreSQL lifecycle creates its
fresh `PGDATA` child there. It must not put the database or WAL in the host's root-backed `/tmp`,
silently enlarge `/run` or `/tmp`, or fall back to an unbounded writable root
filesystem. The private tmpfs ceilings, shared-memory allowance and
`outputBytes` participate in checked summation and must fit inside
the declared memory ceiling. This is a conservative configuration check, not
a bound on total host allocation or a claim that every page is charged to the
runner: initial mount metadata may charge the controller, and process/kernel
overhead remains. It is not proof that every admitted workload will complete
within its limits. Resource exhaustion fails the workload, not the bound.

These limits complement, rather than replace, the existing read-only mounts,
capability drop, no-new-privileges, private IPC and lane-specific network
policy. A future native PostgreSQL runner requires network mode `none`; no
host Docker or database socket is exposed to repository code.

## Delegated generation cgroup ownership

The source-fixed cgroup v2 root is
`/sys/fs/cgroup/system.slice/catchplate-coder-lifecycle-privileged-v12.service`.
The unit requests `Delegate=cpu memory pids` and `DelegateSubgroup=supervisor`;
the privileged controller must actually be in that subgroup. There is no
fallback to a host-global Docker hierarchy or a different cgroup driver.
Its cold unit capability set also adds `CAP_SYS_PTRACE` to read the actual
nonroot supervisor's `/proc` executable and namespace descriptors. This is a
source unit change, not a live capability change, arbitrary tracing API or
independent observer implementation.
The source-owned layout is:

```text
delegated service                         [no direct processes]
├─ supervisor                             [privileged controller]
└─ catchplate-coder-v12-<generation>       [no direct processes]
   ├─ daemon                             [dockerd and inherited daemon children]
   └─ containers                         [no direct processes]
      └─ Docker-created container cgroups [gated supervisors and workloads]
```

Separating populated leaves from domain parents permits domain-controller
distribution under Linux's [no-internal-process constraint](https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint).
Systemd 254 or later is required for `DelegateSubgroup=`; delegation makes
controllers available but does not itself enable them. See the primary
[systemd delegation contract](https://systemd.io/CGROUP_DELEGATION/).

The [generation owner](../data-plane/decision-gate-rs/src/generation_cgroup_v12.rs)
checks the actual hierarchy and availability before enabling only
`cpu memory pids`. A preopened `daemon/cgroup.procs` descriptor places the
daemon child there in `pre_exec`, before daemon execution; moving the daemon
after it could already have forked is not the admission path. Dockerd is
started with `native.cgroupdriver=cgroupfs` and an explicit absolute
generation `containers` parent. Every runner create also sets and checks that
exact `HostConfig.CgroupParent`. Docker's per-container parent takes precedence
over its daemon default, so both are explicit; see
[Docker's cgroup-parent contract](https://docs.docker.com/reference/cli/dockerd/#default-cgroup-parent).

The held body target must independently be an actual component-wise descendant
of this generation, with matching `/proc` cgroup membership and actual
`cgroup.procs` membership. An inspect string alone does not supply that check.
Cleanup kills only the owned generation hierarchy, waits for aggregate
`cgroup.events` population to reach zero, then removes bounded cgroup
directories. It does not recursively unlink cgroup pseudo-files or treat an
empty parent `cgroup.procs` as evidence that descendants are gone. Missing
delegation, controllers, identity or cleanup evidence fails closed; these
source paths and their host prerequisites remain unverified in execution.

## Fresh output and pre-start admission

Before a lane starts, its output directory must be fresh, controller-owned
during preparation and assigned to that lane's exact admitted nonroot user
and group. A pre-existing directory, substituted path or ownership mismatch
must not be accepted by repairing it after repository execution has begun.
This avoids both stale result reuse and assuming that a root-owned bind is
writable by the declared runner user.

The implementation creates an exclusive `runner-output-<ordinal>` mountpoint
directly below the privileged mode-`0700` generation parent, then mounts the
fresh bounded tmpfs for that lane's exact admitted UID/GID and mode `0700`.
The parent is never made worker-writable. Each lane has a separate filesystem,
including when profiles use different users. The controller's original OCI export directory remains
separate; this does not change the signed output destination inside the
container or move controller-generated OCI archives into worker ownership.
Actual mount identity, options and byte/inode capacities are read back at
creation, both pre-start checks, after execution and after result reading;
directory creation or Docker's bind declaration alone cannot establish them.
The retained descriptor and mount observations must still identify the
controller-created filesystem. The observed state binds the complete output
mount record's digest, not just the directory pathname.

The [output storage owner](../data-plane/decision-gate-rs/src/runner_output_storage_v12.rs)
publishes a fixed, root-only mode-`0600` custody sidecar before mounting. That
record binds the generation, underlying mountpoint, fixed lane, runner IDs
and byte/inode limits; mounted identity is separately retained and checked.
Its `create`/`verify` and fixed-generation `teardown` helpers provide no arbitrary
mount target or recursive-cleanup callback. Interrupted setup can be handled
only when the exact owned custody remains intact. Invalid, changed, legacy or
unknown state fails closed without automatic repair; this is not universal
crash-cleanup proof.

Fixed generation cleanup first stops/removes the owned cgroup, then strictly
unmounts each owned output filesystem before recursive directory removal.
An unmount or identity failure is not permission to recurse through a
remaining mount, detach it as a fallback or
declare teardown complete; residual generation mounts deny recursion.
Lazy detach can leave a busy filesystem alive after it disappears from the
mount table, so it is not equivalent to completed unmount. See
[`umount(2)`](https://man7.org/linux/man-pages/man2/umount.2.html).
Output is temporary memory-backed storage, not a durable host-output promise;
copying accepted artifacts into independently
admitted retained storage is a separate responsibility.

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

After the accepted start, a separate running inspect repeats the exact
configuration checks and obtains the actual host `State.Pid`. Before the
payload can execute, the controller acquires a pidfd, process and namespace
descriptors, checks the expected static supervisor and generation membership,
hands the exact retained descriptors to the pinned observer peer, requires its
scope-bound channel readiness, rechecks liveness, and publishes the fixed
one-use release. Running-inspect,
held-target custody and release digests enter the generation observation.
This gate is unsigned controller custody, not independent observer approval.
After actual wait and capture, the retained pidfd must indicate termination;
the original result's observer target PID/start ticks and namespace/cgroup
claims must match the held target. The observer's pidfd inode must identify the
same open description transferred with `SCM_RIGHTS`, not an independently opened
descriptor. Root verifies the original observer signature under existing
release-bound trust before publishing the protected terminal. The client and
publication path do not supply the still-missing independent observer server.
The exact sequence and
remaining observer/terminal-producer boundary are in
[controller body launch](controller-body-launch.md).

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
The controller now separately implements pre-start attach capture for the signed
command's stdout/stderr, with original deadlines and independent stream caps,
and collects the complete signed output tree. See
[body output ownership](controller-body-output.md); these source paths remain
unexecuted and do not make the rotating log complete evidence.

The result reader retains an output-directory descriptor across execution
and rechecks its device, inode, ownership and mode identity. It reads one of
the two existing fixed result basenames relative to that descriptor; only
`ENOENT` for the lane-specific name permits the legacy fixed-name fallback.
Symlinks, special files, wrong ownership/group, group/other permissions,
multiple links, empty or oversized files, and metadata/content-length changes
during the bounded read are rejected. `O_NONBLOCK` prevents a supplied FIFO
from blocking before the regular-file check. The expected result file is
owned by the admitted runner user, not by the privileged controller. Its
canonical plan/lane/body/command/observed-exit and retained runner-image/runtime/
rootfs bindings are checked afterward. Both controller layers now consume the
same closed, bounded 4 MiB original result contract and validate its terminal
and signed-claims commitments; the executor independently verifies the observer
signature. See [body evidence](controller-body-evidence.md) for the v13 observer
binding, integer-capable v12 lifecycle codec and remaining producer prerequisites.

Inspect equality establishes only the source-level admission rule and, when
actually exercised, the daemon's reported configuration. It is not independent
proof of kernel enforcement, complete executable identity, successful work,
or teardown. The added actual-target acquisition checks do not establish
continuous executable mappings, observer event completeness or a signed
terminal publisher. The external controller still owns the full resource inventory
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
| `/var/lib/catchplate-runner` | 2 GiB |
| Aggregate output | 256 MiB, 4,096 inodes |

The listed memory-backed capacities total 2,688 MiB, below the 4,096 MiB
memory ceiling. The numerical difference is not guaranteed host or cgroup
headroom for process/kernel overhead. This is a bounded example, not a measured
sizing result, prepared PG16 image identity or complete native resource profile.
The signed [native opt-in](native-postgres-controller-consumer.md) requires the
listed owner and memory/storage/PID/open-file minima; CPU remains an admitted
choice under the general bounds. The 256 MiB output minimum accommodates the
seventeen bounded 8 MiB logs plus reports. PostgreSQL `fsync`
on a tmpfs does not establish survival of host power loss or storage loss.

The separate [native cluster manager](native-postgres-verification.md) and its
bounded local log capture and original-report consumer are source-implemented
but unexecuted. Fixed PG16 toolchain/image closure, admitted invocation/deadlines,
the original outer execution-evidence producer, verification of actual
output-mount enforcement and authenticated cleanup are still required. The fifteen suite deadlines total
5,100 seconds before startup and
cleanup; the existing Unit deadline is 900 seconds. Adding execution bounds
does not change that deadline, omit suites to fit it, remove their exclusions,
waive changed-test coverage, or authorize verification before the complete
preparation prerequisites are satisfied.
