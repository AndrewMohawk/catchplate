# Fixed controller body supervisor

Status: source implementation, unbuilt and unexecuted. The lifecycle selects a
fixed supervisor, acquires its actual Linux process custody, and publishes a
one-use release only for that held target and launch context. This unsigned
controller gate does not supply the missing independent runtime observer or
original terminal publisher. Ordinary child exit is not an accepted body result
or independently signed runtime observation.

## Separate launch authority from workload arguments

The signed `ContainerCommand` stays unchanged. The controller creates one private
launch directory per lane and binds it read-only at
`/serverware-controller-launch-v12`. Once the full admitted body is available,
it exclusively publishes `launch.json`, binding the plan ID, lane, complete
runner identity and body, and original absolute boottime deadline.

The container invocation is fixed:

```text
/usr/libexec/serverware-coder-body-supervisor-v12
    /serverware-controller-launch-v12/launch.json
```

No caller-selected context path, shell, environment, Docker socket or generic
execution IPC is introduced. The container configuration requires `Env: []` and
working directory `/`. Engine-added ambient variables are ignored by the
supervisor; the child receives only the exact signed environment and working
directory, never inherited process variables. This also avoids inserting a final plan ID
into signed command arguments and creating a commitment cycle.
Moby's [process-environment construction](https://github.com/moby/moby/blob/v26.1.0/container/container.go#L677)
adds defaults even when configured environment entries are empty; those defaults
are not child-command authority.

```text
admitted plan + exact runner and command
  -> retained root-owned launch directory
  -> one-use original context publication -> pre-start Docker inspect
  -> start fixed gated PID1 supervisor -> running inspect -> actual target custody
  -> live custody recheck -> atomic root-owned release.json
  -> descriptor-pinned workload execution -> actual child exit/descendant cleanup
  -> actual wait + capture -> held pidfd termination
  -> output/result joins [need independent observer + terminal producer: unfinished]
  -> existing authenticated full-generation destruction
```

The context uses a closed, bounded typed JSON recipe. Its identity zeros only
`contextSha256`; exact original-byte admission rejects alternate representations.
The storage owner compares the full create-time command, including its timeout,
not merely `commandSha256`, whose existing recipe does not include timeout.
It also joins the complete runner and body scope. Publication cannot be retried
after partial I/O or reused through a cloned handle.

The root-owned directory is mode 0700 before context publication, then 0555.
The complete published inventory contains `launch.json` and, only after actual
target acquisition, one `release.json`; both are root-owned, single-link
mode-0444 regular originals. Retained descriptors, name/mount identity and
original-byte hashes are checked before launch and after execution.
The context is controller-write-once and read-only to the container; this is not
a claim of filesystem immutable-flag enforcement or hostile-root protection.
Its custody identity, published context/release digests, running-inspect digest
and held-target custody digest join the generation observation.

The exact additional read-only bind is mandatory in pre-start inspect. Signed
source/artifact/output destinations cannot overlap the context or fixed
supervisor executable. Other existing resource, private-namespace and mount
restrictions remain unchanged.

## Actual target custody before release

After a successful start, the running validator repeats the complete expected
configuration/ownership comparison and requires a positive running `State.Pid`.
That actual PID, the independently admitted static-supervisor digest, the exact
generation cgroup path and original deadline enter
[`HeldBodyTargetV12::acquire`](../data-plane/decision-gate-rs/src/body_target_v12.rs).
No caller-provided process observations or accepted-proof object substitute for
this acquisition.

The owner retains an actual pidfd, `/proc/PID` directory, five namespace
descriptors and executable/cgroup descriptors. It checks start ticks, actual
namespace PID1, the bounded immutable static executable measurement, namespace
types/inodes, and an exact v2 cgroup descendant plus membership in its held
`cgroup.procs`. Component boundaries prevent a same-prefix sibling from being
accepted. A loader or worker PID whose actual executable is not the admitted
supervisor fails; there is no broad process search or alternate-target fallback.
The generation is now an explicit delegated cgroup v2 hierarchy with separate
daemon and container children, not an inferred consequence of the daemon PID's
location; see [runner cgroup ownership](coder-runner-bounds-v12.md#delegated-generation-cgroup-ownership).
Kernel PID and namespace views are the observations used here, not caller
claims; see [`pidfd_open`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
and [`/proc/PID/status`](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html).

Root revalidates the held target, then
[`HeldBodyLaunchV12::release`](../data-plane/decision-gate-rs/src/body_launch_storage_v12.rs)
publishes a bounded original binding `contextSha256`, actual host PID, start
ticks, namespace target PID 1 and the non-extended deadline. Its identity zeros
only `releaseSha256`. A private pending file is written, synchronized and
checked before `RENAME_NOREPLACE` exposes the complete `release.json`; publication
uncertainty poisons the one-use owner, rather than authorizing a retry or reset.
The gate carries no signature or independent observer approval.

The waiting supervisor validates that original against its retained context,
own namespace PID and own start ticks before spawning the payload. It does not
pretend to derive its host PID from the private namespace. Only absence of the
fixed release name is waitable, within the original deadline and signal policy;
malformed or substituted state fails. See the closed
[release contract](../data-plane/decision-gate-rs/src/body_launch_contract_v12.rs)
and actual [supervisor](../data-plane/decision-gate-rs/src/body_supervisor_v12.rs).

After actual wait and capture completion, held-pidfd termination is required
without following a possibly reused numeric PID or inventing an exit status.
The original result's observer target PID/start ticks, namespace identities and
cgroup digest must match the retained observations. A pidfd inode from a separate
independent open is **not** treated as the same descriptor handoff. The separate
observer signature and whole-body commitment checks remain mandatory.

This two-stage gate prevents payload start from preceding root's process
acquisition. It is not continuous executable-mapping observation, protection
against a compromised privileged host, or a terminal evidence publisher. The
held descriptors and repeated identity checks are intentionally distinct from
the signed observer's still-unimplemented acquisition/event ownership.

## Supervisor scope

The supervisor checks its actual UID/GID, PID1/proc state and restricted process
configuration. These checks do not independently prove isolation from the host;
the controller's separately inspected private launch remains necessary.
It measures its real executable descriptor against the independently admitted
runner pin using the existing immutable, root-owned static-ELF requirements.
The bounded measurement API adds an independent byte ceiling, original-deadline
checks and positional reads without changing the caller's shared file offset.

The child entrypoint is opened once, measured and executed through that retained
descriptor. Supported entrypoints are ELF executables; scripts use an explicitly
signed interpreter executable with the script in its signed arguments. Ordinary
root-filesystem symlinks can resolve within the retained root, but execution does
not reopen the command pathname. The existing effective-argv convention is
preserved: an initial executable argument is not duplicated; otherwise it is
prepended, exactly as the prior Docker Entrypoint/Cmd composition did.
The descriptor-execution choice follows the Linux
[execveat interface](https://man7.org/linux/man-pages/man2/execveat.2.html);
rooted resolution follows [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).

One supervised child receives the payload streams directly. The supervisor adds
no messages to stdout or stderr. It observes exec failure and actual exit,
forwards termination signals, and reaps children within its private PID1 scope.
Execution uses the controller's absolute deadline, never a newly granted
duration. Any extra cleanup allowance is kill/reap-only, not permission to keep
running work. Outer controller cancellation and full-generation destruction are
still required. Synchronous kernel file I/O cannot be forcibly preempted by a
userspace deadline; late completion is rejected before accepting its data.
Linux's [PID-namespace rules](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
are the basis for namespace-local reaping and init-exit cleanup, not proof that
this implementation has executed correctly.

This is supervision, not continuous observation of descendant/transient mappings
or independently signed launch events. No observer key is embedded, no absent
runtime fields are synthesized, and no `BodyExecutionResultV12` is fabricated.
An admitted image containing the genuinely immutable static supervisor, its
closure pins, observer ownership and terminal producer must still be prepared.
The observer design also needs an explicit treatment of kernel-provided
executable mappings: the current file-backed mapping contract cannot represent
`[vdso]` as an ordinary file. This checkpoint neither invents backing-file
digests nor silently accepts a smaller observation scope.

## Readiness transport repair

The local upgrade readiness probe previously passed forbidden connection headers
to the generic close-only HTTP builder. It now has a separate fixed recipe:
`POST` to the independently pinned target, `Host: docker`, `Connection: Upgrade`,
`Upgrade: serverware-readiness`, and `Content-Length: 0`. Its generated exact
header must still match the independently signed fixture pin. Generic Docker
HTTP header restrictions are unchanged.

The bounded local socket-pair exchange verifies the exact 101 response, a real
server payload byte before client half-close, the complete client stream and
EOF, then the remaining server bytes and EOF. Both streams have a 16 MiB ceiling;
client data must be nonempty and server data at least two bytes. All I/O shares
one original deadline, and every worker is joined on success or failure. This
is a local readiness transcript, not evidence of an actual Docker daemon attach.
The unsigned release-asset preparer checks these payload sizes before and after
copying supplied originals. It does not generate or replace the independent
signed header pin, stream pins or fixture signature.

## Verification boundary

No build, formatter, interpreter, test, container or runtime verification ran.
The implementation-first phase continues. The exact source must be frozen before
immutable preparation and consolidated sequential verification. Historical
results do not cover these changes; production Nitro/KMS, signing and witness
services remain unprovisioned.
