# Native execution cgroup containment

This is a source-only private ownership mechanism, not a runnable workload or a
production supervision claim. `execution/containment.rs` creates one new cgroup
leaf only when called with the genuine retained `StartOwner` and its non-Clone
`StartPermit`. The owning start path must supply the real producer and caller;
neither a signed grant by itself nor successful observation JSON is permission.
There is no public configuration, task migration or exec operation in this file.
The separate [blocked-child owner](native-executable-child.md) consumes its exact
one-attempt child admission. A private-construction cleanup borrow exposes only
the actual fixed directory/kill/events controls to the
[independent guardian](native-execution-guardian.md), never caller-selected FDs.

## Admission and effects

The root-owned start path admits and retains the actual protected cgroup-v2
parent and ancestor originals, exact signed parent path/device/inode, domain
topology and already-enabled memory, pids and cpu controllers. This mechanism
does not enable controllers, alter ancestor limits or repair host provisioning.
The root-owned journal must durably consume its stable capability slot before
returning the pointer-matched permit. Existing or interrupted attempts never
authorize another leaf creation.

`ContainmentOwner::create(Arc<StartOwner>, StartPermit)` consumes that exact
permission before its sole `mkdirat` of the signed child name. It refuses an
existing leaf. The new directory must be root:root 0700 on the actual retained
parent mount. It holds the directory, fixed controls and their named/held
device, inode, mount, mode and ownership associations throughout admission.

Before any task can be admitted, the new leaf must be an unpopulated domain with
no descendant cgroups or enabled child controllers. The only limit writes are
the signed `memory.max`, `memory.swap.max` (zero), `pids.max`, and `cpu.max`
quota/period. Each receives one bounded write and exact canonical readback.
Short writes, errors, changed identities and mismatched values consume the
attempt; there is no retry, fallback, leaf reuse, automatic removal or repair.
All admission work uses the original start owner's nonrenewing clock and
retained originals. `check_admission()` additionally requires the leaf remain
unpopulated. The consuming child transition separately retains the same actual
owner and resource-limit checks without falsely requiring its new leaf to remain
unpopulated after clone.

The new child path joins the actual leaf to `CLONE_INTO_CGROUP` and closes
escaping control descriptors. It stays blocked before exec; private orchestration
arms its genuine guardian without releasing it. Same-child network ownership
and a consuming execution release remain open. A PID string or one-time
membership scan cannot replace the construction. The existing never-executed
egress child and static custody launcher are unchanged.

## Emergency termination versus confirmed cleanup

Cleanup authority is sealed to this task-created directory and its fixed
`cgroup.kill` descriptor. It is not renewed admission. Expired or revoked
admission, damaged journal originals, or a passed cleanup deadline do not
suppress the one emergency kill attempt when actual local descriptor ownership
still verifies. The attempt is marked before writing the sole fixed byte `1`;
an interrupted or short write is uncertainty, never an automatic second write.
Drop can make that same best-effort attempt if it has not happened; it does not
wait, remove the leaf, persist a completion or report success.

`kill_and_wait_empty()` subsequently checks the retained permit's independent
cleanup integrity and observes actual `cgroup.events` under the original signed
absolute `CLOCK_BOOTTIME` cleanup bound. Integrity failure is reported after
bounded cleanup, not used to suppress termination. A missed bound returns an
error even if an empty leaf is observed late. The bound controls waiting and
success reporting, not permission to abandon already-owned tasks. Reads are
fixed-size, at most two `pread` calls with no EINTR/EAGAIN retry; polling uses
the remaining absolute bound. These checks do not claim to preempt a blocked
kernel syscall or replace the separately scheduled independent guardian.

The private-construction `LeafEmpty` result records only a timely actual
populated-zero observation and whether the kill write was acknowledged. An
uncertain kill write can coexist with genuinely observed emptiness. This is
not a successful-exec, exit-status, leader-reap or complete supervision receipt.
The launcher must separately reap its actual workload leader pidfd; the guardian
is that child's sibling and cannot perform that reap. Private guarded cleanup
requires both the launcher's leader/leaf result and the guardian's own empty
observation and exact reap. No cgroup is automatically removed.

The [Linux v6.12 cgroup-v2 documentation](https://docs.kernel.org/6.12/admin-guide/cgroup-v2.html#core-interface-files)
specifies that `cgroup.kill` covers the descendant tree and concurrent forks;
`populated=0` excludes live tasks in that tree but does not establish leader
reaping. This supported profile requires a domain cgroup, not a threaded one.

The shared `cgroup_control_v1` directory/events observation API is reused without
adding a generic control-write method. Static launcher permissions, identity
bytes, deadlines, cleanup receipts and behavior are not transferred or changed.
Trusted-host-local ownership is assumed; this is not hostile-root or kernel
exclusion. No builds, tests, syscalls or workload execution are evidenced by
this source implementation.
