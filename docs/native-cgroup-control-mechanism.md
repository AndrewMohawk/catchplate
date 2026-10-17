# Retained cgroup-v2 control preparation and observation

`catchplate_decision_gate::cgroup_control_v1` extracts the static custody
launcher's actual cgroup directory/control checks and populated reader. This
is source-only integration: no cgroup was opened, created, populated or killed;
no build, test or runtime command ran.

## Narrow mechanism

The Linux-only API is:

- `verify_directory(BorrowedFd) -> DirectoryObservationV1` verifies an actual
  protected cgroup-v2 directory and returns private-field kernel observations.
- `PreparedKillV1::open(BorrowedFd)` retains a CLOEXEC duplicate of that actual
  directory and opens only its fixed `cgroup.kill` control. `check()` verifies
  the same held/named association. There is **no write method or kill-FD export**.
- `EventsV1::open(BorrowedFd)` separately retains the directory and its fixed
  read-only, nonblocking `cgroup.events` FD. `check()` revalidates ownership;
  `populated(&mut self)` reads the actual retained control. `poll_fd()` borrows
  only this read-only events FD for the caller's existing wait mechanism.

These are non-Clone descriptor owners with sticky failure, not permission
carriers. They accept no caller success value, pathname, arbitrary control name
or arbitrary write payload. Separate event and kill preparations mean graceful
empty observation does not introduce a new requirement to open a writable
kill control. No task migration, directory creation/removal, freezer operation,
resource setting, kill issuance or native guardian is implemented here.

The actual directory is checked with fstat/statx and cgroup-v2 fstatfs, including
nonzero inode, root owner and no group/world write bits. Each owner keeps its
own directory duplicate and the selected control. The held control must be
regular data on that exact device and mount; fixed-name stat/statx observations
must equal its held identity. Rechecks retain directory/control device, inode,
mount, mode, uid and gid association and descriptor access/nonblocking/CLOEXEC flags.
This is not an exclusive cgroup lease or hostile-root exclusion proof. The
caller still owns authenticated directory selection, protected ancestry,
membership, delegation/migration restrictions and lifecycle permission.

## Parser and unchanged static lifetime

The reader preserves the existing bounded recipe: seek to zero, read fewer
than 4096 bytes, require ASCII and exactly two whitespace-delimited fields per
record. There must be exactly one `populated` field with value `0` or `1`;
missing, duplicate or malformed populated records refuse. Other kernel event
keys remain allowed with the same two-field shape. Existing EOF, EINTR and
partial-read EAGAIN handling is retained. Read errors or association drift
stop the retained owner; no successful read is accepted from a caller.

`policy_custody::launcher` still owns `BoottimeDeadline`, its boot/time-domain
checks and `poll_until(PRIORITY)`. Its private kill-availability helper merely
prepares and drops `PreparedKillV1`, as it previously opened and dropped the
fixed kill FD. Its populated query and empty-wait use `EventsV1`. No new timer,
relative timeout, renewed deadline or additional cleanup allowance is added.
Blocking kernel calls and repeated signal interruption still require the
caller's existing independent watchdog; this extraction is not preemption.

The static cgroup identity remains `catchplate.policyCustody.cgroup/v1` with
the same ordered, length-framed domain/device/inode/mount-id/mode/uid/gid bytes.
`finish_graceful_cleanup` retains its exact identity check, actual leader-pidfd
reap, populated-zero wait under the original absolute CLOCK_BOOTTIME cleanup
bound, cleanup receipt construction and watchdog-disarm protocol. No static
signature, identity domain, launch permission or cleanup receipt is transferred
to a native caller.

## Kill request is not confirmed whole-tree termination

Linux describes `cgroup.kill` as a fixed-value process-tree SIGKILL operation,
including concurrent forks and migration protection during the kill. That
does not make opening its FD—or a later successful write—a completion receipt.
`cgroup.events` populated-zero concerns live processes in the cgroup and its
descendants; it does not reap the leader or prove it exited successfully.
[Linux v6.12 cgroup controls](https://docs.kernel.org/6.12/admin-guide/cgroup-v2.html#core-interface-files)

Any future native guardian must independently own the exact admitted cgroup,
its original absolute cleanup deadline and separate permission before adding
a source-fixed kill action. It must distinguish attempted/issued kill from
actual populated-zero plus exact leader reap, and keep uncertainty on failed
IO, drift, expiry or incomplete reaping. It must also establish that its entire
workload subtree cannot escape that cgroup and that the guardian itself is
outside the killed subtree. No such supervision, execution, whole-tree cleanup
or pilot result is claimed by this preparation/observation module.
