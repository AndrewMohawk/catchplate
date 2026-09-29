# Native blocked executable child

This is source-only implementation, not a tested start interface or pilot
result. The explicit [v5 lifecycle](native-execution-lifecycle.md) now consumes
this owner after genuine same-child networking and guardian admission.
`start::prepare_blocked_child` consumes the actual executable-parent
admission, durable start and creation claims, and newly limited cgroup owner.
The older diagnostic child is unchanged and cannot be converted into this one.

`BlockedChild::create` makes one `clone3` attempt with `CLONE_INTO_CGROUP` and
`CLONE_PIDFD`, plus new PID, mount, IPC, UTS and network namespaces. It neither
migrates a task nor adopts an existing PID. The actual leaf is checked before
creation; afterward its fixed `cgroup.procs` original must contain only the
clone-returned leader. A failed attempt consumes the existing claims.

## Image, identity and blocked handoff

The genuine `StartOwner` retains the same `PreparedFilesystem`, manifest,
EROFS/fs-verity/loop originals, executable, optional ELF interpreter and original
clock. A separately detached, nonrecursive copy of that closed immutable mount
is prepared for the child. All argv/environment storage and descriptor copies
are allocated before clone. The syscall-only child installs that mount in its
private mount namespace, pivots to it and detaches the old root, then selects the
held in-image cwd. No host loader, shell, `PATH` lookup, inherited secret/socket,
ambient submount or external EROFS data device is substituted.

The admitted static ELF or ordinary dynamic ELF remains selected by the exact
manifest. Dynamic `PT_INTERP` lookup occurs inside the installed immutable root;
the independently checked loader descriptor stays retained by the parent.
Libraries, scripts passed to an in-image interpreter and modules are bound by
the complete supported image, not by a claim that every application will run.
This slice provides no writable workspace, mounted proc/dev filesystem or
additional device access.

The child applies the fixed, signed manual network policy before readiness.
It resets inherited signal dispositions and alternate stack, sets the fixed
umask, empties supplementary groups and all capability sets, locks securebits,
sets the signed non-root UID/GID and no-new-privileges, disables dump/core dumps,
and verifies those changes. Stdin is the actual null device; stdout/stderr are
bounded pipes. The combined signed output limit is retained by the owner;
the lifecycle accounts for both streams through bounded final EOF. Successful
exec retains only descriptors 0, 1 and 2.

Before clone the parent retains a creator-**thread** pidfd. The child installs
PDEATHSIG and polls that pidfd to close the parent-death race, then repeats this
after credential changes, which can clear PDEATHSIG. It sends a fixed private
readiness record and blocks on a private gate. The parent takes ptrace custody
with EXITKILL/TRACEEXEC, interrupts the child and retains the exact pidfd wait
event using WNOWAIT. Actual pidfd namespace ioctls and nsfs identities establish
that all five held namespaces belong to this child and differ from the launcher.

`GuardianBorrow` can only be made from that checked blocked owner. It exposes
sealed borrows of the actual leader/creator-thread pidfds and genuine leaf,
kill and events descriptors, plus the operation and already projected absolute
deadlines. Its separate one-attempt guardian latch is consumed before spawning
the guardian. The guardian READY bound is the original admission deadline; the
signed stop/cleanup bounds do not renew it. Guardian preparation cannot itself
resume the workload.

## Consuming exec release

The [v5 lifecycle](native-execution-lifecycle.md) now moves a genuine same-child
network-ready owner into the guarded execution/cleanup scope. Its one-shot
release latch precedes the sole gate send and PTRACE_CONT; no serialized result
or old diagnostic owner can authorize either. An EXEC acknowledgement requires
the exact retained leader's
`PTRACE_EVENT_EXEC` stop and original event-message identity. Gate EOF,
pre-exec death, exit status 127 or a vanished executable FD are not success.
Final original-clock checks precede detach at that positive first EXEC stop;
normal signals are then handled by the application while the independent
guardian enforces the signed lifetime. This source path has not been executed.

`BlockedChild::terminate` attempts emergency whole-leaf kill and exact leader
pidfd kill even if admission has expired. It separately performs the exact
leader reap and bounded populated-zero observation, propagating either failure
without claiming cleanup. The independent guardian and launcher each have
their own at-most-one kill attempt; both can target the same owned leaf during
teardown. This is not a globally exactly-once kill guarantee. Drop performs
best-effort kill/nonblocking reap only: no successful receipt, retry, rmdir or
reuse. A sibling guardian cannot reap the workload leader; the launcher must
retain that separate obligation.

The supported kernel mechanisms fail closed when unavailable. Relevant primary
contracts are Linux's [clone3/cgroup placement](https://man7.org/linux/man-pages/man2/clone.2.html),
[pivot-root operation](https://man7.org/linux/man-pages/man2/pivot_root.2.html),
[PDEATHSIG credential-change semantics](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html),
[ptrace events and EXITKILL](https://man7.org/linux/man-pages/man2/ptrace.2.html),
and the pinned Linux v6.12 [pidfd UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/pidfd.h)
and [wait-event status producer](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c).
This remains trusted-host-local ownership, not protection from a hostile kernel
or privileged host operator. No build, runtime or cleanup experiment was run.
