# Controller body observer acquisition

Status: source-only, unbuilt and unexecuted. The receiver, descriptor-bound
target acquisition and read-only gate snapshot are prerequisites for a future
observer, not an operational observer server or permission to release a body.
No ready acknowledgement, continuous event acquisition or signed evidence is
produced by these components.

## Received originals and actual target

The shared
[exchange contract](../data-plane/decision-gate-rs/src/body_observer_contract_v12.rs)
fixes the launch, ready and terminal schemas, original deadline and nine descriptor
roles: pidfd, proc directory, executable, user/mount/PID/network/cgroup namespaces,
and cgroup directory. The launch retains the complete body context, original
source/artifact scope and inherited proxy pin. These values do not authenticate
themselves merely by being well-shaped or arriving over a socket.

The actual composition is
[AcquiredBodyObserverLaunchV12::acquire(accepted, expected_controller_executable, deadline)](../data-plane/decision-gate-rs/src/body_observer_v12.rs).
It takes ownership of an already accepted socket and an independently supplied
controller executable pin. The fixed-endpoint receiver checks `SO_PEERCRED`,
obtains the actual peer pidfd through `SO_PEERPIDFD` rather than opening a peer
pidfd from a numeric PID, and joins its immutable static executable to that pin.
It receives one `L` byte carrying exactly nine `SCM_RIGHTS` descriptors, then
one bounded u32-big-endian-length original launch frame. Extra ancillary data,
pre-ready bytes and premature EOF are rejected. The effective deadline is the
minimum of the independently owned service bound and original launch deadline.

Both peers now require Linux `SO_PEERPIDFD` (available in Linux 6.5), with no
numeric-PID reopening fallback. The returned descriptor comes from the socket's
retained peer identity; it is not a new process lookup. See the
[Linux 6.5 implementation](https://github.com/torvalds/linux/blob/v6.5/net/core/sock.c#L1671-L1699).
The receiver requires `SO_PASSPIDFD` disabled and still adopts/closes any forbidden
`SCM_PIDFD` before returning an error. The client also closes such unsolicited
descriptors. This accounts for the kernel's actual descriptor installation,
not just ordinary `SCM_RIGHTS`; see the
[ancillary pidfd receive path](https://github.com/torvalds/linux/blob/v6.12/include/net/scm.h#L127-L158).

The composition calls the actual target owner and then the read-only gate.
`verify_pending(deadline)` rechecks the retained peer/channel and gate without
sending anything. The future service must independently admit its controller
pin and authenticated listener and provision their ownership; the accepted
socket and this API do not supply that missing cold authority. There is no
daemon, listener creation, ready/send, resume, signature or terminal method.

[ReceivedBodyTargetV12](../data-plane/decision-gate-rs/src/body_observer_target_v12.rs)
owns the received descriptors and joins them to actual kernel/filesystem
observations: target PID and start ticks, shared pidfd identity, namespace
identities, immutable static supervisor measurement, exact cgroup membership and
the retained original launch context. It verifies that the fixed release file
is still absent. A numeric PID, decoded launch object or copied observation does
not replace this acquisition.

The read-only
[HeldBodyGateV12](../data-plane/decision-gate-rs/src/body_observer_gate_v12.rs)
takes that actual owner, not a caller-supplied census. `acquire(target, deadline)`
and `verify_gated(deadline)` check the original target and absent release around
bounded procfs observations: exact PID/Tgid, `TracerPid == 0`, one task and an
empty child list. Status reads are capped at 64 KiB, child reads at 4 KiB and the
task inventory at the selected task plus `.` and `..`. Calls may only shorten
the retained original deadline; they do not reopen a window.

This is a repeated live snapshot, not an atomic or continuously maintained
no-child guarantee. The owner does not stop, trace, signal, resume, detach or
reap a process, and dropping it only releases its owned descriptors. Passing
the snapshot does not authorize a ready response, a signature or a new claim
that an event source has been armed.

## Numeric ptrace attachment deliberately withheld

The proposed numeric `PTRACE_SEIZE`/`PTRACE_INTERRUPT` owner was removed before
integration. A task can exit and its numeric TID can be reused between the held
target check and `PTRACE_SEIZE`. A later original-pidfd/proc recheck can detect
the mismatch but cannot undo the attachment safely: signaling only the original
pidfd leaves the unrelated task traced, while `PTRACE_O_EXITKILL` can kill it when
the tracer exits. A numeric kill or detach fallback would introduce another
unapproved target operation, not repair the missing atomic association.

Linux documents that ptrace addresses individual thread IDs, that seize itself
does not stop the target, and that `EXITKILL` kills a tracee when its tracer exits.
The read-only replacement makes no pidfd-to-ptrace atomicity claim. See the
[ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html).

## Remaining boundary

A safe event acquisition owner, complete executable/kernel-provided mapping
treatment, continuous event history, independent signing authority and an actual
serving lifecycle remain missing. In particular, the current file-backed mapping
contract must not invent a backing file for `[vdso]` or silently omit it.
No listener provisioning, observer keys, release approval or production-runtime
proof is supplied here. The existing client must still obtain a genuine observer
original, and root must authenticate it and join actual exit/output/target
observations before its separate terminal publication path can succeed.
