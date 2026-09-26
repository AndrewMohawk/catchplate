# Integrated native body-observer lifecycle

Status: design for the remaining producer, not implemented release authority.
The current source is unbuilt and unexecuted. This document proposes a complete
session owner instead of treating more record decoders as a working observer.
It authorizes no provisioning, workload release, tests or production use.
The [initial persistence composition](controller-body-observer-persistence.md)
implements only the held, gated starting slice; continuous acquisition and the
release dependencies below remain unfinished.

## Starting point and hard boundaries

The actual [host coordinator](../data-plane/decision-gate-rs/src/body_observer_v12.rs)
receives held descriptors, admits the gated target, births the namespace worker,
retains its real initial stop, measures complete initial mappings and produces
one unsigned v14 history event. The
[worker](../data-plane/decision-gate-rs/src/body_observer_worker_v12.rs) then waits
only for abort/EOF. Its same-thread
[wait owner](../data-plane/decision-gate-rs/src/body_observer_wait_acquire_v14.rs)
and syscall-info reader acquire actual kernel metadata; neither offers resume.
The [history reducer](../data-plane/decision-gate-rs/src/body_observer_history_state_v14.rs)
checks reported transitions, not whether the kernel produced them.

Three decisions must precede any production-ready sender:

1. Establish an independently admitted execution/mapping policy that makes the
   promised observation coverage achievable. Tracing options alone are not it.
2. Provide a bounded host-owned store for exact acquisition originals, with an
   explicit acknowledgment/continuation rule and failure behavior.
3. Resolve namespace-init terminal custody. The namespace-local worker cannot
   be its own surviving final-outcome observer.

Existing signed v13 evidence remains unchanged. Its flat mapping inventory
cannot represent this temporal, multi-address-space model. A separately
versioned signed consumer must be implemented and deliberately enrolled; no
v14-to-v13 flattening, dropped special mappings or manufactured signature is an
acceptable bridge. See [history](controller-body-observer-history.md) and
[original-result admission](controller-body-evidence.md).

## Ownership and proposed interfaces

The full responsibilities in this section are proposed. `BodyObservationSessionV14`
and `HistoryOriginalStoreV14` currently implement only initial gated custody and
local original publication, not the policy, continuation or terminal authority
described in this table.

| Owner | Exclusive responsibility | Must not accept |
| --- | --- | --- |
| Host `BodyObservationSessionV14` | Consume `HeldInitialBodyHistoryV14`; retain controller channel, target/worker custody, admitted policy, original deadline and durable store | Caller-created successful history, substitute target or ambient policy/key |
| Namespace `TraceSchedulerV14` | Own all ptrace/wait operations on its creating thread; retain actual stopped-task tokens, birth joins, task/MM registry and continuation state | Generic PID/ptrace commands or a deserialized stop token |
| Host `HistoryOriginalStoreV14` | Publish unchanged snapshot/event and supporting acquisition originals; acknowledge the exact committed sequence/head | Hash-only replacement for missing originals or unbounded append |
| Host terminal owner | Reconcile actual final outcome, independently acquired output/static custody and durable history | Blindly signed terminal-request fields |
| Purpose-enrolled signer | Sign only the completed same-session claims after all joins | Arbitrary evidence dictionaries or a reducer-success DTO |

The host remains the actual worker's parent and sole reaper. Preserve the
[process owner's](../data-plane/decision-gate-rs/src/body_observer_process_v12.rs)
thread affinity, original pidfds, deadline and fail-closed drop ordering.
The worker keeps no signer key or external serving socket. A future serving
owner supplies independently authenticated configuration and protected storage;
socket ownership alone does not create that authority.

Consume the existing initial owner through a fixed internal transition; do not
copy its original bytes into a new owner and discard process custody. The
current `verify_gated` and initial-snapshot checks require absent release,
unchanged mappings and the initial stop. They cannot be reused unchanged after
release. Introduce explicit gated/running/draining/failed states with matching
custody checks; never disable those predicates with an unchecked Boolean.

## Ready, release and monitored continuation

The proposed sequence preserves the current independently held launch scope:

```text
actual initial stop + mappings
  -> policy admission + durable Initial snapshot/event acknowledgment
  -> worker armed with actual stop and original deadline
  -> host emits the existing scope-bound Ready while target remains stopped
  -> controller atomically publishes its existing one-use release original
  -> observer verifies that original through retained launch-directory custody
  -> one-use monitored continuation of the worker's owned stop
  -> acquire -> persist originals -> acknowledge -> continue, until terminal
```

Prefer observing the existing fixed release file over inventing a caller-selected
release path or a second authority. Its context/start/deadline joins must be
checked after Ready and before continuation. If an explicit release-notice frame
is later needed, version and integrate both endpoints; do not silently change
the v12 client protocol.

Replace the private abort-only worker protocol with a closed session protocol,
not a generic debugger RPC. The parent can acknowledge an exact persisted batch
and permit a specific owned stop generation to continue; it cannot nominate a
PID, syscall, register value or signal. The worker decides the permitted restart
from actual stop state. Duplicate/stale acknowledgments, missing originals,
deadline expiry, peer loss and queue overflow permanently fail the session.
Ready remains unsigned coordination, not runtime evidence or permission to
relax the execution policy. No admitted policy/store/terminal owner means no Ready.

## Descendant birth and exec replacement

Birth requires both the parent's real fork/vfork/clone event and the child's
actual initial stop. Keep either arrival in a bounded pending table until its
counterpart joins. Do not resume an unmatched child or infer parentage from a
mutable PPid field. Linux wakes the new task before reporting the parent's
ptrace event; the design therefore permits child-first observation. Retain the
actual event message, source task lifetime, child stop and namespace identities
before assigning a journal-local task ordinal.
[Linux v6.6 fork implementation](https://github.com/torvalds/linux/blob/v6.6/kernel/fork.c).

For the joined pair, hold both tasks, acquire the child's real identity/backing
custody and establish its MM relationship. Only then produce `TaskBorn`, persist
its required snapshot and acknowledge continuation. Pending counts, task counts,
descriptor ownership and original bytes need independent caps within the
admitted run. No synthetic birth fills a missing notification.

`CLONE_UNTRACED` defeats automatic ptrace inheritance; clone3 also supplies its
flags through a userspace structure. Consequently, scalar syscall arguments
alone are not authoritative captured clone3 flags. The admitted policy must
deny unsupported birth/async paths before they can escape acquisition, or supply
a separately authenticated complete kernel source. This includes deciding how
kernel-created asynchronous workers participate, not silently ignoring them.
[clone semantics](https://man7.org/linux/man-pages/man2/clone.2.html),
[kernel birth paths](https://github.com/torvalds/linux/blob/v6.6/kernel/fork.c).

On exec, join the actual exec stop and former-TID event message to the owned
group, reacquire the surviving task/executable/maps, and record exactly the
remaining peers superseded by that replacement. Do not manufacture final exits
for them: Linux changes a non-leader execing TID to the group leader's ID and
the old leader may have no final wait notification.
[ptrace exec semantics](https://man7.org/linux/man-pages/man2/ptrace.2.html).
Use the existing `Executed.retired_task_ids` transition; preserve unrelated
tasks still sharing the old MM. Retired numeric IDs never resurrect an old
journal ordinal. Missing or contradictory identity joins abort.

## Actual MM sharing and consistent mapping acquisition

Choose `kcmp(..., KCMP_VM, ...)` on genuinely held, stopped task identities as
the proposed direct MM-equivalence observation. Zero means shared MM; unequal
results mean distinct MMs. Running-task comparison can be misleading, and
kernel configuration/access checks can make the operation unavailable. Deny
that profile on failure; no fallback to equal maps, equal Tgid, a clone event
name or a caller-supplied sharing Boolean.
[kcmp documentation](https://man7.org/linux/man-pages/man2/kcmp.2.html).

The implementation must admit both task lifetimes before comparison, recheck
them afterward and perform the operation from the owning namespace/thread.
Use bounded equivalence-class representatives; do not introduce an uncapped
all-pairs scan. Journal-local MM IDs identify these observed lifetimes, not
kernel pointer values. Recheck relationships at births, exec and any admitted
operation capable of changing them.

Before a complete MM snapshot, stop every admitted sharer and close pending
birth joins affecting that MM. Acquire all map rows and executable backing
bindings under that barrier, then recheck the barrier and exact original maps.
One stopped thread does not freeze its siblings. Shared file contents can also
change through other mappings; immutable backing custody and separately admitted
external-write restrictions remain necessary.
[shared/private mapping semantics](https://man7.org/linux/man-pages/man2/mmap.2.html).

## Syscalls, mapping mutations and the kernel-policy boundary

The scheduler should retain real wait status plus applicable GETSIGINFO,
GETEVENTMSG and GET_SYSCALL_INFO observations before deriving a history event.
Syscall entry/exit/seccomp phases come from kernel metadata, never parity.
Pre-exit stops are not final exits. Signals and group-stops need an explicit
transparent handling policy; suppressing every signal or treating every stop
as resumable changes program behavior.
[ptrace stop distinctions](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Maintain an architecture-specific, independently admitted syscall profile.
For permitted mapping-changing operations, obtain before/after complete MM
snapshots under a sharer barrier and persist a `MappingsObserved` original before
returning affected tasks to userspace. Treat mmap/mprotect/pkey-mprotect/mremap,
unmap/brk, SysV attachment and exec as a starting inventory to close against the
actual supported kernel/ABI, not an exhaustive portable list. Unsupported
architecture, syscall, interrupted transition or unresolvable blocking/barrier
state fails closed. The scheduler must handle blocking calls without assuming
one globally runnable task can always make progress.

These observations do **not** prove instruction-by-instruction execution,
unchanged executable memory, absence of transient mappings, or absence of
external writes. A full-file digest is not a mapped-memory digest. Writable
aliases, anonymous/JIT code, remote-memory writes, mutable shared objects,
kernel-special mappings and asynchronous kernel activity require an explicit
allow/deny and acquisition design. Snapshot comparison alone cannot fill gaps
between observations.

An independently admitted kernel enforcement profile must close those gaps
before signed completeness claims. Linux exposes hooks including `task_alloc`,
`mmap_file` and `file_mprotect`; their existence is not proof that a particular
LSM configuration covers every relevant write, birth or executable transition.
Require the actual policy implementation, loaded identity, hook-path coverage,
scope and enforcement continuity, or deny unsupported behavior. Special mappings
such as vDSO need an admitted representation/kernel identity or genuine memory
acquisition; labels never become invented file measurements.
[LSM hook definitions](https://github.com/torvalds/linux/blob/v6.6/include/linux/lsm_hook_defs.h).

## Original-byte publication and backpressure

The host store must be outside the workload's write domain. It takes ownership
of bounded preprovisioned storage and retains exact canonical event/snapshot
originals plus the underlying acquisition observations required to explain each
transition. Persist a referenced snapshot before its event and acknowledge only
after the complete publication boundary, including required file/directory sync.
An ambiguous or incomplete append poisons the run; no acknowledgment, repair by
hash alone or resume follows. A documented filesystem/persistence contract is
still required; fsync is not a universal power-loss or anti-rollback proof.

Use bounded framed/chunked transfer for snapshots rather than assuming a 16 MiB
SEQPACKET message is supported. Authenticate the original worker/channel, bind
each transfer to session/sequence/length/digest, and reject missing, extra or
reordered chunks. Snapshot 16 MiB, event 256 KiB, one million events and combined
512 MiB originals are existing structural ceilings, not free disk/RAM allowances.
Provision byte/inode/descriptor limits and account queued acquisition originals
separately. Exhaustion aborts; it does not drop events or reset the deadline.
The current controller-output tmpfs is not durable host history storage.

The current [initial task-original transfer](controller-body-observer-acquisition.md#worker-to-host-task-originals)
implements a bounded credential-checked chunk path for the worker's eight
before/after status/stat originals and binds the exact stop. Those originals now
reach initial persistence. It does not yet provide continuous snapshot/event
transport, durable acknowledgment before continuation or complete native
wait/syscall acquisition originals.

## Namespace-init termination and terminal reconciliation

When PID-namespace init terminates, Linux kills the namespace's remaining
processes. **Inference for this architecture:** the namespace-local tracing
worker cannot reliably survive to report init's final wait or emit `End`.
[PID namespace lifecycle](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

Drain and durably acknowledge available records before allowing a controlled
init pre-exit stop to continue. Unexpected init death still produces an
incomplete run, never a success record. The host then needs an independently
admitted actual final-status source joined to the original target lifetime.
Polling its held pidfd establishes termination, not an exit code; holding that
pidfd does not make an unrelated process waitable by this parent.
[pidfd wait/poll semantics](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
Choose an authenticated runtime/real-parent outcome channel or a redesigned
surviving observer custody before implementation; a pre-exit event message or
the controller's terminal request alone is not the missing final-status owner.

Only after genuine final task accounting may the host record final retirement
and `End`. Worker death/EOF, an empty reducer or a timeout is insufficient.
Unjoined deaths, pending births, incomplete writes and unresolved MM lifetimes
prohibit a successful terminal. Outer cgroup/namespace/storage destruction stays
the controller's separate obligation.

Before release, also retain independent output-root/stream/static-executable
custody needed after process death. The current nine-descriptor handoff does
not carry an output-root FD or independent stream feed: implement a fixed,
source-owned acquisition seam or an explicitly versioned descriptor extension.
Rehash actual retained stream/payload/manifest originals after completion and
join the root's terminal request to them, actual exit outcome, original context,
source/artifacts/proxy, and native inventory when present. No hash in a request
authorizes signing itself.

Preserve the [acyclic claims order](controller-body-evidence.md#acyclic-signed-claims):
actual runtime/body claims, authenticated observer history, runtime report, then
original body terminal. The root still verifies the independent observer and
actual output/outcome joins before exclusive terminal publication. A new v14
consumer must bind history originals/head/counts, policy and kernel provenance;
enrollment of its signer/configuration remains an external prerequisite.

## Cohesive implementation sequence

1. **One session owner and release gates.** The initial persisted gated session
   now consumes actual initial custody and local storage together. Complete its
   fixed policy, independently admitted storage and actual terminal-source
   dependencies. Integrate worker-channel state and fail-closed cleanup. Until
   dependencies are genuinely admitted, preserve abort-only behavior.
2. **Acquisition through durable acknowledgment.** Implement the bounded real
   wait scheduler, birth rendezvous, task lifetimes, stopped KCMP_VM joins,
   sharer barriers, exec replacement and exact-original store/transport together.
   Extend the same-call opaque stop capability; no public event-to-owner shortcut.
3. **Complete monitored run and terminal ownership.** Implement the explicit
   ready/release/continuation transition, admitted syscall/mapping policy,
   independently acquired outputs and host-surviving final-status reconciliation.
   A bounded unsupported case terminates the run rather than relaxing coverage.
4. **Signed admission and serving integration.** Implement the distinct signed
   v14 producer/consumer, real policy/key configuration admission and fixed
   service lifecycle. Keep v13 behavior unchanged and public activation closed
   until independent provisioning and release requirements are met.
5. **Freeze, then verify the whole lifecycle.** Follow `goal.md`: immutable
   preparation first, then one consolidated source-consistent verification
   phase. Include child-first notification, shared-MM mutation, non-leader exec,
   unsupported births, signal/blocking paths, journal failure, init death and
   genuine terminal/output joins. Codec fixtures alone cannot establish these
   kernel or custody properties. No such verification ran for this design.
