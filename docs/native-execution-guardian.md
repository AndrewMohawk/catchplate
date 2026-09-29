# Native executable-child guardian

This is a source-private, trusted-host-local mechanism. It is not a public start
profile, a running application, a production attestation or tested cleanup proof.
The child remains blocked before exec; actual same-child network enforcement and
the release/lifetime orchestration remain separate requirements.

## Actual ownership

`Guardian::arm` accepts only a private-construction borrow of a genuine new
`BlockedChild`. It duplicates that child's actual leader pidfd, creator-thread
pidfd and its claimed containment's fixed directory/kill/events descriptors.
No caller-selected PID, path, generic FD list or serialized successful check can
construct a guardian owner. The exact operation and pidfd identity are rejoined
to the blocked child before the guardian can be used by a future release path.
The genuine blocked child burns a one-attempt guardian latch before preparation;
failure cannot produce a second guardian attempt from the same child.

An independent `clone3(CLONE_PIDFD | CLONE_CLEAR_SIGHAND)` process remains outside
the workload's newly created leaf. Before reporting READY it closes every
inherited descriptor except those eight fixed controls, retains a blocked signal
mask, disables dumpability, sets no-new-privileges and checks the actual original
control associations and live parent/leader handles. It does not load or execute
an application, accept descriptor transfers, mint permission, or receive a
command capable of granting exec. This trusted launcher child inherits address
space contents; it is not a separate hostile-host or secret-custody boundary.

The parent owns the real guardian pidfd and private seqpacket endpoint. READY
must arrive within the existing admission deadline. It is not accepted from an
external endpoint or rebound to another workload. The guardian is armed only
after the new child is blocked, and never substitutes for that child's own
pre-guardian parent-death/ptrace protections.

## Stop and cleanup

The two BOOTTIME timerfds use the signed, already projected absolute stop and
cleanup deadlines. They are not `now + TTL`; suspend does not extend them. Parent
death, leader death, any channel message/EOF, stop-timer readiness, malformed
state or a monitoring error enters exact-leaf termination. Admission expiry,
approval revocation and journal diagnostics do not gate this emergency action.

Each guardian makes at most one write to its retained `cgroup.kill`; an error or
short write is never retried. The separate launcher containment owner retains
its own one-shot emergency action, so the two independent actors can both target
the same exact owned leaf during teardown. This is not a global exactly-once kill
claim and does not permit repeating creation, publication or application effects.

The guardian observes `cgroup.events` through bounded reads and waits only until
the original absolute cleanup bound. It reports an empty leaf separately from
whether its own kill write was acknowledged. Any uncertain or late observation
cannot produce successful cleanup. It never removes a cgroup or repairs journals.

`finish` cancels the guardian, requires its exact empty observation and reaps that
guardian through its original pidfd. This does **not** reap the workload leader:
that direct child remains the launcher's responsibility. A combined lifecycle
result must require both actual leader reap and leaf-empty evidence. Dropping an
owner sends stop/EOF and attempts only a nonblocking reap; it never waits forever,
kills the guardian, or asserts successful completion.

The private `GuardedChild` composition consumes actual start preparation and
network parents, claims containment, creates the blocked child and arms its
guardian. Its explicit termination evaluates both child cleanup and guardian
completion even if one fails, requiring exact workload and guardian reaps plus
their empty-leaf observations before producing a local data-only result. It has
no release/continue operation and therefore does not yet run an application.

## Kernel basis and remaining acceptance

The implementation follows the kernel's distinction between whole-subtree
termination and the separate populated observation in the
[Linux 6.12 cgroup-v2 documentation](https://docs.kernel.org/6.12/admin-guide/cgroup-v2.html).
It uses absolute suspend-aware timers as described by
[timerfd_create(2)](https://man7.org/linux/man-pages/man2/timerfd_create.2.html),
and an actual process handle created atomically by
[clone3(2)](https://man7.org/linux/man-pages/man2/clone.2.html).

No build or runtime validation has run. The frozen verification phase must prove
the actual supported kernel/permissions, READY-before-release ordering, parent
death, child death, expiry, malformed channel/controls, failed kill, bounded empty
observation, both exact reaps, and absence of surviving task-owned resources.
