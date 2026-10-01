# Cold ordinary-service retirement

This continues [cold launch and coordinator assembly](native-pilot-genesis-assembly.md).
Its purpose is to retire the two real inspected ordinary services and their
inspection helpers. A finished coordinator is not evidence that those processes
have been reaped, and cleanup is not evidence that a publication succeeded.

## Shutdown order

The cold inspected entry retains its original delivery, parent channel, worker
and absolute timers across the serving call. Only this cold profile observes
parent stop traffic in service accept/receive waits. A pending stop unwinds the
serving stack before the entry validates that request. Other profiles keep their
existing treatment of unexpected parent traffic.

If the serving call returns first, for example because the coordinator closes
its connection, the entry retains those same owners while waiting for the stop
request. It does not resume serving or create another cleanup interval.

The request binds the exact C9 delivery, service role, invocation and original
deadline. The service closes its inspection helper's real stop pipe and consumes
the helper's `waitid(P_PIDFD)` result. Only the private result of that actual reap
can support the terminal notice. The notice binds the request and reports the
serving outcome separately from helper retirement.

The Python parent authenticates the notice against its retained channel and
same unreaped service child, then consumes that service's own PIDFD reap and
checks the reported exit disposition. Both stages are required before releasing
resources. A nonzero serving exit can coexist with known cleanup; it cannot be
reported as operation success.

The wire is `custodyGenesisOrdinaryStop/v1` followed by
`custodyGenesisOrdinaryTerminal/v1`, each prefixed with `serverware.`. Sender
authentication uses kernel `SCM_CREDENTIALS` together with the retained channel,
PIDFD, start time and direct-parent relationship, including an unreaped zombie
whose final packet is still queued. This is not per-packet `SCM_PIDFD` evidence.
The real exit must match the terminal's serving status 0 or 1; a later protocol
or cleanup failure exits 2 and cannot satisfy that comparison.

Forced kill, missing or malformed notice, incomplete startup, expired original
timers, or `ECHILD` remain cleanup-unknown. The retained owner and relevant
capabilities remain reachable; absence of a process is not a substitute for
consuming its actual same-parent reap.

Wholly parked children remain a separate case: before any release can reach
native execution, no inspection helper can exist. Their actual direct-child
reaps remain sufficient for pre-release cleanup. A possible or partial native
release cannot use that exception. Resource retirement keeps accurate remaining
descriptor inventories across partial close failures.

## Verification and remaining work

Implementation verification is pending the frozen-source batch. This change
does not establish protected provisioning, a running cold ceremony, native
key custody or production acceptance. Source checkpoints remain **36/46** and
production acceptance **0/6** until the broader requirements have evidence.

The complete independently operated commissioning graph and public
installation, retained cold-core transfer, adoption-validator/signing ownership,
operational recovery and authority transitions still need integration.
Independently approved dependency/release artifacts, Nitro/KMS/signing/witness
services and connected application allow/deny, provider, hardware and lifecycle
acceptance remain required.
