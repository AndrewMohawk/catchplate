# Cold ordinary-service retirement

The follow-on [cold commissioning mode](native-pilot-genesis-commissioning.md)
connects these owners to fixed jobs and protected public installation. The
remaining-work discussion below records the boundary at this earlier checkpoint.

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
`custodyGenesisOrdinaryTerminal/v1`, each prefixed with `catchplate.`. Sender
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

Frozen source `84207f6c066fb2c9a738f411caf866da15db3663` passes:

- **24 Python controls**, with no failures or skips, in **0.685 seconds**;
  five changed Python files also pass grammar and both Make inventories.
  One control uses a real socketpair, fork, kernel sender credentials, PIDFD and
  consuming child wait. The remaining controls check public protocol and
  assembly inputs, not live service owners.
- **Five real-child Rust controls** against the exact production retirement
  module: consuming stop/reap, repeat refusal, actual nonzero exit, `ECHILD`
  refusal and partial-startup destructor cleanup. A tiny offline harness imports
  the same source module and uses the project's existing pinned libc; it does
  not substitute a copied algorithm or successful validation stubs.
- The cached offline Rust 1.88 check of the gate, DRS, CSA, genesis controller
  and adoption validator, completed in **2m53s**. Compiler warnings remain;
  this is not a warning-free release build.

Python and real-child execution used one CPU and private user/network
namespaces. Rust compilation used the pinned network-disabled, resource-bounded
toolchain container. The native test executable was then run outside Docker's
default clone3 filter, with one CPU, a 1 GiB virtual-memory limit and a 45-second
outer timeout; each test child retained its own two-second absolute kill timer.
No full runtime-artifact build, cloud operation or paid test was performed.

The frozen archive, test executable, commands and logs are retained at
`codex-offload/catchplate/engineering-builds/84207f6c-genesis-retirement-QAvxG3/`.
These checks execute the real reap primitive, not the privileged inspection
helper or complete C9 stop/terminal ceremony. Actual protected provisioning,
service construction, event-woken shutdown under live traffic and end-to-end
cleanup remain unverified. Source checkpoints remain **36/46** and production
acceptance **0/6**; this result is not a running-pilot or native key-custody claim.

The complete independently operated commissioning graph and public
installation, retained cold-core transfer, adoption-validator/signing ownership,
operational recovery and authority transitions still need integration.
Independently approved dependency/release artifacts, Nitro/KMS/signing/witness
services and connected application allow/deny, provider, hardware and lifecycle
acceptance remain required.

The next connected implementation should extend the existing authority
coordinator with a separately selected cold job profile and protected installer.
The current hot job/approval profiles and publication destinations do not accept
these three cold launches. Producing a launch bundle does not install it.

Preserve the dependency order: actual parked owners and resources, ordinary
histories/runtime/C9 and static endpoint C9, retained Retrieval initialization,
Publication then Retrieval grants, ordinary grants, endpoint launches/releases,
then complete coordinator Runtime/v2 and its C9/key/launch inputs. The existing
assembly needs the actual services released before that coordinator runtime
can be approved. Install components before their launch file, with exclusive
fixed destinations and exact readback; native C9 requires root-owned public
runtime originals and separately role-owned credential originals.

Before endpoint cleanup, a separate retained owner must acquire and transfer
the actual fs-verity cold-core descriptor for operational adoption. A public
Bundle cannot substitute for that descriptor. None of this may renew the
original startup window or self-approve independently provisioned inputs.
