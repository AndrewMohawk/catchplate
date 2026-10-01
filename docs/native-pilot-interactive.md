# Bounded interactive pilot interval

Explicit supervisor policy/v20 can keep the actual assembled pilot alive for
one independently approved interval after the genuine generation-origin
handoff. It retains policy/v19's native completed-invocation selection and the
same **164 jobs / 113 signing selectors**. This is a source feature, not an
available deployment or evidence that application requests succeed.

## Selection and sequence

Outer `serverware.nativePilotSupervisorCommissioningPolicy/v20` selects
`serverware.nativePilotSupervisorContinuationPolicy/v2`. The latter adds one
`interactive` field containing this exact static policy:

```json
{
  "apiVersion": "serverware.nativePilotInteractivePolicy/v1",
  "stopAtBoottimeNanos": 123456789000,
  "expiresAtUnixNanos": 1800000000000000000
}
```

Numbers above illustrate the wire only; they are not current approvals or usable
deadlines. Both must be positive integers within the existing signed 64-bit
wire limit. V18/v19 continue to require inner continuation/v1 and immediate stop.
The new outer purpose is
`initial-driver-bootstrap-through-bounded-interactive-native-shutdown`.

The source-fixed last `shutdown`/`stop` job remains in place. The supervisor
first performs the existing origin-handoff and inherited-clock validation,
then composes a `run-interactive` action bound to the exact observed handoff
hash and the two original absolute ceilings. The authority coordinator passes
that actual approved action to the conductor; it does not synthesize `stop` or
accept an application command. No additional authority key or arbitrary job
list is introduced.

The conductor retains its real driver, cohort and five ordinary service owners.
Their existing native inspection/lifecycle loops continue; actual PIDFDs are
watched for exit. A narrow post-release check does not reopen preparation or
create a heartbeat. The approved stop must precede all original live bounds,
including cleanup reserve and the native cohort's fixed 250 ms reap reserve.
The original UNIX expiry also remains in force. No duration renews a lease.

Both parent processes wait for the selected interval before entering their
existing bounded cleanup. SIGINT/SIGTERM remain active during that wait.
Cancellation or error sends SIGTERM through the actual retained child PIDFD,
even after the last commissioning job was sent. Positive final reply writes and
retained action bookkeeping are committed under a narrow signal mask; blocking
I/O waits remain cancellable. Unknown cleanup keeps ownership rather than
declaring success or retrying the attempt.

## Adopted lifecycle selection (.416)

The cold-to-adopted lifecycle now supports the same action through explicit
`serverware.nativePilotAdoptedSupervisorPolicy/v2`. Its purpose is
`independently-approved-adopted-native-commissioning-through-bounded-interactive-shutdown`;
its required `interactive` field uses the existing policy shown above. V1
cannot authorize an interval. Either version may still authorize immediate
`stop`, so an interactive selection never prevents safe early shutdown.

Every action still needs its separate request-bound Approval2. The retained
policy checks exact interval equality and the actual generation-origin handoff.
The adopted authority intersects the original driver/cohort/ordinary lifetimes,
cleanup/reap reserves, adoption and driver authorization expiry, and all five
ordinary generation-grant limits. It forwards the complete action through the
existing executor and actual parent/conductor wait paths; no new owner, job,
key selector, retry or duration-based renewal is introduced. The catalogue stays
176 jobs and 123 selectors.

This closes a source integration gap, not a live-session demonstration. Focused
verification is pending; deployment and an application allow/deny run remain open.

## Result and remaining work

A completed interval reports only its action/handoff hashes, actual start/end
BOOTTIME, actual end UNIX time and `approved-interval-ended`. Both parents join
that result to their retained approved action and original deadline, and must
also observe the actual child's terminal result and reap. Interval evidence is
forwarded only with `stopped-cleanup-complete`; legacy stop and failures cannot
carry it. `pilotAcceptanceVerified` and `productionReleaseEligible` remain false.

This does not execute an application probe or prove allow/deny behavior,
provider success, publication, attestation or process recovery. Mandatory
publication reconciliation must still have a genuine independently admitted
prior receipt and durable state: custody-configuration installation is not
policy publication, and an empty directory is not an authenticated baseline.
The separate publication foundations remain in progress. Independently approved
dependencies, protected services/inputs, connected application behavior and
full pilot/production acceptance remain required. Source checkpoints stay
**36/46** and production acceptance **0/6**.

## Focused verification

Exact source `6e53feaefdc20f482973455f3fbd4a12c9d75ece` passed all **27 focused
Python controls** in **3.899 seconds**: interactive, continuation-profile,
final-inventory and endpoint-commissioning suites. The eight new controls cover
closed policies, distinct continuation versions, exact handoff/action binding,
integer/clock/result bounds and forbidden acceptance assertions. All eighteen
changed Python files passed grammar checks and exact membership in both Make
inventories. This was one frozen run; no failed or repeated test batch.

Archive, harness, log, changed-file inventory and hashes are retained in
`codex-offload/serverware/engineering-builds/6e53feae-interactive-l3QQso/`
outside the repository. No cloud or paid action, running pilot, signal fault
injection, native/artifact rebuild or full owner transcript has been performed
for this source slice. Pure public policy/action/result controls do not
manufacture owners or claim integration acceptance. Publication Rust work is a
separate in-flight slice and is not covered by this result.
