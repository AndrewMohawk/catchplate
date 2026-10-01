> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Request-bound current-head approval intake

The `.388` source connects eight late approval jobs between service material
and bridge-runtime installation. These are **independent decisions over actual
requests**, not automatically composed approvals. Source `65744b94` passes 107
focused controls; the `9dbdb9f5` refinement passes its one new targeted control.
Startup remains closed while the rest of the job graph is incomplete.

## Order and authority

Supervisor policy/v15 adds `currentHeadIntakeOriginal`. Its closed policy permits
only the fixed eight-target intake profile; it cannot preapprove future request
hashes, nonces or decision timestamps. V1–v14 keep their earlier field scopes.
The existing 108 signing-key selectors are unchanged.

The four ordinary service jobs use existing current-head input/v1. The helper's
four jobs use input/v2, ordered `settlement-store`, `fence-authority`,
`cgroup-executor`, `termination-ledger`. Each job reuses that service's approved
initial-checkpoint authority, not its history-root or delivery authority. The
helper's four decisions remain separate even though they share a signing key.
Signed results stay retained; there are no extra publication destinations.

The service-material owner hands authenticated public data to the first
current-head job only. The new owner retains that handoff and actual earlier
inputs/results. Subsequent jobs do not reopen earlier live owners across phases.
Every proposed complete current-head input must match the conductor's retained
bridge preparation, actual trust request, original bootstrap/window and service
runtime/history/generation bytes. Four helper histories must match the actual
primary and supplemental ceremony results.

## Pending approval and resume

At one of these jobs, `CommissioningSupervisor.step()` returns
`awaiting-independent-current-head-approval`, the actual pending job request
and an immutable public observation, with their exact byte hashes.
It does not construct a currentness decision, sign anything or publish an input.
The independent checkpoint authority must inspect those facts and supply the
complete existing current-head input plus an `AuthorityJobApproval/v1` for the
actual pending job. Protected bytes and matching hashes alone are not evidence
that the supplying authority is independent or that its decision is correct.

`resume_current_head()` accepts public read-only input and approval FDs with
independently authenticated SHA-256 pins. The intake retains duplicated FDs,
identities and exact bytes, checks their provenance boundary and source joins,
then uses the existing exclusive input-first/approval-last installer. No caller
path, executable, key selector or alternative job is accepted. The supervisor
cannot call its static approval serializer for these jobs.

Each admission attempt is consumed before reads. A failed or partial admission,
installation or reply fences the attempt; there is no retry. The original
boot/domain, startup, checkpoint, grant and request ceilings remain in force
through validation and publication. Waiting for approval never extends them.
Protected resources stay retained until genuine terminal cleanup is known.

Each actual signed result is fully authenticated on first receipt. Later
rechecks compare its exact approved input/pin and result bytes under the same
immutable source and original lifetime guards; they do not repeat the entire
five-service signature-validation graph for every earlier result. This avoids
unnecessary startup work without extending a deadline or accepting a changed
statement. Live startup performance has not been measured.

At the following job, the retained owner authenticates all eight actual signed
results before exposing them to the future bridge composer. The phase executor
already requires the runtime's eight handshakes to equal the authenticated
handshakes built from those exact inputs and outputs. Another valid signature
is not interchangeable with this attempt's result. Trust-request and handshake
digests retain their distinct existing domains.

## Remaining work

The current inventory has **150/159 handled jobs**: 142 fixed composers plus
eight protected late-intake jobs, with **nine current slots missing** and
**108 selectors**. Five additional bridge authorization prerequisites still
need insertion, so these numbers are neither complete remaining-work counts
nor a percentage of readiness. Source checkpoints remain **36/46** and verified
production acceptance **0/6**.

Next are complete bridge runtime policy/composition and installation, bridge
delivery and five authorizations, launch/publication and remaining
release/constructed/origin/stop jobs. Real worker cleanup needs compatible
parentage, a single reap owner and genuine cleanup-intent production. Executable
packaging, independent approval/signing services, immutable dependencies,
Nitro/KMS, provider/hardware execution, provenance and full acceptance remain.
No deployment, live signer or pilot is supplied by this source connection.

## Focused verification

Exact source `65744b94554f81809d8b2b9913fc69315a1444e9` passed all **107 controls
in 13 suites** in one Python 3.11.15 run (exit **0**, about **27 seconds**).
Ten changed Python files passed grammar and both Make inventories;
**47 relative documentation links** resolved. Eight new pure/synthetic controls
cover all eight signed input/result associations, chronology and substitutions,
evidence-only observations, and exact bridge-handshake result binding.

Two-file refinement `9dbdb9f537036d16e244d0a6e5e1b1be9aa81b62` changes only
retained-result reuse and its ninth control. That one new control passed in
**1.630 seconds**, with two-file grammar/both Make inventories. The 107 passing
controls were not repeated. The unbound inner phase/cache checks use explicit
synthetic namespaces and clocks; they do not construct a real owner or prove
protected FD intake. Native source/dependencies are unchanged and were not rebuilt.

Both exact archives, harnesses, commands, logs, result and verified thirteen-file
checksum manifest are retained locally at
`/home/catchplate/codex-offload/serverware/engineering-builds/9dbdb9f5-current-head-intake-9IeiSE/`.
Archive SHA-256 values are recorded in that manifest and `RESULTS.md`.

No protected supervisor/policy/intake owner, signing entrypoint, publisher,
native service, provider, hardware, cloud or paid operation ran. Live
pause/resume, independent approval provenance and startup performance remain
unverified. These checks are not pilot or production acceptance.
