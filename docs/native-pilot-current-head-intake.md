# Request-bound current-head approval intake

The `.388` source connects eight late approval jobs between service material
and bridge-runtime installation. These are **independent decisions over actual
requests**, not automatically composed approvals. Source verification is pending
at freeze. Startup remains closed while the rest of the job graph is incomplete.

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

Pending source freeze. One assembled Python pass will cover the changed
contracts and their adjacent public consumers. Unchanged native/dependency
builds are not repeated. No protected owner, signer entrypoint, service, cloud
or paid operation has run for this batch.
