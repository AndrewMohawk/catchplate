# Historical registration exchange admission

[`authority_registration_history_exchange._verify_on_configuration`](../catchplate/authority_registration_history_exchange.py)
authenticates the original planning, caller-authorization and execution-grant
exchange without requiring a reservation or completion to exist. It is a private
source-only verifier, not present-caller authentication, recovery permission or
renewed execution authority. No tests or runtime verification ran in this batch.

## Inputs and result

The keyword-only API takes `payload`, `configuration_digest`, `generation`,
`runtime_role_identities`, `originals`, `authorization_enrollment_bytes`,
`grant_enrollment_bytes`, `current_root_enrollment_bytes`, `root_public_key`,
`live_window`, `work` and optional `transport_deadline_ns`. Configuration,
enrollments and the root key require independent admission; returned originals
cannot appoint their own expected keys or scope.

`originals` is the existing immutable raw10: caller authorization, planning
request raw3, planning response raw4, complete before-vector and grant. Existing
per-original and planning-group bounds apply, with at most 64 MiB for those ten
originals plus all three enrollments. Original bytes and detached configuration
graphs are held before native callbacks. The caller's cumulative work is reused.

The frozen private `_HistoricalRegistrationExchange` contains only same-call
facts: `request_digest`, `operation_id`, `authorization_digest`, `database_id`,
`generation_digest`, `expectations`, `planner_public_key` and
`evidence_public_key`. No verifier accepts that result in place of the original
exchange. It carries no pending head, executable grant, currentness or permission.

## Genuine full replay

The helper authenticates the [original planning request](historical-evidence-planning-request.md),
[original planning response](historical-evidence-planning-response.md), exact
request/response input equality and [historical plan observations](historical-evidence-planning-history.md).
It then verifies the [original dedicated caller authorization](registration-historical-authorization.md)
and joins its request/operation/generation to the independently configured
planning scope.

Admission additionally runs the actual complete-vector plan replay over raw3
and the original before-vector. It checks genuine plan proof/input semantics,
affected predecessors, complete after-vector derivation and allowed changes.
Every claim derived by `grants._replay_claims` must equal the genuinely signed
historical grant: original frames and byte counts; request/operation;
retained-record, plan and result identities; complete before/after-vector
identities; original plan interval; and signed snapshot/capability identities.
Grant signature plus a before-vector hash alone is insufficient.

The real historical grant control verifier separately authenticates the
root-enrolled dedicated authorizer, key separation, caller-authorization
identity, database/generation and enrollment scope. Its original interval must
remain within the authenticated caller and planning intervals. No live verifier
is given a fabricated historical clock to bypass expiry.

## Processing and authority boundary

Historical controls may have expired. Their signed positive intervals,
configured age/skew limits and mutual ordering still apply. The independently
supplied current processing window is unchanged, with sticky wall/monotonic
checks and any shorter inherited deadline. Expiry, rollback or cumulative work
exhaustion fails; no helper creates a new allowance or revives an old grant.

[Completion history](registration-completion-history.md) reuses this exchange
admission while retaining its full raw10/raw3/raw4 aggregate bound and separate
genuine pending/completion-original verification. The separate
[completion recovery path](registration-completion-recovery.md) integrates
historical retained-subject ownership through genuine signer-original joins,
present-actor/recovery-purpose admission and bounded reconciliation in this
same source-only batch. This module performs none of those actor, transport or
storage actions. Credential finalization, action-time currentness and
cross-generation historical authority resolution remain separate; no signing,
SQL, retry or renewed execution authority is provided here.

Deferred frozen coverage must include changed full-vector descriptors and each
grant claim, unrelated authentic exchanges, key/scope substitutions, impossible
original timing, expired processing windows, clock reversal and shared-work
exhaustion. Source presence is not production acceptance.
