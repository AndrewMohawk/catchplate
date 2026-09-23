# Global audit capacity: coordinated implementation contract

Status: implementation in progress, not an admitted migration or enabled
production invariant. The `de99011` checkpoint repairs four policy writers but
does not provide this global counter. No current build or execution evidence
exists for this work. Keep the full startup and production gates closed.

The prepared components are `serverware/authority_audit_capacity.py` (pure
query composition, mutation finalization and independent validation) and
`serverware/authority_store/audit_capacity_sql.py` (an independent pre-DML SQL
assertion renderer). They are not yet connected to the production planner,
reservation adapter, executor or installed function inventory. Their existence
does not supersede the live four-writer repair or initialize a shared counter.

There are 17 authored pure component methods, 13 source/rendering methods and
23 native PostgreSQL component methods. Source review compares independent
state/key framing and real operation templates; no test has executed. The
Python component excludes NUL and unpaired surrogates before serialization,
matching PostgreSQL's representable string boundary. SQL JSONB has already
discarded duplicate keys and original exponent spellings, so the SQL guard
cannot replace original-byte admission. Complete depth/node/64 MiB native
boundary execution is also still required.
Generic non-counter integers remain subject to the frozen Python interpreter's
integer-to-decimal digit limit and PostgreSQL's numeric representation limits.
The native fixtures establish neither universal parity for arbitrary-size
integers nor original-byte admission. Integration must retain exact canonical
transport validation and close that numeric input profile; all global-counter
numbers are already explicitly bounded signed-64 integers in both components.

The Python/source fixtures enter the isolated test inventory. The native SQL
fixture requires an externally prepared disposable PostgreSQL Unix-socket
cluster; it never starts an engine. Like the existing PostgreSQL components,
it remains in the excluded native-test inventory until the prescribed runner
admits it. The changed-test gate must fail closed on that exclusion, not treat
it as a passing test or permit manual execution before implementation/freeze.

## Source findings that determine the implementation

There are twelve registered audit-producing operation names: activation
prepare/abort, genesis prepare, RBAC mutation, control-approval
request/decide/consume/deny, and JIT request/review-receipt/decide/deny. Nineteen
operation declarations permit outbox writes, including future/missing kernels
and kernels whose current body does not emit an audit. The invariant must
follow declared write permission and actual complete mutations, not a list of
today's call sites.

The nineteen declarations are `policy.activation.prepare`,
`policy.activation.finalize`, `policy.activation.abort`, `policy.genesis.prepare`,
`rbac.binding.mutate`, `control-approval.request`, `control-approval.decide`,
`control-approval.consume`, `control-approval.deny`, `jit.request`,
`jit.review-receipt.issue`, `jit.decide`, `jit.deny`, `release.reserve`,
`release.v1.reserve`, `webauthn.trust.complete`, `webauthn.registration.create`,
`webauthn.registration.finalize` and `webauthn.credential.revoke`. This list is a
review inventory, not a substitute for the source write-permission predicate.

Current policy and quota counters have different keys and partition digest
domains. Legacy staging uses a locked SQL COUNT. No admitted initializer
produces either scalar: the v8-to-v9 migration requires the aggregate table
empty, while ordinary aggregate mutation templates permit UPDATE only. The
phase-2 backfill specification is declarative and incorrectly describes the
audit limit as configuration-owned. Summing old counters, renaming one, or
inserting zero on a missing row would not establish the actual population.

Policy's per-operation commitment map also grows for the lifetime of the
counter. A one-event entry uses 76 bytes plus the enclosing map, so 55,189 such
entries already exceed its 4 MiB map limit, before reaching 100,000 pending
events. The encompassing state JSON repeats this map and has its own 4 MiB SQL
bound. Selected rows additionally face a 4 MiB envelope limit. A global count
must not use this lifetime map or discard retained replay evidence to make it
fit.

## New compact profile

Use a new, source-owned aggregate identity, distinct from both old scalars:
kind `metadata-audit-outbox-global-capacity-v1`, partition domain
`serverware.metadataAuditOutboxCapacityPartition/v1`, frame `global`. The
existing generic aggregate row/state envelope can hold it, but its semantics
are separately closed:

- `live_count == active_count` is pending-plus-claimed cardinality.
- The exact integer capacity is the source-owned 100,000 limit.
- Reserved and committed unit maps are exactly canonical empty objects.
  Replay remains bound by retained audit identities, consumed evidence and
  operation/capability state; this is not authority to prune those records.
- No expiry or work-page state is present; the expiry root is the source empty
  root. Time passing does not remove an outstanding audit.
- Revision advances once for a transaction touching outbox rows, including
  zero-delta status changes. Sequence advances by fresh counted INSERTs only.
- Missing, malformed, stale or over-capacity state denies admission. There is
  no implicit bootstrap or reconciliation from untrusted database counts.

## One explicit planned CAS

The planner supplies an exact selected before row for this global identity to
every outbox-writing program. After business mutation construction, derive the
counter effect from the complete unique OLD/NEW row set, not a caller's charge:

| OLD to NEW | Outstanding delta |
| --- | ---: |
| Absent to fresh pending | +1 |
| Pending to claimed, claimed to pending, or unchanged counted membership | 0 |
| Pending/claimed to audited | -1 |
| Audited to audited | 0 |
| Counted deletion, only if separately permitted | -1 |
| Audited deletion, only if separately permitted | 0 |

Unknown statuses, fabricated absence, changed primary identity and conflicting
before rows fail closed. Arithmetic does not authorize deletion, inserting an
already-audited row, reopening terminal rows or marking an event audited
without a verified ledger receipt. Current outbox templates do not allow
DELETE. An empty exact replay must remain an empty mutation plan.

Append exactly one compact-counter UPDATE when there are outbox mutations and
none otherwise. Include its selected row, full-row CAS, mutation template,
query/mutation/work/byte costs and computed after-root in the existing signed
plan. Remove per-kernel counter mutations/queries rather than charging twice.
Independently rederive the relationship at measured-plan validation,
planner-writer reservation and SQL executor admission before business DML.
Do not add a hidden maintenance trigger: its unplanned row/root revisions
would escape the signed predicted transition.

## Bounds and version closure

Changing this shared contract needs a coordinated source/measurement and
installed-manifest transition, not a helper-only edit. Preserve the original
business allowance when adding framework accounting; reclaim old counter
query/mutation slots where they existed. Default operations already reach the
global 256-query/512-mutation ceilings, so a blanket increment cannot pass the
old profile. Any additional framework allowance must be named, bounded and
carried through a new primary-root work profile, Python admission, generated
SQL constraints and source inventories. Do not silently truncate the business
set to make a test fit.

The planner table currently limits work to 4,096 although source operations can
declare 16,384. Its selected-row envelope also has a separate 4 MiB limit in
both DDL and the Python reservation adapter. Correct those specific persisted
bounds as part of the reviewed framework allowance; raw request/challenge
limits are not permission to raise unrelated transport or secret-input caps.
New modules must enter the signed v9 import closure, not merely image COPY.

The next integrated batch has these concrete seams:

1. `authority_contract.py`: explicitly grant the four WebAuthn participants the
   aggregate UPDATE and proof primitive, close business versus framework
   allowances, and advance the source/profile versions. Reclaim old query and
   mutation slots only for the twelve reviewed writers. Do not assume a uniform
   work-unit credit: policy kernels have fixed work charges, while quota kernels
   often charge by mutation count.
2. `authority_transition_policy.py` and `authority_transition_quota.py`: remove
   their old audit-counter queries/updates while preserving fresh-event identity,
   exact absence, pending status, operation charges and whole-operation replay.
   Unrelated quota, traversal and maintenance aggregates stay intact.
3. `TypedTransitionPlanningProgram.read_inputs`: compose the exact global query
   before any selected-row reads. In its transition method, retain the real
   `KernelContext` and finalize the complete business mutation batch before
   bounds, sorting, traces, proofs, root derivation or signing. Preserve declared
   no-op behavior; a counter must not turn an empty replay into a write.
4. `validate_measured_plan_payload`, `reserve_authority_planner_transaction`
   and `complete_authority_planner_transaction`: independently validate the
   supplied selected/mutation relationship before accepting or persisting it.
   Historical replay uses its historical before-state, not today's counter head.
5. The v9 SQL executor and source-owned installer: install and inventory the
   exact invoker function, close owner/EXECUTE privileges and signature/source
   admission, and assert the relationship before business DML. Retain existing
   locks, full-row CAS and after-root comparisons. No caller-selected deltas or
   new planner payload fields are needed.

The current components still enforce the existing operation maxima; they do
not yet grant that extra framework allowance. Activating the hooks alone would
deny the four permission-incomplete WebAuthn declarations and every participant
without an admitted baseline. The coordinated changes and baseline/delivery
producers below are required before this can become a working global invariant.

## Delivery and initial authority are separate required producers

PostgreSQL claim/finish explicitly reject direct delivery and refer to measured
`record_inclusion`. The current activation inclusion kernel records receipts
but does not select/update the metadata outbox. The legacy inclusion recorder
instead requires the outbox row already audited. Consequently adding a
decrement to the SQLite finish helper cannot repair production liveness.

Implement a general, receipt-bound PostgreSQL delivery transition for all
outbox producers: join the original immutable event, verify actual ledger
inclusion through admitted independent evidence, and commit terminal status,
counter decrement and receipt consumption together. Ambiguous ledger append
acknowledgment does not free capacity. Exact terminal retry is zero-delta;
conflicting ledger/event identity denies. Activation-specific receipt
bookkeeping alone cannot cover unrelated JIT or credential events.

Fresh empty genesis may establish zero only under authenticated empty roots
and admitted writer exclusion. Populated migration requires complete
status-bearing source evidence and an independently accepted root checkpoint.
The existing migration outbox digest covers event identities/bytes and total
row count, not status membership, and cannot be reused for this purpose.
Offline copies preserve pending/claimed/audited status; SQLite migration first
completes local audit. Neither is authority to fabricate a global baseline.

SQLite retains its separately scoped locked COUNT and inline completion
semantics until an explicitly implemented transition covers it. PostgreSQL
runtime direct DML remains revoked; the v9 executor is the integration point.
Do not reopen direct privileges to work around missing delivery or bootstrap.

## Required evidence

Author and then run, only after the repository verification gate: real helper
and PostgreSQL guard cases for every state transition, whole-batch capacity,
missing/extra/crossed counter CAS, duplicate identities, malformed states,
underflow/overflow, exact replay after delivery, unchanged inputs and full
rollback. Integration must prove full-capacity concurrency, actual ledger
receipt admission, interrupted/ambiguous delivery, authenticated initialization
and migration replay under writer exclusion, complete source manifests, and
source-root startup. Component arithmetic or same-database consistency alone
does not establish independent roots, omission-proof bootstrap, trusted time
or production readiness.
