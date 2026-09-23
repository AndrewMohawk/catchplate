# Global audit capacity: coordinated implementation contract

Status: common planner/executor integration is implemented in source, unbuilt
and unexecuted. No admitted counter initialization, receipt-bound delivery,
migration or production invariant is established. Keep startup and production
gates closed; a missing global baseline denies every participating operation.

The components are `serverware/authority_audit_capacity.py` (pure
query composition, mutation finalization and independent validation),
`serverware/authority_audit_trace.py` (separate exact framework trace accounting), and
`serverware/authority_store/audit_capacity_sql.py` (an independent pre-DML SQL
assertion renderer). They are connected to the common typed planner, measured
payload admission, reservation/completion adapters, SQL executor and source
function/ACL inventory. The SQL assertion takes `(text,jsonb,jsonb,bigint)`;
the planner role receives only its five exact read-only invoker dependencies,
not business DML. Source revisions and installed manifests require a reviewed
transition, not automatic repair of an accepted database.

Authored pure, native and source-linkage fixtures compare independent
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

The removed policy and quota counters had different keys and partition digest
domains. Legacy staging still uses a locked SQL COUNT. No admitted initializer
produces the new scalar: the v8-to-v9 migration requires the aggregate table
empty, while ordinary aggregate mutation templates permit UPDATE only. The
phase-2 backfill specification is declarative and incorrectly describes the
audit limit as configuration-owned. Summing old counters, renaming one, or
inserting zero on a missing row would not establish the actual population.

The removed policy counter's per-operation commitment map grew for its lifetime.
A one-event entry uses 76 bytes plus the enclosing map, so 55,189 such
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
plan. The twelve existing emitters no longer select or update their old audit
counters; fresh-event identity and replay guards remain. Activation preparation
now declares the empty replay its consumed-evidence-checked branch already
returns. The relationship is independently checked at measured-plan validation,
planner-writer reservation/completion and SQL executor admission before business DML.
Do not add a hidden maintenance trigger: its unplanned row/root revisions
would escape the signed predicted transition.

## Bounds and version closure

Source revision `.25` and primary-root work profile `/v2` make the change
explicit. The original business ceilings remain 256 rows, 512 mutations and
16,384 work units; twelve reviewed operations reclaim one old query/mutation
slot. Final-plan ceilings are 257/513/16,386, but only the exact counter address
may consume the additional row/mutation. One composed query work unit is always
charged for participants, and one counter-mutation unit only when outbox rows
change. Empty replay cannot borrow the mutation unit. Generic aggregate,
single-query, challenge and selector limits are unchanged.

The selected business array remains capped at 4 MiB. Only the exact global
selection may use the extra 8 KiB envelope allowance; its row is at most 4096
bytes and `contractSelector` must be null. Both Python and SQL enforce the
separate business and total byte bounds. The planner DDL now admits the named
16,386 final work limit rather than the old inconsistent 4,096; raw requests
remain at 4 MiB. The 64 MiB composite plan/transport cap remains a separate
constraint: this is not a guarantee that every individual maximum fits at once.

Trace accounting retains 4096 business entries and grants only exact framework
identities: scan, row, leaf, 64 contiguous proof-node reads, a write when present,
and a root read only for the four source-declared new aggregate dependencies.
Shared-prefix reads for other proofs remain business-charged. The absolute
trace ceiling is 4165; no-op and shared-root cases receive less allowance.

The integration has these concrete seams:

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

The four WebAuthn participants now declare the aggregate UPDATE/proof permission;
this does not implement their missing business kernels. Final source packaging
and measured import-root hashes must include all new modules. Existing imported
closure artifacts are not evidence for the changed tree. Baseline and delivery
producers below remain required before this becomes a working global invariant.

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
