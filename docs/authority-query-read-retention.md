# Retained query observations and pre-kernel primary verification

## Status

This is source implementation, not executed planner or startup evidence. The
four missing WebAuthn transitions still block control-plane startup. No complete
index query primitive, SQL index writer, independent root checkpoint or new
snapshot protocol is activated by this change.

The typed reader now preserves individual query observations alongside its
existing deduplicated selected-row union. The measured planner obtains and
verifies the actual primary proofs before invoking the transition. These are
separate guarantees: membership verification does not prove that a SQL predicate
returned every matching row.

## Query records

`authority_query_reads.py` retains source query identities, canonical declared
and resolved query definitions, ordered selected addresses and actual returned
row counts. Address records hold table, canonical key bytes, BusinessKey/v1
digest and exact presence. They contain no mutable row or query aliases.

The source program is snapshotted before SQL. Deferred field references resolve
only from previously observed present rows. The typed reader's
[staged primary verification](authority-query-proof-staging.md) verifies those
source rows before resolving their values into SQL parameters or absence keys.
An omitted ordering becomes the source-owned primary-key ordering. SQL uses
that resolved query; retention does not independently reinterpret its parameters
afterward. Retained records alone still provide no membership authority.

The distinction between zero SQL results and an exact-key absence is explicit:

| Observation | SQL result count | Retained addresses |
| --- | ---: | --- |
| Ordinary empty query | 0 | Empty tuple |
| Exact-key miss | 0 | One absent address for the resolved key |
| Nonempty query | Number returned | Ordered present addresses |

Validation requires one record per declared query in execution order, including
empty queries. It rejects missing, extra or duplicate queries; within-query
duplicate addresses; mismatched keys/digests/presence; invalid absence forms;
forward, self or absent-row references; and global selections not covered by the
query records. Identical rows may legitimately occur in multiple queries. The
reader still rejects conflicting full-row observations of the same key.

`PlanningState` retains the source query program and immutable records. The
program is private bookkeeping, not a caller-supplied authority declaration.
After primary verification, record association is checked again against the
engine's owned selected-row snapshot. `KernelContext.observed_query_rows` exposes
one query's retained order without altering global `contractSelector` metadata.
Its name is intentional: it returns an observation, not a complete-range proof.

Retained definition/address bookkeeping has a separate finite 64 MiB aggregate
byte ceiling. Source program snapshots are bounded before SQL, and record bytes
are checked as records accumulate. Query and address-occurrence counts remain
within the source operation's row allowance, including its exact framework slot.
This is an additional admission restriction, not an increase to the existing
business row, work, selected-input or whole-plan limits. These measurements do
not claim an external parser or whole-process memory bound.

Source-value copying has a separate conservative byte count, depth limit of
128 and node limit of 1,000,000. It rejects lossy or unsupported types, cycles,
NUL and lone-surrogate strings rather than coercing them. Address inventories
share one copy budget; they cannot each spend a fresh allowance for every key.

## Proof-before-kernel ordering

`verify_primary_plan_inputs` invokes the actual primary membership engine using
source-owned operation/table contracts, exact supplied root descriptors and
operation bounds. It accepts original rows and proofs, not a previously created
successful result. It also applies the actual global audit-capacity input checks
with an empty mutation tuple; it never invents or initializes a missing counter.

The transition receives exactly the engine-owned row dictionaries. The matching
owned proofs remain the inputs to later mutation/root recomputation. The final
capacity/work checks and both existing root-transition/payload verification
paths remain in place. A mutable nested membership result is not an authority
token, and this earlier verification cannot replace final mutation verification.

The added phase has its own source-owned conservative hash ceiling. For maximum
selected count `N` and audit participation `A` (zero or one), it reserves 66 root
descriptor hashes, `66 + 70N` membership hashes, and `N + A` audit-capacity hashes:
`132 + 71N + A` in total. Cached empty hashes do not discount these allowances.
Vector, child-slot, depth, node and 64 MiB primary-input bounds remain separate.
The original business 4 MiB selected envelope and exact framework allowance are
also checked. These are per-phase limits, not a rewrite of persisted primary
transition metrics or kernel `workUnits`, and not total planner runtime cost.
Query bookkeeping has additional bounded key hashing, copying and association
passes; its work is not included in the primary phase's hash metric.

The separate [measured validation entry point](authority-query-read-accounting.md)
now accounts those repeated observation passes under one cumulative budget.
It preserves this legacy API and is not yet composed into planner admission.
Its result remains bookkeeping, not primary or complete-range proof authority.

## Remaining boundaries

The typed reader now stages membership proofs before deferred values influence
dependent SQL. This is membership relative to the captured database roots, not
independently current root authority, trusted time, or query completeness. Other
database-derived admission inputs do not acquire those guarantees merely from
the staged-reference path. Full final verification remains mandatory.

Query records are currently ephemeral planner state. They are not committed by
the existing Snapshot/v3, persisted as a new evidence protocol, or independently
admitted by the SQL executor. The [fixed index join](authority-index-primary-join.md)
still needs integration of the source complete-query declarations, retained
proof frontiers, same-checkpoint root-pair authority and closed versioned
Python/SQL transport admission. Existing exact-page metadata
does not gain completeness authority from these records.

The [distinct complete-index declarations](authority-complete-query-contract.md)
now have their own source-bound schema and can be retained as observations
without legacy ordering or absence synthesis. The planner reader rejects this
kind before business/proof SQL. The standalone bounded frontier reader performs
real root-relative reconstruction, but maintained storage, admitted root pairs,
primary joins and versioned retained-evidence integration remain missing.
Retention does not turn that declaration into proof evidence.

The original retention slice added 24 query-record component methods, nine
pre-kernel primary-input methods and one planner source-order method, preserving
all existing method identities. Staging adds separate reference and lifecycle
coverage. The retained-byte boundary fixture checks the real 64 MiB record
admission ceiling, not the separate source-copy budget. The primary-input
fixture composes actual membership verification, the counter-update kernel and
final root recomputation against independent tree hashes.

All authored component tests and source-order checks remain unrun. They do not
establish database behavior, signature acceptance, full planner execution,
startup, trusted time, rollback resistance or production completion.
