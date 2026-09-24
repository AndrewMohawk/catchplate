# Primary proofs before dependent queries

## Status and scope

This is unexecuted source implementation. It stages primary membership proofs
for the typed planner's deferred field references before those values influence
dependent SQL. It does not make the four missing WebAuthn transitions available,
prove query completeness, or establish independent authority for database roots.

The [retained query records](authority-query-read-retention.md) identify which
earlier observed row a reference needs. Those records are bookkeeping, not proof.
`authority_query_staging.StagedQueryProofs` acquires the actual primary proof and
invokes the actual membership engine before `resolve_query` produces parameters.

## One collector per planning transaction

The measured planner creates the collector after reading the before-root vectors
and keeps it private to that invocation. It is not part of `PlanningState`, a
caller-provided verification result, a reusable credential, or a serialized
protocol. Non-typed planning paths retain their existing final verification.

For each source-snapshotted typed query:

1. Enumerate `SelectedRowFieldReference` values in predicates and absent keys.
   Each must name an earlier present observed address with the requested field.
   This step does not resolve the field as a query parameter. Address checks may
   inspect primary-key columns, including a key column named by the reference.
2. Acquire proofs only for reference sources not already verified by this
   collector, using the real batched SQL proof producer and captured roots.
3. Verify them with the real primary membership engine and source-owned table
   contracts. Use the engine's owned row snapshots for subsequent resolution.
4. Resolve the source query from those snapshots, then execute its SQL and retain
   the new observation. No dependent SQL runs after a staging rejection.

Repeated references reuse the original verified proofs rather than causing a
second physical proof read. Equal overlapping query results preserve the prior
owned wrapper; canonically different full rows reject the transaction. Mutable
cached rows and proofs are guarded by immutable canonical stamps. The cache is
not permission to change a verified field and reuse it for another query. Row
stamps are checked before cache reuse; cached proof stamps are checked at final
merge, before those proof dictionaries are returned from the collector.

The collector binds the cursor and trace identity and enforces a one-way
lifecycle. Once final proof selection begins, no additional query staging is
allowed; final proof merging cannot be repeated. A failed operation leaves the
collector unusable rather than admitting partially accumulated evidence.
The guard also rejects reentrancy: a caught nested error permanently poisons the
outer operation, including proof completion and merge. An already executing
bounded producer may finish its current reads; no successful membership/cache
publication or collector result follows from the poisoned invocation.

## Final verification is still required

`unproved_rows` selects only the remaining global rows for `_derive_multiproofs`.
The exact global audit counter is never an early deferred source: it stays in
the existing final singleton proof path. `merge_proofs` requires unique, exact
coverage across the retained early proofs and the remaining proof inventory.

The complete merged input still passes `verify_primary_plan_inputs` before the
kernel. That phase applies the actual audit-capacity guard, including the
required compact counter. The early membership stage cannot call it before the
counter is read, and does not invent a counter or claim capacity admission.
Final mutation/work checks, primary-root recomputation and signed-payload
reverification remain mandatory and separate.

## Source-owned cumulative bounds

Let `B` be the operation's maximum business selected rows, `R` the number of
distinct referenced rows and `S` the number of nonempty verification stages.
The collector requires `S <= R <= B <= 256`. A referenced address cannot spend
a second row allowance at another barrier.

Root capture conservatively reserves 66 hashes once. Each membership stage
retains the actual engine's independent cold allowance and full per-proof
charges: `66 + 70n` for `n` present sources. The aggregate source ceiling is
`66 + 136B`; the tighter observed composition is `66 + 66S + 70R`. Cache state
does not discount charged membership work.

Across all early stages, input bytes are limited to 64 MiB, JSON nodes to
1,000,000, proof vectors to `64B` and child slots to `1024B`, with depth at most
128. Remaining limits are applied before each reconstruction, not reset to a
fresh full allowance per stage. Source query-call counts are bounded separately.
These are additional admission restrictions, not increases to operation rows,
kernel work units, final selected envelopes or the outer 64 MiB plan ceiling.

Canonical cache-stamp creation and rechecking have their own cumulative 64 MiB
byte and 1,000,000-node budgets. They are not hidden under the membership engine's
input metric. The actual planner additionally supplies one shared
[QueryRead bookkeeping ledger](authority-query-read-accounting.md), used for
source snapshots and reference enumeration even on cache hits. Its identity is
bound before the reader begins; none of these staging phases can replace it.
Legacy standalone collectors may omit that meter and retain their original
named public query-helper route. The production typed planner may not omit it.
None of these component metrics claims total planner CPU, process memory, SQL
producer allocation or an external parser limit.

## Trace and wire compatibility

Each disjoint staged batch of `n` rows needs at most `5n` physical proof reads.
All stages plus the unproved remainder therefore stay within `5B` business proof
reads. An audit-participating operation retains its separate 65-read singleton
counter block: one leaf and 64 consecutive node reads.

The current trace contract allows interleaved reads before the final mutation
write suffix. Counter markers remain unique and its proof block stays intact.
No synthetic trace entries hide proof reads, and no whole-inventory final proof
reread is added. Actual trace digests naturally change with execution ordering.

Proof/v3 shapes, primary-tree hashes, root-transition metrics and the exactly
nine-frame Snapshot/v3 contract are unchanged. No staged cache or query record
is promoted into new signed completeness evidence. A later complete-index
protocol still requires coordinated versioned producer and Python/SQL admission.

The [private complete-acquisition path](authority-complete-acquisition.md) now
uses this actual staged collector when merging global primary proofs, then
performs the global primary check and all six real range/row joins on its shared
query/acquisition meter. Staged proof and cache-stamp budgets remain separate.
Its raw evidence cannot cross the current typed pre-kernel protocol gate; public
v3 complete queries still deny before business/proof SQL.

## Remaining production boundaries

Membership is relative to the supplied captured database roots. Those roots,
database time and other aggregate admission reads are not made independently
authoritative by checking a deferred reference. Index population/all-writer
maintenance, authenticated bootstrap, same-checkpoint primary/index roots,
trusted time, rollback-resistant witness state and complete bounded WebAuthn
kernels remain separate requirements.

## Authored verification coverage

The staging fixture retains 20 methods using the actual proof producer and
membership engine against independent tree/store data. They cover source
ownership, deferred resolution, cache reuse and mutation rejection, transaction
lifecycle, cumulative source limits, the final singleton counter block, and
mandatory complete-input verification. Three query-record methods cover source
enumeration, and one new planner source-order method covers transaction-local
construction and proof reuse; the existing observation-order check is extended.
Existing test method identities are preserved.
Seven additional methods cover shared-meter identity and exact cumulative work,
preconsumed and exhausted allowances, cache-hit bookkeeping, legacy compatibility,
and caught reentrant failures during acquisition/completion. There are 27 authored
methods in that fixture; none is passing evidence yet.

All of this coverage is authored but unrun. The cursor fixtures are deterministic
SQL responders, not PostgreSQL. They do not prove database execution, transaction
isolation, service startup, production infrastructure or end-to-end release
acceptance.
