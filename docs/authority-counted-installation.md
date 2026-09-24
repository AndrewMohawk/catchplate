# Counted storage installation and writer wiring

Status: source integration, unbuilt and unexecuted. Source revision `.29`
connects the counted store to PostgreSQL bootstrap, expected-schema replay and
the actual primary-tree row trigger. It does not enable complete-query planning,
install anything on a running database, or establish independent root authority.

## Installation boundary

The real `db._install_policy_candidate_authority_guards` calls
[`prepare_counted_store`](../serverware/authority_store/counted_installation.py)
inside its existing offline-bootstrap transaction. The pristine expected-schema
replay uses that same installer. The three dedicated counted tables and eleven
helper functions have PostgreSQL-only schema/permission inventories; SQLite's
table and trigger inventory is unchanged.

The helper accepts only a fixed quoted namespace and an active caller-owned
transaction. It admits the six fixed source tables and either zero or all three
store tables as permanent ordinary relations, excluding partitioning and
inheritance. It acquires deterministic write-excluding source locks, rechecks
relation identities, and locks an existing store before inspecting its heads.

- Fresh storage requires every indexed source table to be empty under those
  locks. Only then are the actual table definitions and all eleven exact
  source-profile revision-zero empty heads inserted.
- Existing storage requires the complete eleven-head source identity and valid
  revision/count/root descriptors. No missing head, table or population is
  repaired, reset or inferred to be empty.
- A populated predecessor requires a separately admitted bidirectional restage.
  This source change supplies neither that migration nor permission to rewrite
  an accepted database. Existing source/structural-contract mismatches still deny.

Checking an existing descriptor is not reconstructing its complete population.
Fresh local emptiness is not an externally enrolled checkpoint. Schema admission,
population/root association, writer exclusion and independent currentness remain
distinct requirements.

## Actual row maintenance

The existing SECURITY DEFINER primary trigger captures PostgreSQL OLD and NEW
rows. For each of the six indexed tables it invokes the real invoker dispatcher
after the corresponding normalized primary event. A primary-key move performs
DELETE then INSERT for both trees within the same SQL statement. Nonindexed
tables retain their primary-only behavior.

The dispatcher selects every fixed profile for the source table; callers do not
choose a subset. Missing heads or a failure in any later profile abort the
statement, including already applied business, primary and counted changes.
Counted tables remain framework storage, not recursively indexed business rows.

The dedicated NOLOGIN owner owns the helpers. Runtime, executor, planner-writer,
verifier and PUBLIC receive no direct helper EXECUTE grant. Catalog admission
binds the exact signatures, invoker mode, strictness, volatility and search paths;
the existing owner closure and full expected-schema comparison remain mandatory.

## Limits and remaining activation work

The installed-source contract explicitly distinguishes per-profile/event limits
from whole-operation accounting. There are at most three profiles per normalized
event; the existing v3 business work count is not a measurement of SQL hash work.
The [private acquisition path](authority-complete-acquisition.md) now shares
defined head/range/row and proof work with query bookkeeping. SQL maintenance,
commit and whole-operation accounting are not covered by that meter; independent
root-vector protocols remain due.

The public v3 planner still rejects complete-index queries before business/proof SQL.
Its current v3 payload, signature, persisted replay and SQL Snapshot/v3 cannot
silently acquire extra counted evidence fields. The private collector now runs
genuine primary/range joins, but typed execution then rejects before the kernel.
Retained complete read/write evidence, independent roots and time, and a
coordinated versioned replay/commit contract are required before activation.
The four WebAuthn startup gaps remain open.

The 14 isolated installation controls, five added ACL source controls and eight
added native trigger/installer controls are authored only. All 24 previous
counted-maintenance native IDs remain, giving 32 in that suite and 252 across
the unchanged fourteen-suite native inventory.

Authored unit/native controls must be executed against one frozen source through
the prescribed prepared lane. Source review and fixture counts are not evidence
of PostgreSQL installation, rollback behavior, startup or production readiness.
