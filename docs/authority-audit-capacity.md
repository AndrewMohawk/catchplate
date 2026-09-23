# Audit event freshness and global capacity admission

Status: source implementation and source review only, unbuilt and unexecuted.
This is not an authenticated starting count, a startup repair, successful audit
delivery or production acceptance. See the [global integration contract](authority-global-audit-capacity-design.md).

`serverware.audit_outbox_contract.MAX_PENDING` owns the existing 100,000-record
limit. The legacy DB constant and global capacity validator use that value;
an aggregate cannot choose another limit. Generic quota and maintenance
aggregates retain their separately defined capacity and arithmetic.

## Business audit construction

The four policy writers retain fixed fresh-event counts:

| Operation | Fresh audit INSERTs |
| --- | ---: |
| `policy.activation.prepare` | 7 |
| `policy.genesis.prepare` | 1 |
| `rbac.binding.mutate` | 1 |
| `policy.activation.abort` | 1 |

`_fresh_audit_mutations` checks the operation/request-derived identity, exact
tuple size, distinct bounded ASCII string IDs, pending status and one exact
selected absence (`present: false`, explicit `row: null`) for every insertion.
Partial/orphan identity reuse, including identical pending or audited rows,
fails closed. It returns only the business INSERTs and has no database effects.

The eight quota/JIT emitters likewise return their fresh audit INSERT without
a local counter update. Their existing exact event-identity replay returns no
audit mutation and preserves pending/claimed/audited state. Fresh absence now
requires an explicit null row as well as exact false presence. Other quota,
traversal and maintenance aggregates remain unchanged.

Existing whole-operation replay branches remain. Activation preparation now
declares `permits_empty_mutation=True`, matching its existing empty replay branch
which retains consumed-evidence checks. This is not evidence of successful
signed replay; the authored source linkage fixture makes that boundary explicit.

## One framework counter

The common typed planner selects the new compact global row before invoking
the kernel and derives one counter CAS from its complete outbox mutations
before sorting, bounds, proofs or root computation. Policy and quota kernels
no longer query/update their separate old audit counters or grow a lifetime
operation map. Retained event/operation/evidence records still protect replay.

Pending insertion costs +1, movement between pending and claimed costs 0,
and counted-to-audited costs -1. Zero-delta updates still advance counter
revision; an empty replay stays empty. Unknown status, reopening terminal rows,
unselected/duplicate mutations and any nonexact counter update deny. Arithmetic
does not authorize audit completion or a DELETE absent from source templates.

All nineteen source outbox-writing declarations participate. Measured-plan,
reservation/completion and pre-DML SQL admission independently check the same
relationship. Source `.25` and primary-root profile v2 distinguish business and
framework row/mutation/work/byte/trace allowances; older profiles are not silently
expanded. The counter always needs a valid selected before-state, including
empty replay; there is no zero-on-missing fallback.

## Evidence and remaining work

Authored tests call real business helpers, global validators and source
contracts with independently framed rows. They cover fresh absence/count/ID
guards, one/seven-event composition, quota replay, fixed global bounds and
unchanged generic aggregates. Separate pure trace tests exercise exact
framework accounting; PostgreSQL component fixtures install the actual SQL
guard in a disposable external cluster. AST checks prove source linkage only.
None of these tests has executed, and none substitutes for whole-operation,
concurrency, rollback or independently authenticated evidence.

Authenticated initialization/backfill and a general receipt-bound PostgreSQL
delivery transition remain missing. SQLite retains its separate locked COUNT
and completion behavior. Direct production DML remains revoked. A fresh source
manifest, import closure and explicitly admitted installed-schema transition
are still required; image copying or this source commit alone is insufficient.

The [WebAuthn integration](webauthn-authority-integration.md), four missing
business kernels and [startup blocker](authority-transition-startup-blocker.md)
remain open. Verification must follow `goal.md`: finish source, freeze the exact
clean tree, then externally controlled preparation and sequential no-build checks.
