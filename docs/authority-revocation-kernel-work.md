# Shared work accounting for the revocation kernel

## Scope

The private measured transition in
[`authority_transition_webauthn.py`](../catchplate/authority_transition_webauthn.py)
executes the actual unregistered self-revocation kernel using an enclosing
computation's remaining `_ValidationWork`. Public transition and cascade entry
points retain their unmetered behavior. Helpers create no fresh allowance,
reset no counters and accept no caller-supplied successful transition result.

This source is unbuilt and unexecuted. The kernel remains unregistered and does
not close any startup, planner, complete-query acquisition, SQL-maintenance or
production activation gate. Its ordinary returned mutations are not signed
authorization or evidence of a database commit.

The caller must already own the input graphs and separately admit the assertion
receipt, request/capability, current roots, complete query results and trusted
time. An evidence projection in a pure kernel fixture does not establish those
conditions. In particular, matching a list of selected dependencies to the
signed hints does not prove that the database omitted no matching rows.

## Genuine computation under one budget

The measured route preserves the actual sequence: argument normalization,
target ownership, assertion-row binding, complete selected-dependency checks,
cascade mutation construction, same-signer assertion merge, source business
bounds and final result construction. Shared accounting changes none of the
required revocation, counter, challenge, owner, audit-freshness or hint checks.

Existing argument and deterministic audit-ID workers are reused with their
existing work definitions. Prior query generation or receipt verification
does not give these repeated computations a free pass. Signed business
`work_units` remain a separate contract from hash/byte/node accounting.

The actual `KernelContext.exact` body copies its lookup key for every candidate
in the requested table, including nonmatching candidates. The measured private
route charges that real work rather than hoisting the key copy or replacing the
lookup with a second recipe. Dependency predicates likewise retain their actual
row copies and source selection semantics, including global registration
challenges and the combined pending/active session set.

Every real mutation constructor's key and after-row copies must be prepared;
updates also copy the before-row, while inserts retain a null before-row.
Both actual `KernelTransition` constructors canonicalize a result:
the cascade result and the final merged result. Those are separate real encoding
passes, even when much of their data is identical. Result merging, dependency
ordering and public credential projection also retain their own charges.

For `J` emitted audits, a successful full kernel computation performs
`4 + 3J` explicit SHA-256 calls. The four fixed calls bind the operation,
challenge row, public challenge and raw challenge bytes. Each audit performs
two deterministic identity hashes and one event digest. These counts exclude
source constants evaluated at import and any separately executed query, receipt,
capacity or proof computation. No Ed25519 verification happens inside this
kernel; the [actual receipt verifier](authority-assertion-receipt-work.md) must
establish the supplied evidence separately.

## Parsing before allocation

Three stored JSON fields are parsed by the actual kernel: challenge payload,
credential transports and attestation trust path. Their raw strings require
bounded preparation before parsing; measuring the returned graph afterward
cannot bound an allocation that already happened. The real parsers remain in
use, without substituting the receipt verifier's duplicate-object policy for
legacy stored-JSON semantics. For `U` raw UTF-8 bytes, the actual text walk
charges `U` bytes and one node, then reserves `U` bytes and `U + 1` nodes
before `json.loads(str)`. The successful total is `2U` bytes and `U + 2` nodes.
The walk also rejects more than 128 open containers, ignoring brackets inside
quoted strings. No bytes-to-text decode is invented at this string-parser site.

The existing intent normalization adds a fourth actual JSON parse to a successful
full transition. The original validated-base64 challenge decode and canonical
roundtrip also remain genuine, with their work reserved before codec allocation.
For encoded length `L`, padded length `P = 4 ceil(L / 4)`, decoded bound
`D = 3P / 4` and re-encoded bound `R = 4 ceil(D / 3)`, that reservation is
`L + 4P + 2D + 5R` bytes and zero nodes. The existing
`b64decode(altchars=b"-_", validate=True)` and URL-safe canonical re-encoding
both run; this helper does not inherit the receipt codec's separate alphabet
scan or add it to the accounting.
Stored timestamps retain their actual UTC parser and source comparisons.

Defined byte/node work is not exact interpreter memory or elapsed CPU time.
Conservative reservations remain spent, including on failure, and local
row/event/source limits remain independent of the enclosing cumulative budget.

## Semantic composition and remaining admission

The separate [semantic verifier](authority-revocation-semantics.md) now binds
the actual request digest, pinned receipt IDs, UTC cutoff and independently
supplied before vectors. It evaluates the retained proof once, runs this kernel
and the [genuine shared capacity finalizer](authority-audit-capacity-work.md)
on one ledger, then compares both source-sorted seven-field mutation inventories.
It accepts no supplied successful transition and does not register the candidate.
The [retained proof API](authority-revocation-proof-bundle.md) alone remains
proof-only; registry, independent currentness and SQL gates remain closed.

Source review and authored local controls do not establish runtime behavior.
The immutable dependencies, approved verification boundary, frozen source and
prepared no-build artifact closure remain required before execution evidence.

## Authored controls

[`test_webauthn_revocation_work.py`](../scripts/test_webauthn_revocation_work.py)
defines 20 source-only tests with independent output commitments and work
arithmetic. They cover same/separate signers, optional/no audits, whole selected
dependency predicates, exact and one-less budgets, already-spent and repeated
budgets, real parser/codec/constructor calls, and composition with the actual
capacity finalizer and its second validation pass using the same work object.
The Makefile lists this fixture in the isolated verification lane; listing it
does not mean it ran. Fixture assertion evidence and compact capacity rows are
explicit component projections, not independently authenticated authority.
