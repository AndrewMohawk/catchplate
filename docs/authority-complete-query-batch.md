# Operation-bound complete-query batch

## Source boundary

This document describes the implemented source-only batch contract in
[`authority_complete_query_batch.py`](../serverware/authority_complete_query_batch.py).
It is unbuilt and unexecuted. No build, test or SQL execution is claimed, and
the planner's complete-query gate remains closed.

The batch covers the five source-declared roles for explicit
`webauthn.credential.revoke`. It connects
[bound query declarations](../serverware/authority_complete_query.py) to actual
[complete-range/primary joins](authority-index-primary-join.md), under one shared
verification budget. It is not a general query language or operation authorizer.
Supplied roots, arguments and cutoff remain supplied evidence, not an
independently current checkpoint, authenticated intent or trusted clock.

## One owned input graph

`verify_complete_query_batch` accepts the operation, actual argument dictionary,
cutoff, five declarations, full business/authorization before-root vectors,
global selected rows and proofs, four counted read heads and five raw frontiers.
No independent per-query primary rows, successful observation, alternate
verifier or caller-expanded budget is accepted.

Before a hashing constructor or proof verifier runs, all raw fields are copied
into one bounded internal JSON graph: arguments, root descriptors, declaration
selectors, counted heads/frontiers and global rows/proofs. Exact lossless types,
incremental compact ASCII JSON bytes, depth and visited-node limits constrain
that copy. This internal accounting representation is not a new retained wire
protocol or a claim about an upstream parser's allocation.

The real global primary membership evaluator then verifies the full
operation-declared root inventory and all supplied global rows/proofs.
Per-query subsets come only from that evaluator's owned rows/proofs. Each of
the five real joins must
reconstruct its range and bijectively match its leaves to those rows, with the
same source primary before-root. The current operation requires null
`contractSelector`; no annotation-stripping shortcut is introduced.

## Query and head closure

| Query roles | Shared counted head | Group ceiling |
| --- | --- | --- |
| Pending-WebAuthn and active sessions | `webauthn_session_credential_status` | 32 distinct primary addresses across both roles |
| Active grants | `webauthn_grant_approver_active` | 32 |
| Approved control-plane approvals | `webauthn_control_approval_approved` | 32 |
| Global unused registration challenges after cutoff | `webauthn_registration_unused_global` | 32 |

All five roles and all four heads remain required even for empty results.
Frontiers follow declaration query-ID order; read heads are sorted and unique.
Both session roles therefore use one identical head, not independently supplied
root pairs. A query's row limit still derives from its source hint-list length,
with the existing minimum of one and maximum of 32. Hints do not establish
membership, completeness or permission to truncate a result.

Every head must satisfy the fixed profile's revision/empty-root conventions and
fit the corresponding primary population descriptor. Revision zero is valid for
a canonical empty index even if the primary table contains nonmember rows.
These necessary checks do not prove historical index population or currentness.

The global selection may also contain legitimate source-bound point selections,
including exact absence proofs and rows overlapping a complete query. Verifying
this batch does not prove those ordinary queries were declared or complete;
the separate mixed QueryRead contract remains necessary before kernel use.

## Shared verification accounting

The source ceilings are 8,000,000 charged hashes, 64 MiB of defined input work,
1,000,000 charged JSON nodes and depth 128. Ownership copying, the two selected
envelope measurement passes, genuine global membership and every actual join
are separately charged. Repeated proof work is not refunded because the same
row or head appeared in an earlier phase. Remaining limits are clamped before
the next evaluator runs.

The JSON-node total counts the ownership walk, both selected-envelope walks
and each actual primary-engine traversal. It does not count every fixed-size
descriptor or context serializer; those retain their separate source bounds.

The wrapper's conservative context allowance is 95 hashes: a cold primary
descriptor allowance of 66, five declaration constructors, ten binding
constructors, four profile hashes, four empty-root hashes, five outer anchors
and one source projection-manifest hash. Each real join separately retains its
existing conservative context, range, primary and projection charges.

The source business selection limit remains 192 rows and 4 MiB of canonical
selected-envelope bytes. At most one additional selection may use the exact
global audit-counter address; the combined envelope remains limited to 4 MiB
plus 8192 bytes and 193 rows. An omitted counter or an exact counter absence
proof does not become initialized audit-capacity authority. The separate
capacity admission still requires its genuine present state and semantics.

For a query limit `m <= 32`, the batch uses the reader-sized range profile:
`4800+m` frontier entries, `1+160*m+320` opened nodes,
`16*(1+160*m+320)+m` reconstruction hashes and 4 MiB of range input. Generic
range proofs can have more finely subdivided outside subtrees; exceeding this
tighter profile rejects rather than expanding its budget. These limits admit
the existing reader's canonical-cover shape, not every generic range proof.

The returned frozen observation exposes the actual global primary result,
owned rows/proofs and raw evidence, actual ordered joins and phase metrics.
Nested dictionaries remain mutable owned observations, not reusable authority
tokens. The component accounts verification work, not SQL acquisition, network
transfer, backend plans, deadlines, total memory or kernel work units.

## Remaining production composition

[`test_authority_complete_query_batch.py`](../scripts/test_authority_complete_query_batch.py)
contains 20 authored, unexecuted methods with independent primary/counted tree,
manifest and accounting oracles. Controls cover real global membership and all
five joins, empty results, shared heads, the 32/33-session union boundary,
genuine proof/frontier corruption, caller mutation after the pre-hash snapshot,
the 192-plus-one exact framework slot and selected-envelope bounds. Exact
private-ledger limits are not proof that a valid full batch reaches every
maximum. Native-suite counts and execution deadlines are unchanged.

The [combined read/write entry point](authority-complete-read-write.md) now owns
mutations and write frontiers in the same initial graph, invokes these genuine
query phases and the actual indexed writer under one shared remaining budget,
and binds their identical before descriptors. Its counted vector is the union
of read heads and every fixed profile of written tables; queried-only after
heads remain unchanged. It does not accept this observation as prior proof,
produce a retained transition wire or activate the planner.

Retained query transport, mutation-frontier acquisition, schema/ACL and all-writer
maintenance, authenticated population, trusted cutoff/intent, audit-capacity and
kernel admission, Snapshot/v4, SQL before/after checks, receipts and independent
current-root authority remain required. The existing primary transition and
nine-frame Snapshot/v3 contracts are not changed by this component.
