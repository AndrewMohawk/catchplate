# Bounded primary-tree read batching

Status: source implementation and authored component fixtures only; unexecuted.
This repairs a proof-acquisition trace bottleneck. It does not supply complete
predicate/range evidence, independent current roots or any missing WebAuthn
kernel, and does not make control-plane startup healthy.

## Actual producer and planner integration

The singleton `authority_radix_proof.derive_multiproofs` still issues one leaf
lookup and 64 child-vector lookups for each selected row. It retains the existing
SQL, parameter shapes and contiguous trace block. Its extracted leaf helper is
also used by the new `derive_multiproofs_batched` path; leaf validation is not
replaced by a synthetic proof or a database-supplied count.

The batched path admits at most 256 selected business/authorization rows. Each
leaf still has one exact singleton lookup. The producer derives every required
`(table, child depth, parent prefix)` from the existing authenticated-key digest,
deduplicates those identities for this call, sorts them, and groups at most 16
parents into each node lookup. Groups may span tables and depths. A fixed typed
`VALUES` join requests at most 256 exact child identities; its result limit and
bounded fetch retain one additional overflow sentinel.

Returned child table/depth/path, digest, uniqueness and revision are checked
against the exact request and that child's own table root. Text-size checks use
`CASE` projections so a malformed retained record becomes a rejection rather
than being filtered into apparent absence. Missing children use the unchanged
empty-subtree hashes. A well-formed but false or omitted child is still detected
by the real root reconstructor, not by the read producer alone. SQL projections
and deterministic cursor tests are not protection against a hostile driver's
earlier allocations or proof that a live server honored the query.

The cache is local to one invocation and its before-root inventory. Every output
proof receives its own mutable child arrays. The complete sorted v3 proofs,
proof digests, 64 levels, 16 slots per level, persisted hash framing and root
reconstruction semantics remain unchanged. No sparse/abbreviated wire proof is
substituted for the existing format.

The live planner separates only the exact source-owned global audit-counter
address. Participating operations require exactly one such selection; others
require none. It produces that proof first through the old singleton path,
then batches all remaining selections and sorts the combined proof set. Other
aggregate keys, including ones sharing tree prefixes with the global counter,
remain business charged.

## Physical reads versus proof-evaluation work

For `N` non-counter selections and `U` distinct parent identities, the producer
performs `N + ceil(U / 16)` cursor queries, with `U <= 64N`. Consequently its
source bound is at most `5N`: 960 reads for 192 selections, or 1280 for 256.
The separate counter adds 65 reads. These are acquisition bounds, not wall-time,
query-planner, total SQL-byte, whole-operation or production capacity results.

Every batch emits one trace entry for its one actual node SELECT. Its closed
key profile is `catchplate.policyAuthorityRadixReadBatch/v1`, containing a sorted
unique list of one to sixteen parent identities with exact depth/prefix shapes.
Producer and trace consumer use the same validator and limits. Unknown declared
profiles, additional fields, duplicate/unsorted parents and overflow reject.
Existing non-profile trace keys retain their prior decoding behavior; this is
not a new proof that every signed trace entry corresponds to an executed read.

All batches count toward the unchanged 4096-entry business trace ceiling. They
cannot interrupt or replace the separately reserved global counter's contiguous
leaf-plus-64-node block. Root reads, selection queries, selected rows, writes and
other operation work still consume their own existing allowances.

The separate `PrimaryRadixLimits` evaluator continues charging every complete
proof vector and child slot, hash, normalized input byte and JSON node. Sharing
SQL reads does not discount that work or enlarge an operation's row, mutation,
deadline or transport limits. The fixed primary-root profile v2 and persisted
database source revision therefore remain unchanged. This is not unchanged
implementation identity: the altered reader/planner code requires new measured
source, launch and artifact closure before any accepted run.

## Authored coverage and remaining work

`scripts/test_authority_radix_batch.py` contains actual pure-producer cursor
fixtures with independently constructed expected trees, complete singleton/v3
byte parity, multiple relations/composite keys, malformed/omitted sibling
controls, 192/256-row acquisition bounds and real audit-trace budget composition.
Its planner AST check is supplemental, not executed planner coverage. The old
singleton fixture and its 65-read expectations remain present.

The native primary-tree fixture additionally exercises the real batched SQL
inside its existing disposable PostgreSQL transaction. It remains subject to
the exact native inventory and all existing prerequisites; these authored tests
have not run. No omitted, changed or excluded fixture is promoted into passing
coverage by this implementation.

Authenticated ordered-index storage, all-writer OLD/NEW maintenance, bidirectional
bootstrap admission and complete range reconstruction still require a new
coordinated contract. Hashed primary keys and self-consistent exact-page metadata
do not supply them. Independent root checkpoints and trustworthy predicate time
also remain absent. See [WebAuthn authority integration](webauthn-authority-integration.md).

Full planner/executor/witness execution, whole-operation trace/work/transport
capacity and all four startup kernels still need implementation or verification.
Prepare and verify only after the complete source freeze and independently
admitted dependency, controller and coverage prerequisites are satisfied.
