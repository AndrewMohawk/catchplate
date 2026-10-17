# Counted secondary-index range reconstruction

## Status and boundary

This is a source-only, unactivated reconstruction component. The model in
[`authority_index_contract.py`](../catchplate/authority_index_contract.py) and
verifier in [`authority_index_range.py`](../catchplate/authority_index_range.py)
are not an installed secondary-index protocol. The current source has not been
built or executed. No WebAuthn kernel is registered by this work, and the
[startup blocker](authority-transition-startup-blocker.md) remains.

The component checks a complete interval relative to a supplied counted index
root. It does not authenticate that root, its currentness, its relationship to
the primary table, or the population that an index producer was supposed to
include. In particular, the raw range component alone provides none of:

- an admitted row-to-index projection or key encoding;
- SQL index storage, an index producer, or all-writer maintenance;
- primary-row membership joins or full-row selector rederivation;
- independent checkpoint, clock, writer-fence or migration admission;
- operation registration, transaction execution, or startup success.

It must not be substituted for those missing contracts merely because a
caller can construct a valid model or obtain a successful reconstruction.

The separate [fixed projections and primary-proof join](authority-index-primary-join.md)
now provides eleven source-owned selector codecs and joins returned leaves to
the actual primary evaluator's verified row snapshots. That unactivated
consumer establishes correspondence relative to a supplied root pair, not
complete initial population, maintained storage or independently current roots.

## Fixed tree and complete frontier

Paths contain exactly 160 lowercase hexadecimal nibbles at leaf depth. The
separate fixed codec uses a 32-byte equality-partition commitment, a 16-byte
order component and a 32-byte primary-key commitment. This raw component does
not interpret that layout or prove which row fields produced a path. The joined
consumer rederives the fixed encoding; SQL codec/migration admission remains
outstanding.

The fixed profile is `catchplate.policyAuthorityCountedIndex/v1`. Every hash
length-prefixes every frame, including its domain, with an unsigned eight-byte
big-endian length. Common frames contain that profile, index ID, table name,
projection digest and the decimal leaf depth `160`. Empty, leaf and branch
domains are respectively `catchplate.policyAuthorityCountedIndexEmpty/v1`,
`catchplate.policyAuthorityCountedIndexLeaf/v1` and
`catchplate.policyAuthorityCountedIndexNode/v1`.

An empty commitment binds depth, prefix and count zero directly, without a
recursively materialized empty ladder. A leaf binds depth, full path, count one,
primary-key digest and primary-row digest. A nonempty branch binds its depth,
prefix, checked total count and all sixteen child digest/count pairs in nibble
order. This is separate from the domain-plus-NUL primary-proof envelope format;
existing persisted primary-tree hashes and v3 primary proofs are unchanged.
Only an omitted child represents an empty branch; an explicit zero-count child
is rejected. Opaque counts and explicit child counts must also fit the maximum
number of fixed-width keys beneath their known prefix. At leaf depth that
maximum is one, not merely the signed 64-bit ceiling.

The requested interval is half-open. Bounds are full-width keys; an absent
upper bound means the exclusive sentinel above the largest key, and equal
bounds describe an empty interval. Its terminal frontier is a sorted,
prefix-free tuple containing selected leaves and positive-count opaque
subtrees. A selected leaf must lie inside the interval. An opaque subtree must
lie wholly outside it, and the whole root cannot be supplied as one opaque
subtree. Consequently, a nonempty subtree intersecting the requested interval
cannot hide matching leaves behind a digest.

Missing branches mean canonical empty subtrees. They are not a database's
assertion that no row exists: the verifier reconstructs the entire supplied
root commitment and count from the frontier and those empty branches. Omitted
nonempty branches, altered leaves, changed counts or substituted outside
commitments must therefore reproduce the expected root to be accepted. This
relies on the hash construction and on the supplied root being the intended
anchor; it does not establish that anchor independently.

An empty result still needs a frontier that reconstructs the expected root.
This is complete-interval enumeration, not a SQL `LIMIT + 1` check or a
continuation token. Count-only queries, disjoint interval unions and pagination
need explicit additional contracts rather than relaxing the opaque-subtree
rule for an enumeration.

## Inputs, work and observations

The public `reconstruct_complete_index_range` call takes the profile, expected
counted root, interval, terminal frontier and finite limits explicitly.
`IndexProfile`, `CountedNode`, `IndexLeaf`, `OpaqueSubtree` and `KeyInterval`
are frozen data models with exact-type validation and fresh revalidation at
consumer boundaries. Index/table identifiers are lowercase ASCII, bounded to
128 characters; digest strings are canonical lowercase SHA-256; counts are
exact integers bounded by signed 64-bit maximum. Its immutable return
contains selected leaves, the reconstructed root and work metrics. Neither an
input dataclass nor the output observation is an authority token.

`IndexRangeLimits` has these independent defaults and hard ceilings. Every
limit is an exact positive integer; a caller can tighten, not expand, them.

| Field | Ceiling |
| --- | ---: |
| `max_entries` | 8,192 frontier entries |
| `max_leaves` | 256 selected leaves |
| `max_opened_nodes` | 65,536 proper-ancestor nodes |
| `max_hashes` | 1,048,576 SHA-256 computations |
| `max_input_bytes` | 4,194,304 framed scalar bytes |

The `input_bytes` metric is a closed scalar-framing measure, not JSON size or
an assertion about allocations made before this call. Each already validated
ASCII field costs its byte length plus eight bytes for its length frame. The
header measures `catchplate.policyAuthorityIndexRangeInput/v1`, the profile,
index/table/projection identity, depth, expected root digest/count, interval
bounds (`top` for an absent upper bound) and frontier-entry count. A leaf adds
its `leaf` tag, key and two primary commitments. An opaque entry adds its
`opaque` tag, prefix, digest and decimal count. Limits themselves are not part
of that measure. This slice defines no JSON parser or transport protocol.

The other metrics are `entries`, `leaves`, `opened_nodes`, `child_slots` and
`hashes`. Opened nodes are the distinct proper ancestors of frontier terminals,
including the root even for an empty frontier; `child_slots` is exactly sixteen
times that count. One leaf costs one hash. An all-empty branch costs one hash;
a nonempty branch with `n` occupied children costs `17 - n` hashes, including
each direct empty-child hash and its own parent hash. Hash budget is charged
before the corresponding computation. Returned primary-key commitments must
be unique. Proof size and reconstruction work remain visible even if a future
producer shares physical database reads.

These component limits are not allowances added to an operation's existing
business query, mutation or work budget. They do not bound a future SQL sort,
network transfer, producer process or complete operation by themselves. The
eventual integrated caller must account for the complete query and proof set,
including empty queries and any union of intervals, under its own source-bound
budgets and deadline.

## Authored component coverage

`scripts/test_authority_index_range.py` contains 25 authored methods, all unrun.
It constructs expected hashes, complete small trees, sparse frontiers and
interval results independently of the production hash helpers. Cases cover
empty and boundary intervals, concealed or omitted populations, path/count
substitution, malformed or constructor-bypassed inputs, exact budget boundaries,
detached results and observed SHA-256 call accounting without cache discounts.
The full-width 256-leaf case expects 40,465 opened nodes, 647,440 child slots and
647,441 hashes; those are authored component expectations, not measured results
or proof of complete-operation capacity.

The script is listed in the isolated Python source inventory. This neither runs
it nor changes the native exclusions, approved coverage baseline, mandatory
controller/dependency prerequisites or sequential verification workflow.

## Required selector and maintenance integration

The concrete WebAuthn selector requirements come from the current legacy
queries and the unregistered revocation candidate; see
[WebAuthn authority integration](webauthn-authority-integration.md). The
[eleven source-fixed projections](authority-index-primary-join.md) cover these
populations, but do not yet supply their installed SQL query programs:

| Population | Required selection |
| --- | --- |
| Credentials | Exact credential-ID nonreuse across retained history; all-status user history; complete active, enrollment-trusted populations for candidate trust classification. |
| Registration challenges | Global and user-partitioned unused registration challenges beyond one fixed expiry cutoff. User sibling invalidation does not exclude approval-linked challenges. |
| OIDC sessions | All rows bound to an affected credential in pending-WebAuthn or active status, without adding an expiry filter. |
| Approval grants | All active rows bound to an affected approver credential, without adding expiry, remaining-use or reservation filters. |
| Control-plane approvals | All approved rows bound to an affected approver credential, including the audit required for each invalidation. |
| Trust publications | Exact bundle-digest reuse; global pending-state absence; monotonic generation ordering over both retained statuses. |

Exact challenge-ID/raw-challenge joins, first-enrollment session checks and
completion publication/high-water checks can retain primary-key proofs. A
raw-challenge secondary lookup is needed only if that legacy lookup is itself
part of the admitted query program.

The fixed projection contract distinguishes null from an empty string and pins
exact UTF-8 equality, signed numerical ordering and a BusinessKey/v1 tiebreaker.
Current expiry columns are SQL text; the new canonical UTC/microsecond codec
and text limits still require explicit SQL representation and legacy-data
admission. Passage of time changes the interval cutoff, not persisted membership.

Trust withdrawal must use the actual classifier, including first matching
root order, its development exception, missing roots, Python lowercase AAGUID
comparison and literal class matching. SQL locale-dependent lowercase is not
an interchangeable projection. Private development-key material must never
be copied into an index; only its explicitly derived presence fact is needed.
An optimized union of rejected root/AAGUID/class partitions needs its own
complete-union and normalization contract.

All admitted writers must atomically maintain the exact OLD/NEW projections
alongside primary-tree changes. The existing shared primary trigger is the
integration seam, not just the four missing kernels. This includes recovery,
challenge consumption/pruning, session activation/revocation, grant reservation
or consumption, foreign-key cascade deletion and primary-key moves. An unchanged
index key with a changed source-row digest still requires an index update.

Existing `policy_authority_secondary_index_heads` rows are metadata, not this
counted storage or a proof of complete initialization. New storage and helper
definitions need source manifests, owner/ACL closure and an explicitly admitted
migration. Bootstrap must prove both directions of the primary/index mapping
under writer exclusion and independently accepted roots; a database scan or
caller count cannot silently establish genesis for a populated relation.

Planner integration must retain evidence for each fixed query instead of only
flattening its selected rows. Primary and index proofs must join at the same
checkpoint, and the derived complete before/after head changes must be included
in transaction root validation. In particular,
`policy_authority_secondary_index_heads` is itself a primary-authenticated
relation keyed by `index_id`. A future maintenance trigger that updates one of
those heads will also change that relation's primary root. The executor's
post-mutation root comparison must predict that effect; it cannot be a hidden
extra mutation. Conversely, a trigger update and a separately executed planned
head update must not apply the same change twice or advance its revision twice.
This is an integration requirement, not a claim that such an index writer
already exists.

Existing exact-page metadata is not a range proof. Trust staging also needs a
reviewed aggregate operation contract: its
current one-publication mutation bound cannot represent approval consumption,
global challenge invalidation and every affected credential cascade.
