# Primary-root transition source contract

Implementation/review only. This source has not been built or executed. The
project's frozen, externally controlled verification prerequisites still apply;
none of these component fixtures is production or full-operation evidence.

## End-to-end binding

The measured planner emits mandatory `rootTransition` in PlannerResponse/v3 and
`rootTransitionDigest` in MeasuredPlan/v3. SignedMeasuredPlan also moves to v3.
The closed `serverware.policyAuthorityPrimaryRootTransition/v1` object contains
the fixed `serverware.policyAuthorityPrimaryRootTransitionProfile/v2` identifier,
complete ordered business and authorization before/after root vectors, and
strict integer work metrics. Each root includes table, revision, digest and
leaf count. Snapshot/v3 appends the transition digest as its ninth frame. The
existing capability snapshot field binds this new snapshot; there is no optional
legacy-plan fallback and no additional mutable root-transition database column.

`authority_radix_mutation.py` validates every before proof against the exact
supplied head, including proof digest, selected key, presence and full row. It
merges consistent vectors by table/depth/path prefix, applies distinct original
key mutations simultaneously, then reconstructs their union of ancestors once.
It does not sequentially invalidate one proof while checking another. Full-row
CAS, no primary-key moves, exact INSERT/UPDATE/DELETE lifecycle, signed-int64
counter bounds and read-only authorization roots are mandatory. Every mutation
increments revision, including an identical UPDATE. Only INSERT/DELETE change
leaf count; deleting the final row yields the empty root at a nonzero revision.
Unchanged relations remain in the complete after vector.

`authority_root_transition.py` provides the strict wire profile and recomputation
used by both the producer and the signed-plan consumer. The consumer recomputes
the complete delta and metrics before accepting it; a self-consistent digest
alone is insufficient. Persistence retains the exact canonical ASCII plan bytes,
their length and SHA-256. The SQL executor checks these bindings and the closed
v3 profile before even returning a committed retry. Fresh execution compares the
actual locked before roots and, after mutations, actual business and authorization
after roots before receipt construction or consumption writes. A mismatch raises
inside the transaction. Historical replay binds the old receipt to its stored
plan, without requiring current heads to equal historical after heads. The
orchestrating service compares the returned before/after/snapshot commitments and
receipt digest to the verified plan before recording its terminal witness step.

## Source-owned keys and authorization rows

`authority_primary_contract.py` records reviewed active-schema primary keys. It
derives operation-specific business/authorization classes and write permissions
from the source operation contract, not caller row shapes or database metadata.
The complete source key inventory must exactly cover all declared relations.
Both manifest loaders compare every selected metadata field, entry digest and
global digest with source-generated values before returning source-owned query
contracts. Installer catalog checks additionally require these exact key columns
and source manifests; existing physical-index and structural checks remain.

The spurious `policies` relation was removed from JIT dependencies: actual policy
data is the `routes.policies` column. Policy checks and approver-policy validation
are unchanged. The manifest-table `maximum_rows` constraint now admits the
already-declared source selector limit of 128 (previously the table admitted only
64 while the installer emitted 128). This is a source schema correction, not an
authorization to alter an existing installation.

Authorization projection now uses actual proof-selected primary-key rows,
including exact absence, rather than synthetic `authenticatedRelation` table-head
selectors. Every declared authorization relation must have a selected source;
missing query coverage fails instead of synthesizing authorization evidence.
The existing store limit of 64 authorization source rows remains. The source
high-water digest is the actual AuthorizationRootSet/v1 commitment. Read traces
must cover selected authorization rows as well as business rows.

## Work and evidence boundaries

The separate fixed primary-root work profile v2 allows at most 257 selected proofs,
513 declared mutations (unique selected keys impose a tighter effective bound),
16,448 proof vectors, 263,168 child slots, 35,018 charged hashes, 64 MiB normalized
input, JSON depth 128 and 1,000,000 JSON nodes. Each proof carries all 16 child
slots per level. Cold empty hashes are conservatively charged even when cached.
These metrics describe a single evaluator invocation, not total process memory,
wall time, SQL I/O, transport-envelope size, or the older transition `workUnits`.
The old v1 profile is rejected, not reinterpreted. Source revision `.25` keeps
the original business limits while assigning the additional row/mutation to the
exact global audit counter. [Capacity admission](authority-global-audit-capacity-design.md)
separately enforces that partition. Relational-root inventory remains 256;
transport, trace, deadline and transition-work limits remain independent.

The [bounded primary read producer](authority-primary-read-batching.md) now
batches physical child-vector lookups while retaining byte-identical full v3
proofs and these evaluation metrics. Its separate trace profile does not change
persisted roots or discount hash/vector work. The planner keeps the exact global
counter's singleton proof block; whole-operation runtime capacity remains unproven.

The shared engine also exposes `evaluate_primary_radix_memberships`, which
performs genuine read-only proof verification and retains the exact detached
row/proof dictionaries it verified. Both public entry points freshly revalidate
limits, table contracts and root descriptors, including constructor-bypassed
objects. The [fixed index join](authority-index-primary-join.md) uses this owned
snapshot without rereading caller rows or accepting a caller-created successful
result. Existing mutation wire formats and charged metrics are unchanged;
the nested membership dictionaries are owned but not immutable authority tokens.

The planner's [pre-kernel input phase](authority-query-read-retention.md) now
uses that actual membership engine and source operation/table contracts before
passing owned rows to a transition. Its separate conservative hash allowance
also covers root-descriptor and audit-capacity input checks. It does not replace
final mutation/root recomputation or change this persisted transition profile.

Authored fixtures cover independent whole-tree rebuilds, shared-prefix batches,
source-key closure, counter/count semantics, strict lifecycle and wire negatives,
and shared PostgreSQL guards with transaction rollback and historical replay.
Manifest-admission fixtures call the same pure admission function used by both
SQL loaders, including coherent key/entry-digest substitution with a copied
global digest label, strict numeric flags, exact JSON spelling and row closure.
Pure fixtures use actual source operation contracts without patching the missing
kernel registry. Textual/AST wiring tests do not establish runtime integration.
The PostgreSQL fixture uses opaque post-admission stand-ins and directly invokes
the production guard fragments; it is not the complete signed execution path.
It uses the shared tree canonical SQL and extracts the actual wire-domain SQL
support definition, including the Snapshot/v3 exactly-nine-frame exception;
other domains retain their 1–8 bound. Separate [primary-tree SQL controls](authority-primary-tree-sql.md)
exercise the actual production row triggers and full independent tree oracle in
authored native tests, not hand-assigned after roots. They remain unexecuted.

The pure component scripts are listed in the isolated test inventory. The new
PostgreSQL component is listed in the excluded inventory alongside the existing
real-engine fixtures until a trusted controller explicitly binds its engine,
command, resource limits, coverage and cleanup. A changed-excluded-test failure
must not be bypassed. No prepared coverage or test success is claimed here.

## Still required

- Independent root freshness, revision/count authority and time evidence. A
  supplied root descriptor and its successful reconstruction do not supply them.
- Predicate/range completeness, secondary-index maintenance and full operation
  query coverage. These primary-key proofs do not prove a complete range query.
- The four missing WebAuthn kernels and full source-root startup.
- Runtime acceptance of the [separate SQL wire serializer](authority-wire-json.md).
  Its source repair moves message commitments to ASCII-escaped JSON without
  changing persisted UTF-8 tree hashes. Pure Unicode tree tests establish only
  that distinct tree representation; neither source review nor the unexecuted
  component fixtures establish live wire or full-operation parity.
- The older full-trace/work-accounting limits need integrated coverage; this
  profile does not silently raise them.
- Existing installation transition authorization: changed functions/constraints
  remain structurally pinned. The receipt-table-only repair exception does not
  authorize their replacement. No automatic repair or migration bypass is added.
- Full controlled build/runtime verification, crash/replay acceptance, custody
  receivers, fleet evidence producers, provisioning and production release proof.
  In particular, actual signed planner/consumer execution and service receipt
  rejection paths still need runtime tests; AST wiring is not that evidence.
