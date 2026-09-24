# Authority transition startup blocker

Status: unresolved implementation gap; control-plane startup remains blocked.
The frozen `f16da11` source-root run of `scripts/test_control_plane_startup.py`
failed while importing `authority_transition_registry`, before service startup.
The diagnostic-only change described here does not make that runtime healthy.

`authority_contract.OPERATION_REGISTRY` declares four typed pure transitions
that have no kernels in the policy, quota, or release registries:

- `webauthn.trust.stage`
- `webauthn.trust.complete`
- `webauthn.registration.finalize`
- `webauthn.credential.revoke`

Their argument and evidence field sets are already reserved in
`serverware/authority_transition_policy.py`, but no complete implementations are
registered. An unregistered explicit self-revocation candidate now exists in
`serverware/authority_transition_webauthn.py`; its deliberately limited source
boundary and outstanding activation requirements are documented in
[webauthn-revocation-candidate.md](webauthn-revocation-candidate.md). It is not a
repair of the legacy aggregate endpoint or any of the other three operations.
The registry now names missing kernels, unexpected
kernels, overlapping registries, and mismatched identity or planning fields.
All prior closure conditions remain enforced. No operation was removed from
the contract, marked disabled, given a placeholder kernel, or delegated back to
legacy mutation code. Changing the database backend cannot repair this
unconditional import-time failure.

The coordinated implementation direction is documented in
[WebAuthn authority integration](webauthn-authority-integration.md), including
aggregate staging, authenticated predicate/capacity proofs, independent roots
and time, and non-circular evidence production. It does not change the current
contract or waive any startup gate.

Source `.74` adds [successor business-transition helpers](webauthn-successor-transitions.md)
for registration, aggregate trust staging and installation-bound completion,
plus actual original-byte evidence signing/verification with independent pins.
They produce ordinary row effects, not registered kernels or proof tokens.
Successor manifest/query/evidence-consumption adapters and independently owned
production composers remain necessary; all four startup gaps remain visible.
Source `.75` connects registration to real source queries, mutation rendering,
complete-range acquisition and shared proof verification. It does not supply
the missing evidence custody, operation owner or registry activation.
Source `.76` adds original-envelope v2 receipt projection and one-use consumption
to registration/completion effects. Registration's private acquisition now joins
actual reads, independently expected primary/counted roots, capacity finalization
and write proofs. These are source integrations, not durable evidence admission
or a configured operation owner; the four registry/startup gaps remain.
Source `.77` supplies aggregate trust staging's actual manifest, complete-query
family and mutation adapter, plus private pinned-assertion/read/effect/capacity/
write-proof acquisition. It preserves whole-aggregate limits and fails query
overflow before business/range SQL. This is not candidate-policy signature admission, a configured
service owner, signed-plan/executor activation or a startup repair.
Source `.78` adds genuine original signed-candidate admission to that stage
acquisition and derives classifier roots from the real verifier. Installation
evidence production and completion now share the original-byte semantic checks.
Neither addition admits durable evidence, supplies the configured operation or
physical-installation owner, registers a kernel or repairs startup.

The [registry-free request commitment](authority-request-commitment.md) separates
the actual hash/intent workers needed by the inactive revocation verifier from
the planner's eager registry import. Its standalone fixtures can describe that
component without a fake registry. Public planner admission and this startup
closure remain unchanged; real import-denial controls do not replace callable
planner or full-startup evidence. The linked coverage transition retains those
integration assertions in the startup-dependent suite.

The [explicit-context attestation core](webauthn-attestation-core.md) prepares
shared registration cryptography for an eventual measured evidence producer.
It does not itself produce signed authority evidence or fill a missing kernel.

The [counted-storage installation](authority-counted-installation.md) now wires
fresh-empty PostgreSQL preparation, exact existing-head checks, schema/ACL
inventories and real primary-trigger maintenance in source `.29`. It remains
unexecuted. Independently admitted roots, shared operation budgets and versioned
retained evidence are still required; this wiring neither enables counted queries
nor registers a missing kernel.

Source `.30` now threads one [query-bookkeeping ledger](authority-query-read-accounting.md)
through actual typed planning and staged reference resolution, including both
final observation validations. This bounds that repeated bookkeeping only;
SQL/proof/kernel and whole-operation accounting remain separate. The complete
query gate, v3 retained-evidence limitations and four startup gaps remain unchanged.

Source `.31` adds a [private complete-acquisition path](authority-complete-acquisition.md)
through actual head/range/exact-row reads, global primary verification and all
five joined ranges on the same work ledger. Public v3 still rejects before
business/proof SQL; even the private acquired state is rejected by the typed
program before its kernel until the successor retained-evidence protocol exists.
No independent current-root/time producer, new wire protocol or registry
activation is supplied by this source-only integration.

Source `.32` adds the inactive [signed revocation-plan v4 verifier](authority-revocation-plan.md)
and closes the source program's trust-authorization reads, including a sixth
complete role for pending-publication absence. It recomputes both signatures,
retained proofs and semantic effects on one budget. Production producer,
persistence, executor and witness activation are still missing; the four
startup gaps and verification prerequisites remain in force.

Source `.33` adds a private single-cutoff revocation read-phase factory and
detached retention of the original roots and genuinely merged primary proofs.
It derives the actual metered source program and internally creates staging
and acquisition, eliminating a separately configured cutoff and discarded proof
inventory. Source `.34` connects genuine request/receipt verification,
single-cutoff reads, actual kernel/capacity effects and write acquisition on
one work and physical ledger, and binds the exact writer trace in signed
replay. The public v3 and pre-kernel successor gates remain closed. At `.34`,
signed-v4 production, durable original-envelope and independent-context persistence,
and coordinated v4 activation remained required; the private raw producer is
not a registered kernel or startup repair.

Source `.35` adds a [private original signed-v4 producer](authority-revocation-production.md)
using actual acquisition, same-work mixed proof packaging and precharged final
transport. Public v3, service/persistence and registry admission remain unchanged.
Producing an original signed envelope does not establish current roots, durable
replay, one-use execution or a terminal witness.

Source `.36` adds [private original-byte admission](authority-revocation-wire.md)
on the same remaining verification work, including strict decoding and comparison
with the actual canonical encoder before signature checks. Source `.37` adds
private [retention storage and replay](authority-revocation-retention.md),
versioned schema/ACL guards and a configured coordinator. These are source
implementations, not installed schema or public service activation. None of the four missing registered kernels is
enabled by these private producer/verification components.

Source `.38` adds the producer's original canonical eighteen-field context
bytes as a fourth output, preserving its first three fields. It checks the
original acquisition cutoff and encodes the same owned context after packaging,
before signing, on existing work (`0H/2L/2N`; 512 KiB, 4,096 nodes, depth 8).
That context-encoding change did not wire the producer to its coordinator or
service; no registered kernel, public execution path or production authority
was enabled.

Source `.39` repairs a concrete private-producer trace-closure defect: it now
performs the real business/authorization root reads after assertion verification,
including the required framework global audit-capacity root read, and binds both
vectors to independent expectations before the one original database-clock
sample. Bounded copies, canonical comparison and the existing framed commitment
use the same remaining work; no synthetic marker or budget expansion is used.
This source correction is unexecuted and does not establish independent root
currentness, transaction ownership, registry admission or public v4 activation.

Source `.40` adds `RevocationPlanningCoordinator`, a configured private owner
that performs actual database identity/manifest checks in a serializable
read-only deferrable scope, threads one real manifest-prefix trace through the
producer, and closes all read scopes before separate original-byte persistence.
Its thirteen caller context fields exclude the configured identities; original
request/root expectations, cutoff and work survive the handoff. Metadata SQL
precedes the genuine receipt check, which still precedes business SQL. Identity
and source-manifest admission are explicitly outside H/B/N. This remains
unexecuted source; no registered kernel, service route or execution authority
is activated.

Source `.41` fills a concrete private-storage prerequisite: v4 persistence now
materializes the executor's immutable assertion-evidence and authorization
projection rows in the same savepoint before completing a reserved parent.
It reuses the actual legacy row recipes, binds exact row/digest identities
and checks current configured-verifier policy for new records. Planned retries
and historical reads require existing rows without repair or reloading the
current verifier key. Retries retain the live deadline/age/skew check;
historical reads remain clock-free.
No table shape, grant or registry admission expands; the existing v3-only SQL
loader and service replay still require coordinated successor consumers.
This is authored, unexecuted custody integration, not four-kernel completion.

Source `.42` adds the private retained-byte SQL integrity binder described in
the [retention contract](authority-revocation-retention.md#private-sql-integrity-binder).
It joins a caller-locked planner record to its immutable sidecar and returns
raw bound observations, not signature/proof success or execution authority.
Independent key/request/context admission, actual Ed25519 and complete-proof
verification, current locked primary/counted roots and writer reservation
remain consumer prerequisites. No v3 executor, reservation, service replay
or registry gate opens; the component and its native controls are unexecuted.

Source `.43` adds a private stored-replay-to-execution-reservation path. Actual
signature and complete semantic verification precede internally constructed
five-field request bytes binding the original typed request, successor protocol,
retained record and root transition. One serializable writer transaction and
savepoint hold the `planned` parent lock through insertion/exact reserved retry;
all reservation columns and NULL terminal fields must match, and live freshness
is required even on retry. Terminal parents/envelopes are denied without repair.
This is API-level custody, not a new database immutable-envelope/FK contract,
current-head validation, capability/fence authority, business commit or terminal
witness. No native inventory, public v3 route, registry or service gate expands;
the source and isolated controls remain unexecuted.

Source `.44` adds [private counted-head before/after fragments](authority-revocation-retention.md#private-counted-head-fresh-apply-fragments)
using the exact source read/actual-write union and real projected OLD/NEW
event deltas. Full source head rows are locked and compared to the exact
compact vectors, including unchanged read-only profiles. The future fresh
executor must already own genuine independently pinned replay and sorted
primary locks before counted locks, preserve one transaction, and keep live
head reads outside historical retry. These fragments do not activate a public
executor, capability, terminal witness or missing kernel, expand schema/ACLs,
or establish a SQL H/B/N or deadlock proof. Component controls remain unexecuted.

The [explicit-context credential classifier](webauthn-credential-trust.md) now
shares the actual enrollment/root/AAGUID/class/development decision with the
live wrapper and both trust-withdrawal passes. Its immutable context does not
prove the queried credential population is complete or the root is current;
no startup kernel or aggregate authority transaction is activated by this work.

The [row-mutation SQL correction](authority-row-mutation-sql.md) addresses
separate executor parameter, absence and identifier defects. Its shared SQL
component fixture does not establish full executor or startup success; existing
installed function definitions still require explicit repair admission.

The [primary-root transition contract](authority-primary-root-transition.md)
binds source-owned primary keys and complete computed before/after root sets
through planner v3, Snapshot/v3 and pre-commit SQL checks. It also replaces
synthetic authorization table-head selectors with actual proof-selected rows.
This source-only component work does not establish independent root authority,
range completeness, Unicode wire interoperability or full startup success.
The separate [wire JSON repair](authority-wire-json.md) now implements the SQL
message serializer and consumer migration without changing persisted tree hashes;
its authored component and original-byte checks remain unexecuted.

The [fresh audit helpers](authority-audit-capacity.md) retain exact INSERT and
replay guards while dropping the old policy/quota counter paths. The common
planner, payload admission and executor now use the [global capacity contract](authority-global-audit-capacity-design.md),
with separate business/framework budgets and source `.27`/primary-root profile
v2. This remains unexecuted source: authenticated initialization and general
receipt-bound PostgreSQL delivery are missing, and SQLite remains separate.
The offline [inventory v2 component](authority-audit-initialization.md) now
reconstructs the complete root from enumerated leaves, removing reliance on a
supplied count for completeness. Independent root currentness, writer exclusion
and authenticated counter installation remain missing.
The offline preparation now calculates the exact compact initial row and
prospective root transition from that inventory and aggregate-key absence.
It does not install the row or provide independent initialization authority.
The [signed evidence consumer](authority-audit-initialization-evidence.md) now
verifies pinned checkpoint/authorization claims and internally recomputes the
preparation. It remains non-actionable: external producers/context provisioning,
physical writer exclusion, one-use ancestry and atomic installation are absent.
This source-only component does not remove any startup blocker.

The [table-permission closure](authority-table-permissions.md) additionally
corrects twelve missing runtime read-only relations and detailed table schemas.
Source `.26` binds these inventories and adds effective table/column privilege
checks on runtime connections. This is source-only, not native ACL admission.

The [canonical schema-source correction](authority-schema-source.md) separates
complete comparison DDL from extension-only migration execution, restricts
receipt repair to one exact historical table variant, and requires fresh
migration source comparison before signing. Structural capture now checks the
configured NOLOGIN authority owner rather than the bootstrap session login.
The full program and owner contract enter the source digest; old recorded
digests are not automatically upgraded. All of this remains unexecuted.

The [verifier read-permission correction](authority-verifier-read-permissions.md)
binds the current four-table WebAuthn read set, dedicated verifier role and shared
effective-privilege query through all four installation paths and live evidence
reads. Source `.27` rejects older permission/profile contracts. This is not native
role/mTLS proof or completion of the missing WebAuthn kernels.

## Implementation contracts still needed

The following bounds are the existing contract, not permission to truncate a
larger mutation or omit dependent rows. If complete evidence cannot fit the
declared bound, admission must fail closed. Changing these bounds or the
transaction composition requires an explicit contract design and review.

| Operation | Existing row / mutation / work bounds | Missing typed inputs and preserved behavior |
| --- | --- | --- |
| `webauthn.trust.stage` | 4 / 1 / 64 | Exact bundle, predecessor, sequence, rollback epoch, signer, actor, withdrawal IDs, and audit event. Preserve digest-reuse checks, single pending publication, monotonicity, and publication/withdrawal atomicity. |
| `webauthn.trust.complete` | 5 / 5 / 130 | Original business bounds 4 / 4 / 128 plus exact global accounting. `publication_id` plus `verification_evidence_digest`. Bind a durably verified signed publication receipt to the stored bundle and signer; consume it atomically with publication, witness/high-water advancement, and the audit record. |
| `webauthn.registration.finalize` | 113 / 41 / 1026 | Original business bounds 112 / 40 / 1024 plus exact global accounting. In addition to legacy registration arguments: `challenge_id`, `attestation_evidence_digest`, `oidc_session_id`, `sibling_challenge_ids`. Bind fresh registration attestation and trust generation, exact unexpired unused challenge, user and label; preserve credential-ID non-reuse, pending OIDC session authorization, zero historical credentials for first enrollment, sibling invalidation, and audit. |
| `webauthn.credential.revoke` | 193 / 137 / 2050 | Original business bounds 192 / 136 / 2048 plus exact global accounting. In addition to legacy revocation arguments: `approval_grant_ids`, `control_plane_approval_ids`, `oidc_session_ids`, `registration_challenge_ids`. Preserve the bound verified assertion and atomic credential/session/grant/approval revocation, explicit-source global live-registration invalidation, and per-approval audit events. |

Exact implementation references:

- `serverware/authority_contract.py`: four operation declarations; proof
  primitives, evidence types, relation permissions, and bounds are authoritative.
- `serverware/authority_transition_policy.py`:
  `_WEBAUTHN_TRUST_STAGE_FIELDS`, `_WEBAUTHN_TRUST_COMPLETE_FIELDS`,
  `_WEBAUTHN_TRUST_VERIFICATION_FIELDS`,
  `_WEBAUTHN_REGISTRATION_FINALIZE_FIELDS`,
  `_WEBAUTHN_REGISTRATION_VERIFICATION_FIELDS`, `_WEBAUTHN_REVOKE_FIELDS`,
  `_WEBAUTHN_EXACT_CASCADE_MAX`, and `_KERNEL_VALUES`.
- `serverware/db.py`: `stage_webauthn_trust_publication`,
  `complete_webauthn_trust_publication`, `finalize_webauthn_registration`,
  `revoke_webauthn_credential`, and
  `_invalidate_live_webauthn_registration_challenges` document legacy behavior.
  They are not implementations of the typed authority protocol.

## Why registering the legacy functions is not a repair

`authority_store/authority_dispatch.py` binds the original database handler
signature, rejects injected `_connection` and other internal arguments, and
marshals the remaining arguments. `authority_service._synthesize_business_arguments`
adds `businessIntent`; it does not discover challenge IDs, cascade rows, or
produce verification receipts. Merely adding kernel objects would leave these
new inputs absent, or incorrectly trust caller-selected subsets.

The trust-publication API currently performs dependent credential withdrawals,
global live-registration challenge invalidation, and publication staging inside
one `db.connect()` transaction in `app.py:webauthn_trust_publish`. Its staging
handler requires `_connection`; the controlled-writer wrapper rejects that
argument. The stage contract permits only a publication-row mutation, not all
those dependent withdrawals. A reviewed admission/transaction design must
preserve the aggregate atomicity; it cannot be replaced with independent
commits to get past startup.

The legacy completion handler takes only a publication ID.
`webauthn_trust.reconcile_trust_publications` verifies and installs the bundle
locally, then passes that ID. It does not create the typed
`webauthn-trust-publication-verification/v1` receipt. Likewise, the reserved
registration contract requires a `webauthn-registration-attestation/v1`
receipt; no operation-specific producer or admission adapter for that type is
present in the reviewed source. Local verification results and caller-supplied
JSON must not be promoted into signed external evidence.

The [explicit trust verification and local installation path](webauthn-trust-installation.md)
now uses one captured key/schema/time context, validates roots before checkpoint
writes and requires exact durable-write/readback ordering, including ambiguous
state-directory retry. Its unsigned local observation is not that missing
publication-verification receipt; the legacy completion call remains ID-only.

The existing `authority_transition_core.KernelContext` receipt machinery
validates evidence type, binding, canonical statement and signature digests,
verifier identity/measurement/attestation, current source revision, validity
window, and one-time consumption state. Those structural/commitment checks
assume prior authenticated admission; they do not themselves verify an Ed25519
signature against independent purpose-specific identity pins. The trust
installation admission producer remains missing. New producers and kernels must agree
on the complete authenticated binding and use those checks. The unused field
sets alone do not establish a producer protocol.

For finalization and revocation, legacy SQL derives complete sets inside a
transaction. New bounded queries need ordered exact-page/completeness proofs,
not only existence checks for a caller-provided list. In particular, revocation
invalidates all live registration challenges for `source="explicit"`, not
merely those for the revoked credential's user. It also emits one audit record
per invalidated control-plane approval. The existing 32-item cascade hint and
136-mutation contract must be reconciled with those audit costs; silent
truncation or dropping audits is not acceptable.

## Locked trust projection repair

The v9 executor's trust query previously referenced publication columns that
exist only in the high-water table. The shared
`authority_store/webauthn_trust_sql.py` projection joins one published row to its
locked high-water record by rollback epoch, sequence, bundle/publication digest
and payload/metadata digest. Witness and revocation fields come from that same
high-water row and remain inputs to the existing signed-evidence digest check.
High-water-first locking and both row locks are retained.

`scripts/test_webauthn_trust_projection_postgres.py` executes that exact block
against the actual two table declarations in a disposable PostgreSQL database.
The prepared external runner owns engine startup/shutdown; the script accepts
only a local Unix socket and creates/drops one random test schema. It checks
projection, missing/mismatched rows, cross-row mixing and lock contention. This
is not a full v9 dispatcher/planner/witness/executor or migration test, nor proof
of independently authenticated database state.

The rendered query remains part of the exact installed-function definition
checked by the schema manifest. Existing v9 databases with the old function
definition remain fail-closed and require a separately reviewed repair contract;
the code change does not authorize silently replacing their functions. It also
does not supply any missing kernel or remove the startup blocker.

The active executor's credential-policy expression also now includes `aaguid`,
matching the exact sixteen-field shared Python policy. It is a fixed zero-argument
renderer in the same registry-free SQL module, used inside the unchanged
wire/domain digest comparison. JSON null and string values retain their types;
missing or malformed row values are not admitted merely because this expression
can render them. The actual executor still locks and compares the complete
`expectedRow` before any mutation. Four added native component cases compare
the production expression, wire serializer and domain digest against independent
and Python policies, including an AAGUID-only stale-claim negative control.
They do not execute the full executor or prove CAS. The original eight fixture
methods remain, and all twelve are authored and unexecuted. The existing-database
repair requirement above applies to this function-definition change as well.

## Authenticated storage prerequisites

### Persisted PostgreSQL trigger modes

Both per-table and schema-wide structural trigger inventories commit the exact
`pg_trigger.tgenabled` code as `enabledMode`. `O`, `A`, `R`, and `D` remain
distinct; missing or unknown codes are rejected, never defaulted. Source-created
ordinary triggers use `O`, so all other modes differ from that exact expected
manifest even when their definitions are unchanged. SQLite inventories are
unchanged. Existing v9 manifest records lacking this field require a separately
reviewed repair contract; there is no automatic rewrite or startup bypass.

`scripts/test_postgres_trigger_manifest.py` exercises the same native catalog
readers and production definition normalization in an externally prepared,
disposable Unix-socket cluster. It checks mode-only drift, unchanged definitions,
namespace isolation, ordinary enablement restoration and legacy/malformed mode
controls. This is component coverage, not full schema admission or startup.
Stored mode `O` alone does not prove firing under another
`session_replication_role`, independent database authority, or predicate
completeness; those enforcement requirements remain separate.

Source review identified additional prerequisites below the missing kernels.
These are separate from provisioning the production services:

- Business-row identity and authenticated-tree addressing use different digest
  domains. `db.py`'s `serverware_policy_authority_authenticated_apply` stores
  leaves under `serverware.policyAuthorityAuthenticatedKey/v1`; transport and
  mutation plans identify rows with `serverware.policyAuthorityBusinessKey/v1`.
  Proof production and reconstruction must derive the former from the exact
  table/key while preserving the latter in the closed transport schema. They
  cannot use the business digest as a database leaf lookup or radix path.
  The SQL tree additionally length-prefixes the digest domain; the business
  transport prefixes the domain followed by a NUL byte. Empty, key, row, leaf
  and node hashes must match the SQL framing exactly without silently changing
  persisted roots or the transport protocol.
- The narrow tree-proof repair supports losslessly decoded strings, integers,
  booleans, null, lists and objects, with UTF-8 tree serialization; it rejects
  floats and decimal values instead of approximating PostgreSQL numeric scale.
  The separate SQL wire serializer now targets ASCII-escaped Python message
  commitments, with original request/result bytes checked rather than replaced.
  Its lossless-integer profile is not general float parity. The complete stored
  plan remains bound to its original bytes; tree-only Unicode fixtures and
  unexecuted wire components do not prove end-to-end executor compatibility.
- `BoundedQuery.exact_page` is not enforced by the current SQL reader.
  `KernelContext.exact_page_receipt` checks receipt structure and digests, but
  does not reconstruct a predicate/range root from its `proofNodes`. There is
  no complete, maintained secondary-index producer/consumer path. A receipt
  with internally consistent hashes is not proof that matching rows were not
  omitted. The candidate remains unregistered for this reason.
  The separate [counted-index interval reconstructor](authority-index-range.md)
  now implements the bounded hash/count frontier calculation as unexecuted
  source. The [fixed-projection primary join](authority-index-primary-join.md)
  adds eleven selector codecs and actual row-proof correspondence relative to
  a supplied root pair. Neither component is wired into that reader or receipt
  path; maintained storage and independent root-pair authority remain missing.
  No existing exact-page metadata is newly trusted by this work.
  [Query retention and pre-kernel verification](authority-query-read-retention.md)
  now preserve per-query observations and verify primary membership before the
  transition. These public v3 paths do not provide range evidence, maintained indexes or a
  closed signed snapshot protocol for those observations.
  The typed reader also [stages referenced-row proofs](authority-query-proof-staging.md)
  before their fields drive dependent SQL. This relative membership check does
  not add independent currentness, completeness or a missing WebAuthn kernel.
  Source `.28` adds [distinct complete-index query declarations](authority-complete-query-contract.md)
  for explicit revocation, committed by the operation/handler manifests. The
  public v3 planner reader rejects them before business/proof SQL. The
  [.34 private acquisition path](authority-complete-acquisition.md) now composes
  genuine range/member and write proofs without changing that public gate.
  A standalone bounded
  SQL reader now acquires inside leaves and canonical outside-prefix nodes,
  checks primary lookup commitments and performs real range reconstruction
  relative to a supplied root. It does not admit current heads, perform the
  primary-row join or activate the planner. [Storage, all-writer maintenance and bootstrap](authority-index-storage-integration.md)
  remain requirements, not installed capabilities; this source is unexecuted.
  The [all-profile mutation evaluator](authority-index-mutation.md) now derives
  genuine counted before/after roots from the same verified primary OLD/NEW
  images. It fixes component revision and budget semantics, but does not install
  writer maintenance or admit a versioned counted-root transition.
- The planner reads root revisions and digests from PostgreSQL; the executor
  locks and compares those database roots. This establishes a same-database
  compare-and-swap boundary, not an independently retained current-root
  checkpoint against malicious database rollback or substitution. The current
  external witness binds operation, request, capability, result and generation,
  but does not advance the executor's before/after root set or commit receipt.
  An authenticated root transition and independent monotonic checkpoint must
  be integrated before claiming that stronger database threat boundary.
- The [bounded primary read producer](authority-primary-read-batching.md) now
  shares business/authorization child lookups in groups of at most sixteen
  parents, retaining the global counter's exact singleton 65-read trace block.
  Its source acquisition bound is at most five physical reads per non-counter
  selection, without lifting the 4096-entry business ceiling or discounting
  full proof-evaluation work. This source-only repair does not establish full
  planner/operation capacity, maintained ordered indices or predicate
  completeness. Those boundaries still require integration and verification.

Focused proof tests must distinguish an independent expected-root pin from a
root supplied by the same database. Neither an in-memory tree fixture nor a
passing PostgreSQL transaction test establishes the independent witness
property. Keep those evidence scopes separate during subsequent integration.

## Verification after implementation preparation and freeze

Run these sequentially using the prepared Python runtime; do not build from
either test:

1. `python3 scripts/test_authority_transition_registry.py` checks the guard with
   synthetic metadata only: the exact partition, missing/extra/overlapping
   entries, operation/handler/program identity, strict boolean empty-mutation
   policy, and challenge/disabled planning modes. It cannot prove real kernel
   availability or execution.
2. `python3 scripts/test_control_plane_startup.py` remains the source-root
   integration gate. With only this diagnostic change it is expected to fail,
   now naming the four missing kernels. That failure must remain visible.
3. Before treating eventual kernel implementations as complete, add operation
   fixtures for success, idempotent replay, conflicting replay, stale trust and
   predecessor, expired/consumed/wrong-binding evidence, duplicate credential
   history, expired or cross-user OIDC authorization, omitted cascade rows,
   overflow, concurrent row changes, exact audit counts, and full rollback on
   any failed dependency. Then prove the real dispatcher/producer/planner/
   witness/executor path, not just isolated kernel output.

The diagnostic and its unit fixtures do not authorize production authority
deployment, relax the custody boundary, or establish development proxy health.
