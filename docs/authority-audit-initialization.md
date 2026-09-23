# Global audit capacity initialization

Status: source-only prerequisites, unbuilt and unexecuted. No admitted offline
initializer, independent checkpoint producer, new installation receipt or
startup acceptance is implemented. Missing global capacity continues to deny
participating operations. Neither this document nor the component observation
is permission to insert zero, sum old scalars or change runtime DML privileges.

The initializer trace also identified and corrected a source [table-permission
inventory omission](authority-table-permissions.md). Source `.26` protects the
ten primitive and two contract tables from ordinary runtime writes and includes
their detailed schemas. This unexecuted correction is a prerequisite, not an
offline initializer or an installed permission proof.

## Complete-population component

`serverware/authority_audit_inventory.py` implements
`verify_audit_inventory(root=..., records=...)`. It consumes a stream of exact
`selectedRow` / `proof` pairs and returns an immutable
`serverware.metadataAuditOutboxInventoryObservation/v2` with the supplied root
descriptor, source revision, three status counts and derived outstanding count.
The observation has a domain-separated digest, not a signature or authority bit.
Direct construction of its dataclass checks consistency only, not proof validity.

Every selected row must be present, have a null contract selector and carry all
15 source outbox columns. Representation checks reject NUL, unpaired surrogates,
floats and non-JSON values before copying. The source primary-key contract is
`id`; exact SQL text/null/signed-BIGINT shapes and the three status names are
required, along with canonical event-digest spelling. Historical text IDs,
including Unicode, empty strings and IDs longer than today's fresh-event limit,
remain supported within the per-record bound. These checks do not authenticate
event contents, claim ownership, timestamps or ledger delivery receipts.

For each bounded owned snapshot, the component uses the existing primary-radix
evaluator with no mutations to verify the full-row proof and unchanged supplied
root. That same snapshot supplies both ordering and status counts. Records must
be strictly ascending by the persisted `AuthenticatedKey/v1` digest, not SQL ID
order or `BusinessKey/v1` transport digest. Retaining only the previous digest
establishes uniqueness under collision resistance. The stream must end at
exactly the descriptor's leaf count; an extra record is rejected before copying
or hashing it, and an interrupted or short stream never returns an observation.

After each membership proof is validated, its recomputed leaf enters a separate
streaming frontier. The frontier reconstructs the **entire** sparse radix tree
using only those enumerated leaves and canonical empty children. It never uses
the supplied proof's opaque sibling hashes as populated subtrees. On iterator
exhaustion, close every remaining prefix and require the resulting root digest
to match the supplied root. An understated count plus a valid prefix, suffix or
interior subset can no longer pass: the omitted nonempty branches change this
reconstructed root under collision resistance.

Thus v2 derives cardinality from the complete enumerated population relative to
that root digest, while retaining the descriptor-count consistency check. The
old v1 relied on an independently authenticated count and cannot substitute for
this stronger observation. Count pending and claimed as outstanding, audited as
terminal, and reject outstanding counts over the source-owned 100,000 limit.
Audited history does not share that live limit.

This still does not authenticate which root is authoritative. A different or
stale root and its complete population can be internally valid. Root revision,
currentness, database generation, schema, writer fence and independent acceptance
must be supplied by the eventual initializer's separate authority protocol.
An empty supplied root with a positive revision can describe a previously
populated table; it is not fresh genesis. The observed statuses also remain
distinct from cryptographic proof of their ledger-delivery semantics.

## Offline resource and evidence boundary

The verifier retains one record's owned snapshots/proof state, counters, one
previous 64-nibble key, a fixed frontier of 64 sixteen-child vectors and 65 empty
digests, not the full population. Serialized per-record/evaluator inputs
are limited to 64 MiB, depth 128 and 1,000,000 JSON nodes; each proof has exactly
64 vectors and 1024 child slots. The evaluator accounts a fixed single-proof
hash budget. Full-root reconstruction additionally hashes each occupied prefix
once: at most 64 internal-node hashes per member plus 65 hashes to construct the
empty ladder. No online evaluator budget is increased or charged as a substitute
for this separate offline work. The serialized cap is not a peak-RSS promise,
and envelope overhead means independent maxima need not fit simultaneously.

The offline job owner must enforce total CPU, byte, memory and elapsed-time
budgets, including a producer stalled between records. A large terminal history
does not become an ordinary online full-table scan. This component neither opens
a database nor changes the online 256-row business ceiling. It has no signing,
wall-clock, writer-exclusion or DML operation.

The new fixture uses an independently built small tree and independent SQL/wire
hash framing. Authored controls cover mixed and empty populations, missing,
duplicate, reordered and extra members, changed full rows/proofs/roots,
historical SQL types, resource/representation rejection, a reused generator
buffer, stream exhaustion and immutable results. Updated controls reject all
nonempty omitted subsets of the small independent tree even when their claimed
count matches, and retain the unauthenticated revision/currentness boundary.
Separate deterministic frontier controls exercise deep shared prefixes and
radix carries against an independently reconstructed tree; arbitrary synthetic
leaf inputs there are not membership or admission evidence.
Direct observation-constructor arithmetic
checks the 100,000/100,001 boundary without claiming a 100,000-proof workload.
None of these tests has executed, and they are not migration/concurrency proof.

The phase-2 declaration now references the real global identity and fixed
capacity, exact pending/claimed membership, compact empty maps and no expiry.
It retains `initializerImplemented: false` and `onlineActivationPermitted: false`.
No current population, revision, sequence or receipt is fabricated by that
declaration. The six unrelated backfill declarations remain unchanged.

## Deterministic offline preparation

`authority_audit_initialization.prepare_audit_capacity_initialization` now
composes the real v2 inventory verifier, exact global-key nonmembership and the
real primary-radix mutation evaluator. It returns immutable canonical ASCII
bytes under `serverware.metadataAuditCapacityInitializationPreparation/v1`.
This is a calculation relative to supplied roots, not a signed checkpoint,
installation receipt, admitted runtime plan or database initializer.

Inputs are the complete outbox proof stream, both exact root descriptors, one
aggregate `selectedRow` / `proof` pair and an explicit nonnegative signed-int64
`initialized_at_epoch_ns`. The function does not accept a caller-constructed
inventory observation as proof. It takes an owned bounded copy of the absence
record before consuming the stream, and requires the exact global aggregate
key, `present: false`, explicit null row and null selector. Existing rows,
crossed keys/roots/proofs and successor revision/count overflow fail closed.
Interrupted or incomplete streams return no preparation.

The source-owned initialization profile fixes:

- Counter revision `1` and next sequence `0`. Sequence means fresh pending
  INSERTs after this new global counter's initialization, not lifetime audit
  history, retained row count, outstanding count or an obsolete counter value.
- Live and active counts equal to the internally verified pending-plus-claimed
  inventory; capacity stays exactly 100,000. Retained audited history does not
  seed the sequence or consume live capacity.
- Exact compact empty maps, no expiry/work page, the source empty-expiry digest
  and current source revision. The explicit input timestamp is retained and
  committed as data, not sampled from a clock or authenticated as current time.
  Zero is permitted as an explicit input, not silently substituted.

The one prospective INSERT uses a distinct offline calculation label, never an
online operation's template ID. The ordinary aggregate mutation inventory
remains UPDATE-only. A writable mathematical table contract lets the pure tree
evaluator calculate this single after image; it grants no SQL permission.
The result retains the unchanged outbox root and the predicted aggregate root.
The aggregate revision and leaf count advance by one, but **one absence proof
does not authenticate aggregate cardinality or revision**. For a nonempty
aggregate root, a false supplied count can still produce correct root-hash
arithmetic with a false after count. Independent descriptor acceptance or
separate aggregate-population evidence remains mandatory.

The preparation commits the source/key table contracts, inventory and its
digest, full absence record, exact 17-field row, prospective mutation, both
before/after roots and evaluator metrics. A separate full-row digest includes
timestamp and source revision; the existing aggregate `state_digest` intentionally
does not. Its `installationPermitted` field is always literal false. The frozen
result class checks only its bounded canonical outer envelope on direct
construction, not nested proof validity. Neither its class identity nor its
self-digest can replace rerunning the actual preparation and authenticating
its independent authority inputs.

The single-INSERT evaluator retains one selected row/proof/mutation, 64 proof
vectors, 1024 child slots and the fixed 202-hash allowance, in addition to the
separate full-inventory work described above. Per-record and final-document
serialization is bounded to 64 MiB, depth 128 and one million JSON nodes; these
are not peak-RSS or total-job limits. The preparation performs no database or
filesystem writes, signatures, receipt consumption or source-registry changes.
Exact absence also describes a previously deleted counter: one-use generation
and installation ancestry must prevent unauthorized reset/rebootstrap.

Authored component tests compare the complete preparation and after-root with
independent tree/row/hash fixtures and feed its initial row into the existing
online capacity finalizer. They do not establish SQL installation, all-writer
fencing, independently accepted roots or successful migration. They remain
unexecuted under the unchanged `goal.md` workflow.

## Purpose-specific signature consumer

The [signed initialization evidence component](authority-audit-initialization-evidence.md)
now authenticates a pinned checkpoint and separate authorization, compares
independently supplied expected facts and explicit validity windows, internally
reruns the real preparation, and checks its exact row and after-root commitments.
Its immutable result is non-actionable and always has `installationPermitted:
false`. Direct construction of that result is representation-only, not proof.

This closes the local signature/binding/recomputation boundary only. Independent
trust provisioning, measured checkpoint production, actual writer exclusion,
currentness, one-use ancestry and atomic installation remain missing. The
signed aggregate count still relies on the checkpoint producer's independent
evidence. Neither valid signatures nor distinct keys prove those physical or
stateful claims. The source and real-signature fixtures remain unexecuted.

## Existing migration contracts are not initialization authority

Keep these two mechanisms distinct:

- `db._policy_candidate_authority_outbox_root` commits event identities, event
  bytes and total count, but omits status. It cannot authenticate membership in
  the pending/claimed population.
- `scripts/authority/migrate_v8_to_v9._row_manifest` streams full rows, including
  status, under serializable isolation and table-exclusive locks. Its counts,
  discovered keys and row population still come from PostgreSQL; it does not
  join an independently accepted current root and cardinality. Its new-table
  closure explicitly requires bounded aggregate states to remain empty.

The existing root installer rejects populated tables lacking authenticated
roots and calls for a signed offline restage. The one credential replay seed is
not a general restager. Current migration receipts and completed-v9 retry
handling must keep their historical interpretation; they cannot silently add a
new scalar or become proof of a newly authenticated population.

The [canonical schema-source correction](authority-schema-source.md) now supplies
complete comparison DDL to retry/repair, validates fresh migration against source
before signing and checks configured authority ownership after ACL sealing.
Those unexecuted source changes do not populate the global audit counter or
supply independent current-root authority. Likewise, the v2 inventory verifier
is not yet invoked by an admitted migration or initializer; its strengthened
completeness check does not authorize a database change. No database schema, runtime
source revision, registry, online limit or phase-2 activation flag changes here.

## Required producer/installer integration

The next coherent change must close all of these together before enabling an
initializer or changing accepted schema/migration state:

1. Produce and independently admit the purpose-specific checkpoint, and finish
   its installation contract binding database generation, source/schema/key
   contracts, outbox and aggregate
   root descriptors (including cardinality), currentness and all-writer fencing.
   Authenticate the issuer and its evidence, not just a caller-provided digest.
   The outbox's cardinality can now be rederived by the v2 complete inventory;
   the aggregate root still needs its own accepted count/mapping evidence.
2. Under admitted offline writer exclusion, prove the complete status population
   and the exact global aggregate identity's absence. Compare the observation
   with independently authorized installation evidence. No zero-on-missing
   fallback, old-counter conversion or online INSERT grant is permitted.
3. Admit the exact versioned preparation policy above (or a separately reviewed
   successor). Bind its compact full row, expected after roots and timestamp to
   the independently authorized initializer measurement, operation identity and
   one-use generation/installation ancestry. A local clock or prepared document
   cannot supply independent time or reinitialization authority.
4. Install the exact row and authenticated tree changes atomically with receipt
   consumption; compare actual after roots and readback before completion.
   Specify one-use replay, conflicting state, crash/retry and rollback behavior.
5. Close producer registry, receipt admission, startup checks and source/import
   manifests. Fresh empty, populated v8-to-v9 and existing-v9 upgrades each need
   their explicit admitted path. Fresh zero requires accepted empty genesis;
   a historical completed-migration receipt is not a new backfill authorization.

Then verify omitted/changed populations, crossed/stale checkpoints, writer
exclusion, exact capacity, pre-existing conflicting rows, interruption at each
commit boundary, rollback and exact retry using the prescribed controlled lane.
General receipt-bound PostgreSQL delivery and the other project gates remain
separately required. Finish implementation before preparation or tests, as
required by `goal.md`.
