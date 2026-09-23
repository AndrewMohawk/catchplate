# Global audit capacity initialization

Status: source-only prerequisites, unbuilt and unexecuted. No admitted offline
initializer, independent checkpoint producer, new installation receipt or
startup acceptance is implemented. Missing global capacity continues to deny
participating operations. Neither this document nor the component observation
is permission to insert zero, sum old scalars or change runtime DML privileges.

## Complete-population component

`serverware/authority_audit_inventory.py` implements
`verify_audit_inventory(root=..., records=...)`. It consumes a stream of exact
`selectedRow` / `proof` pairs and returns an immutable
`serverware.metadataAuditOutboxInventoryObservation/v1` with the supplied root
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

If the independently accepted descriptor says there are N leaves, N distinct
memberships against its one root cover the whole population. Count pending and
claimed as outstanding, audited as terminal, and reject outstanding counts over
the source-owned 100,000 limit. Audited history does not share that live limit.

This proof is conditional: the radix digest does **not** authenticate the
descriptor's leaf count or revision. An untrusted understated count together
with that many valid membership proofs can omit real leaves. Copying a root
from the same database or signing an opaque database-provided digest does not
solve that problem. Root currentness, database generation, schema, writer fence
and independent acceptance must be supplied by the eventual initializer's
separate authority protocol. An empty supplied root with a positive revision
can describe a previously populated table; it is not fresh genesis.

## Offline resource and evidence boundary

The verifier retains one record's owned snapshots/proof state, counters and one
previous key, not the full population. Serialized per-record/evaluator inputs
are limited to 64 MiB, depth 128 and 1,000,000 JSON nodes; each proof has exactly
64 vectors and 1024 child slots. The evaluator accounts a fixed single-proof
hash budget. The serialized cap is not a peak-RSS promise, and envelope overhead
means independent maxima need not fit simultaneously.

The offline job owner must enforce total CPU, byte, memory and elapsed-time
budgets, including a producer stalled between records. A large terminal history
does not become an ordinary online full-table scan. This component neither opens
a database nor changes the online 256-row business ceiling. It has no signing,
wall-clock, writer-exclusion or DML operation.

The new fixture uses an independently built small tree and independent SQL/wire
hash framing. Authored controls cover mixed and empty populations, missing,
duplicate, reordered and extra members, changed full rows/proofs/roots,
historical SQL types, resource/representation rejection, a reused generator
buffer, stream exhaustion and immutable results. Tests deliberately demonstrate
the descriptor-trust limitation. Direct observation-constructor arithmetic
checks the 100,000/100,001 boundary without claiming a 100,000-proof workload.
None of these tests has executed, and they are not migration/concurrency proof.

The phase-2 declaration now references the real global identity and fixed
capacity, exact pending/claimed membership, compact empty maps and no expiry.
It retains `initializerImplemented: false` and `onlineActivationPermitted: false`.
No current population, revision, sequence or receipt is fabricated by that
declaration. The six unrelated backfill declarations remain unchanged.

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

## Required producer/installer integration

The next coherent change must close all of these together before enabling an
initializer or changing accepted schema/migration state:

1. Define a purpose-specific independent checkpoint and installation contract
   binding database generation, source/schema/key contracts, outbox and aggregate
   root descriptors (including cardinality), currentness and all-writer fencing.
   Authenticate the issuer and its evidence, not just a caller-provided digest.
2. Under admitted offline writer exclusion, prove the complete status population
   and the exact global aggregate identity's absence. Compare the observation
   with independently authorized installation evidence. No zero-on-missing
   fallback, old-counter conversion or online INSERT grant is permitted.
3. Explicitly define initial revision, insertion-sequence baseline and timestamp
   semantics. Bind the exact compact row, its state commitment, expected after
   roots, initializer measurement and operation identity. A local clock cannot
   supply independent time authority.
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
