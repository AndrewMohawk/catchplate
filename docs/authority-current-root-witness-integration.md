# Independent current-root witness integration

Status: source-backed integration design, not an implemented or provisioned
current-root authority. This document assigns no new wire schema, role, key,
endpoint, enrollment or permission. Existing replay-witness purposes remain
unchanged. Source components and authored fixtures are unbuilt and unexecuted.

The purpose is to make a future Snapshot/v4 bind independently admitted primary
and counted roots, without treating a restored database, signed historical
receipt or caller-supplied root as current authority. The
[counted storage contract](authority-index-storage-integration.md) and
[combined mutation component](authority-index-mutation.md) supply separate
storage/calculation prerequisites, not that authority.

## What the existing witness actually binds

[`authority_witness.py`](../serverware/authority_witness.py), especially
`_validate_request`, `_accept_stored_receipt` and `transition_bytes`, implements
the closed replay-witness request/receipt v2 protocol. Its signed receipts bind
operation, request, capability, result, generation, fence and receipt-log
ancestry. `headDigest` is a witness-log commitment, not a database root vector.
There is no database enrollment, complete primary/counted vector, writer receipt
or authority snapshot in that protocol.

[`authority_service.py`](../serverware/authority_service.py) checks the executor's
writer receipt before `_execute_v9_operation` calls `_witness_transition` with
`commit` or `reconcile`. That terminal request carries `resultDigest`, not the
checked writer receipt, snapshot or before/after roots. Persisting its response
in `policy_authority_external_witness_receipts` does not add those bindings or
independent rollback resistance.

[`executor_v9.py`](../serverware/authority_store/executor_v9.py) constructs
`policyAuthorityWriterCommitReceipt/v2` inside SQL. It binds Snapshot/v3 and
operation-scoped primary before/after roots, but is DB-computed unsigned JSON;
its self-digest is not an independently authenticated completion statement.
`AuthorityService._handle_execute` is the concrete postcommit seam: the real
SERIALIZABLE transaction context exits before the receipt is returned. A future
purpose-bound completion attestation must distinguish that successful boundary
from receipt construction inside the transaction or an unknown COMMIT outcome.

The existing witness configuration authenticates a generation and a startup
`minimumSequence`/`minimumReceiptDigest`. Its validated contiguous local journal
must meet that floor. A valid older journal prefix that still meets the floor
can require independent rollback detection: a minimum is not the latest acknowledged head.
The generation's artifact `externalHighWater` is not database-vector enrollment.

## Independent enrollment and complete vector

Enrollment must be supplied and retained outside the examined database's
rollback domain. Bind a stable database identity and enrollment digest, accepted
generation/predecessor ancestry, exact source/schema/root-inventory/projection
manifests, authorized computation and completion identities/measurements, trust
policy, and the initial independently retained vector/head. A DSN, current SQL
OID, request nonce, missing receipt or missing local journal cannot create a new
enrollment. Initial empty state needs admitted complete absence evidence;
populated state needs the bidirectional authenticated restage described by the
storage contract. Neither is established by a fixture's explicit seed.

The primary vector must cover the complete source-owned business/authorization
table union, not only the current operation's selected roots. Each descriptor
binds table identity, revision, digest and leaf count under its fixed primary
profile/key contract. Operation-local business/authorization classifications
are views of that enrolled inventory, not permission to drop other tables.

The counted vector must bind all eleven current source profiles: index/table
identity, counted profile, projection and projection-manifest commitments,
revision, root digest and count. Every written table requires all of its fixed
profiles, even when its row images are nonmembers. Queried-but-unwritten roots
and all other enrolled roots remain unchanged. Source/profile inventory changes
require explicit generation/restage admission, not absent-head defaults.

The current counted write-effects document is not this complete vector: it
intentionally omits query-only heads and complete-query evidence. All primary
and counted roots must refer to the same admitted checkpoint. Necessary count
relationships or a matching same-database pair do not establish population,
currentness or independent enrollment. The separate
[retained revocation bundle](authority-revocation-proof-bundle.md) now commits
the full operation-local read/write union and raw evidence, but supplies no
independent currentness or complete enrolled database vector. Its secret-bearing
raw contents remain inside the semantic boundary, not in a witness request.

## Minimum requests, durable state and receipts

The following are contract requirements, not registered message types:

| Purpose | Minimum binding |
| --- | --- |
| Fresh currentness | Enrollment and accepted generation, caller challenge, intended context, exact service head sequence/digest, complete vector commitment, pending status and independently checked validity. |
| Pending transition | Exact predecessor head/vector, unique operation/request/capability, monotonic fence, Snapshot/v4, intended after-vector and bounded authenticated computation assurance. |
| Completion | Exact pending identity/fence, retained original writer receipt bytes/digest, snapshot, before/after vectors, result and purpose-bound postcommit assurance from an enrolled producer. |
| Durable record | Exact canonical request/response bytes and signatures, enrollment/generation, predecessor and sequence, vector/pending state and consumed transition identities. |

All inventories, canonical envelopes, retained records, proof work and historical
lookups need source-fixed limits and rejection of duplicate/unknown fields and
identities. Reserve completion/recovery capacity before admission. The existing
4-MiB witness message and 16-MiB journal-record limits are not permission to
enlarge a protocol or bypass the outer plan budget.

Keep secret-bearing selected rows inside the admitted semantic execution
boundary. The independent service needs commitments, bounded proof evidence
and exact attested computation assurance naming a trusted producer/measurement;
an opaque snapshot digest is insufficient. Do not export credential material or
arbitrary selected-row JSON to make the witness recompute it.

Fresh challenge binding prevents a retained old response from being accepted
as the answer to a new currentness request. A response describes a serialized
service observation; it is not an indefinite lease on that head. Subsequent
authorization needs the matching reservation/CAS or a defined final-use fence.
Cross-host validity cannot compare independent machines' monotonic clocks; the
existing local Unix peer/deadline assumptions need their own admitted transport
and time contract, not reuse as an off-host guarantee.

## Pending state closes the commit gap

The smallest conservative design serializes one pending transition per enrolled
database. More concurrency requires a separately proved partition/merge model.

1. Admit computation against the independently current predecessor and exact
   complete before-vector. Durably anchor the intended transition and fence
   before authorizing SQL. While pending, deny new currentness authority and
   competing writers for that enrollment.
2. Executor admission consumes that exact fence, locks and checks actual before
   roots, performs all maintained mutations, compares actual after roots and
   records the protected framework marker below in the same transaction.
3. After a confirmed commit, an enrolled completion producer authenticates the
   original receipt and exact pending/snapshot/vector association. The root
   service advances its independent head/vector durably before acknowledging
   completion or issuing further currentness authority.
4. Exact retry returns the original historical decision/receipt without
   repeating SQL, granting another fence or relabelling history as current.

A postcommit-only witness append leaves a gap: a commit followed by rollback of
the database before external advancement could become invisible. The durable
pending state must survive that uncertainty. Timeout is not proof of abort;
absence of a local marker or the reappearance of the before-root cannot
distinguish noncommit from rollback after an unacknowledged commit. Retain the
pending fence and deny until purpose-bound recovery resolves the same decision.
No automatic SQL re-execution, reset, expired-reservation release or absence-based genesis
is sufficient. If externally completed state has a missing/divergent local
marker or vector, report rollback/divergence rather than rematerializing it.

Generation handover must preserve current heads, consumed decisions and pending
work, or deny activation until separately authorized recovery. Request-selected
new generations and unknown ancestry cannot reset any of those facts.

## Acyclic, protected untracked framework marker

A primary-tracked marker containing the pending digest would be circular:

`pending decision -> expected after-vector -> marker row -> pending decision`

The source already has a deliberate framework custody boundary:

- [`authority_contract.py`](../serverware/authority_contract.py),
  `_FRAMEWORK_CUSTODY_TABLES`, includes `policy_authority_consumed_envelopes`,
  `policy_authority_writer_receipts`, `policy_authority_external_witness_receipts`,
  execution envelopes, capabilities and planner transactions. `_spec` rejects
  framework tables in declared business reads/writes before deriving the
  authorization classification.
- [`authority_primary_contract.py`](../serverware/authority_primary_contract.py)
  derives query and authorization manifests solely from those source classes.
  [`db.py`](../serverware/db.py) aliases operation write tables to business
  writes; `tracked_authenticated_tables` is the query/authorization/business-write
  union, and its actual trigger loop uses that union.
- [`schema.py`](../serverware/authority_store/schema.py) commits
  `frameworkCustodyExcludedFromBusinessRoots: true` in the source contract.
  [`metadata_schema_source.py`](../serverware/authority_store/metadata_schema_source.py)
  contains the existing consumed-envelope/writer/external-witness receipt DDL.

Use a new purpose-specific immutable consumption/commit marker in that protected
untracked framework inventory, or explicitly version an existing receipt seam.
Do not silently reinterpret an existing purpose or declare an ordinary
application table to be framework custody. The new marker must bind enrollment,
generation, pending decision, predecessor checkpoint/fence, operation/request,
capability, snapshot and actual after-vector commitments, with exact one-use
identity/uniqueness constraints. Its admitted executor-only operation inserts
it after actual after-root checks, within the same SQL transaction. It has no
primary or counted maintenance trigger.

This requires coordinated exact DDL, canonical/scratch catalog contracts,
owner/ACL/function admission, framework classifications, source manifests and
receipt validation. The marker is protected transaction evidence, not proof
that the database has not been rolled back. Its absence confers no authority.
The final signed root receipt belongs in a separately defined protected
framework log after independent completion, not inside the root it signs.

The acyclic binding order is:

`prior checkpoint -> snapshot/expected vector -> pending decision -> SQL marker -> completion receipt`

If an application row needs a workflow reference, plan a stable operation or
earlier reservation identity independent of the pending decision/after-vector.
Never insert a pending/final receipt digest into an already calculated
application after-image as an unaccounted post-root side effect. All application
changes remain covered exactly once by the complete vectors and mutation proof.

## Reuse and implementation boundary

[`WitnessJournalIO`](../serverware/authority_witness_journal.py) supplies real
bounded immutable publication, no-replace rename, file/directory barriers,
shared locking and poisoned-handle recovery. Its caller must provide the
trusted directory/singleton, canonical protocol validation and quotas; it does
not supply independent latest-head retention. Existing witness capacity and
generation/exact-replay checks are useful patterns, not transferable purpose
authorization. See the [durability boundary](authority-witness-journal-durability.md).

The [local initialization store](authority-audit-initialization-store.md)
provides a separate example of owned SERIALIZABLE commit, exact retry and
unknown-outcome handling. Its fixed one-use role is not a general current-root
service, and a separately located PostgreSQL database alone does not prove
rollback resistance. Do not repurpose its schema, signing purposes or enrollment.

Required implementation remains: the bounded purpose-specific contracts and
signature admission; an independently provisioned latest-head/pending backend
and service; authenticated enrollment/generation/recovery; protected SQL markers
and postcommit assurance; and coordinated Snapshot/v4, planner, executor,
receipt, schema/ACL and source-manifest integration. Every application writer,
including legacy/direct DML and authorization-source updates, must participate
or be fenced. Installing counted maintenance triggers alone cannot achieve it.

No current source component establishes those deployment premises. Independent
administration, trust pins, durable latest-head authority, time, transport,
writer exclusion and recovery provisioning remain external requirements. The
existing startup and controlled-verification gates stay closed.
