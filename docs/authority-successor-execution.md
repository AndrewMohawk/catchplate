# Successor execution source path

This source path separates permission to execute from proof of the proposed
changes. Neither a planner signature, computation key, root vector nor pending
receipt alone authorizes database writes. Source `.139` now connects genuine
original admission, protected immutable custody and identifier-only execution,
including the source installer, ACL/catalog checks and actual transaction
owners. These changes remain unbuilt, unexecuted and unprovisioned; no public
successor route is activated and existing legacy gates remain closed.

Source `.140` adds a separate restricted recovery role and
[`SuccessorExecutionRecoveryReader`](../catchplate/authority_successor_execution_owner.py).
Its sole protected read function retrieves exact canonical packet originals by
independently held pending-decision and packet digests, with no direct table
or sequence access. The real PostgreSQL read-only owner preserves the caller's
live retrieval window, TLS/ACL admission and before/after source-catalog checks.
Expired historical controls remain readable without renewal; returned bytes
still require genuine historical authentication and an independently admitted
current pending checkpoint. This does not provision the role or enable SQL retries,
execution or a public recovery route.

## Authorization order

```mermaid
flowchart TD
    A[Independently authorized original request and plan] --> B[Pre-decision execution grant]
    B --> C[Computation snapshot binds original grant digest]
    C --> D[Durable current-root pending decision]
    D --> E[Original grant, pending receipt and plan admission]
    E --> F[Dedicated issuer retains original custody packet]
    F --> G[Separate durable one-attempt journal]
    G --> H[Identifier-only executor: atomic writes and marker]
    H -. private postcommit recovery .-> I[Read-only completion and durable delivery]
```

The grant precedes the pending decision. Its original signed-byte identity
becomes `capabilityDigest` in the reserve and computation snapshot. The grant
therefore cannot contain the later pending receipt or that snapshot's digest:
either dependency would make the signatures circular. Instead it binds the
original plan/retention, typed request, genuine result and complete before/after
vectors. Admission joins those same commitments again after reservation.

Revocation's existing signed capability ID and Snapshot/v4 remain distinct
historical commitments. Neither is relabelled as the new original grant digest.

## Dedicated authorization purpose

The successor grant uses a separate root-signed enrollment, bound to the
original current-root enrollment, database, generation, source revision and
the exact seven [supported replay operations](authority-successor-replay-families.md),
not the larger source-planning inventory. Its dedicated authorizer key/measurement
is not a computation, completion, state or plan-signing identity. Existing
issuer database credentials do not supply this signing authority.

The independently admitted `requestAuthorizationDigest` must identify the real
caller/request authorization. A digest copied from the incoming grant, stored
plan or caller-supplied success object does not satisfy that requirement.
Grant verification authenticates the enrolled authorizer's assertion; it does
not independently establish the caller's session, key custody or measurement.
No generic scope-object-to-production-grant issuer is provided.

Source `.143` adds [original-plan grant and dedicated authorizer enrollment
production](authority-successor-execution-grant-production.md). The grant
producer performs genuine plan replay itself and signs only same-call derived
claims with independent authorization scope; public caller admission, cold
authorizer ownership and key/service provisioning remain external.

The later [registration execution authorization prerequisite](registration-execution-authorization.md)
provides a separate root-delegated caller purpose for the fixed
`webauthn.registration.evidence.admit` request. Actual original raw8 source and
raw2 evidence inputs are reconstructed into the typed request; its signed
authorization is authenticated and joined to genuine raw3 plan replay before
successor-grant signing. Plan production is unchanged. This is not a supplied
permission digest or successful replay carrier. Existing control-plane
enrollment grants still permit evidence
signing only: their operation string cannot be repurposed into SQL permission.
No cold process, public caller route, reserve or SQL call is added by this
prerequisite, and credential finalization remains a separate operation.

[`authority_successor_execution_preparation._produce_reserve_on_work`](../catchplate/authority_successor_execution_preparation.py)
connects an original grant to actual reserve production. It accepts grant and
enrollment originals, independent authorization/history/key inputs and the
original plan, not a supplied capability digest or verified-plan object. The
grant verifier performs genuine plan replay once; the same-call result feeds
the existing computation signing suffix. The reserve uses the actual original
grant digest and cannot outlive the grant, caller deadline or inherited local
monotonic deadline. The older scope-only computation helper is not upgraded to
execution-grant admission by this separate path.

## One genuine plan replay at final admission

[`authority_current_root_execution_admission`](../catchplate/authority_current_root_execution_admission.py)
authenticates the original enrollment, reserve request and state receipt, checks
the independently expected pending head/sequence/fence, and recomputes the
original computation snapshot from actual seven-operation plan replay. The candidate
contains only same-call derived request, selected rows, mutations, result,
work units, complete vectors and expected marker data. It is ordinary data, not
a proof token or a callable database permission.

[`authority_successor_execution_grant`](../catchplate/authority_successor_execution_grant.py)
provides original enrollment/grant signature verification and a standalone
original-plan verifier. The combined
[`authority_successor_execution_admission._admit_on_work`](../catchplate/authority_successor_execution_admission.py)
uses the control verifier after genuine pending/plan admission, then joins all
grant claims to the same-call reconstructed snapshot. This performs the heavy
plan proof computation once, without accepting a successful replay carrier as
an input.

The original grant identity must equal the reserved capability digest. The
reserve cannot change the grant's original issue time or extend its expiry.
Actual clock checks preserve the caller's unchanged live window and inherited
monotonic deadline. Historical plan validity is not renewed into new authority.

## Original-byte custody, not a supplied execution candidate

[`authority_successor_execution_packet._prepare_on_work`](../catchplate/authority_successor_execution_packet.py)
invokes the genuine combined admission once on the caller's existing work. It
accepts original controls/plans and independent expectations, never an incoming
successful candidate or packet. Its canonical exact-16-field packet binds
authorization/request/operation identities, the unchanged reserve interval,
actual selected rows, ordered mutations, result/work units, complete vectors
and the exact 18-field marker.

The packet's `originals` object has seven entries: `currentRootEnrollment`,
`grantEnrollment`, `grant`, `reserveRequest`, `reserveReceipt`,
`computationSnapshot` and `plan`. Controls retain original bytes as canonical
base64url with raw SHA-256 and byte count; `plan` retains the ordered original
raw2/raw3/raw4 frames appropriate to its family. Raw byte hashes remain distinct
from framed grant, receipt, snapshot and packet identities. The complete
encoded packet, including this framing, is at most 64 MiB; existing cumulative
work and individual source bounds still apply. Retained originals do not
independently enroll their historical keys, authorization or checkpoint.

## Protected SQL and actual transaction owners

[`authority_successor_execution_owner`](../catchplate/authority_successor_execution_owner.py)
provides `SuccessorExecutionIssuer.issue(...)`, which produces that packet
itself, and `SuccessorExecutionExecutor.execute(...)`, whose only custody
selectors are `pending_decision_digest` and `packet_digest`. The executor does
not accept candidate JSON, mutations or a successful attempt carrier.

The distinct fixed database roles each have only their protected function,
with no direct relation/sequence privileges or generic function execution:

- `catchplate_policy_authority_successor_issuer` calls
  `catchplate_policy_authority_issue_successor_execution(text, text)`.
- `catchplate_policy_authority_successor_executor` calls
  `catchplate_policy_authority_execute_successor(text, text)`.
- `catchplate_policy_authority_successor_recovery` calls
  `catchplate_policy_authority_read_successor_execution(text, text)`.

[`authority_store.successor_execution_sql`](../catchplate/authority_store/successor_execution_sql.py)
stores the admitted packet in immutable
`policy_authority_successor_execution_custody`. Its executor locks that exact
custody row, joins both identifiers and rejects an existing commit marker before
using the retained effects. SQL checks source/canonical framing and commitment
joins; it does not replace genuine Ed25519 admission with signature-shaped JSON.
The independently admitted dedicated issuer is the cryptographic boundary.

[`authority_store.current_root_execution_sql`](../catchplate/authority_store/current_root_execution_sql.py)
supplies the reused source-fixed mutation body. The atomic path locks and checks
complete before roots, applies actual closed primary-key/full-row compare-and-swap
mutations with maintained primary
and counted indexes and the existing audit-capacity guard, checks the complete
after-vector, and inserts the exact 18-column immutable framework marker in the
same transaction. The later postcommit receipt commits that marker, never the
reverse. Neither a matching marker nor its absence proves rollback resistance.

Each issuer/executor owner uses actual PostgreSQL 16 TLS/role admission and
keeps its catalog checks and protected call on the same physical
`SERIALIZABLE READ WRITE NOT DEFERRABLE` transaction. Its exact eight-value
configuration contains the fixed role, existing connection/query pins and an
eighth independently admitted **source-generated complete structural-manifest
digest**. The actual full catalog, including functions, ACLs and business
triggers, must match that pin before the protected call and again before normal
outer commit. Observing a catalog never enrolls its own expected digest.
Returned custody locators or marker bytes are unsigned observations, exposed
only after normal outer transaction commit and connection closure, not signed
completion evidence. A late error may follow commitment; deadlines and bounded
database waits are not a hard native-call watchdog.

The source installer now includes the exact custody schema, functions, guards
and grants; it has not been run here. All three roles and identities must be
independently provisioned. Offline metadata bootstrap requires the prefixes
`CATCHPLATE_POLICY_AUTHORITY_SUCCESSOR_ISSUER_`,
`CATCHPLATE_POLICY_AUTHORITY_SUCCESSOR_EXECUTOR_` and
`CATCHPLATE_POLICY_AUTHORITY_SUCCESSOR_RECOVERY_`, each with all six suffixes:
`MEASUREMENT_SHA256`, `ATTESTATION_RECEIPT_SHA256`,
`CREDENTIAL_ISSUANCE_SHA256`, `TLS_CLIENT_DN`, `TLS_CLIENT_SERIAL` and
`TLS_ISSUER_DN`. Missing values do not fall back to legacy identity pins.
Existing custody stores require separately reviewed migration; no automatic
adoption, repair, role generation or public activation follows from installation
source. Legacy execution gates remain unchanged and no direct DML is granted.

## Durable attempt before database connection

[`SuccessorExecutionAttempts`](../catchplate/authority_successor_execution_attempts.py)
owns a separate private preprovisioned `CurrentRootJournal` in an independent
database-rollback domain. Construction requires an independently current exact
local sequence/head and the expected structure-manifest digest, not a minimum
sequence or a checkpoint derived from the scanned journal. Recovery verifies
the source-bound canonical chain and exact checkpoint. Capacity is bounded by
the actual journal's 2–1024-record limit; each attempt is at most 4 KiB.

The executor joins the actual attempt owner's structure digest to its catalog
pin and calls its fixed `_claim_on_work` before opening any database connection.
One immutable record is published and fsynced before the call can return.
Either a repeated pending decision or a repeated packet is rejected forever,
including identical resubmission after SQL abort or restart. Ambiguous
publication poisons/closes the owner; a late deadline failure can leave an
already durable attempt. Nothing deletes, expires, clears or resets it, and
capacity exhaustion does not create a replacement journal or generation.

This is not request authorization or hostile-host antirollback. Restart safety
depends on the protected separate domain and independently current checkpoint;
a valid old local prefix cannot admit itself. Local inspection is unsigned and
cannot authorize retry, completion or cancellation.

## Completion remains a separate authenticated path

The `.136` [fixed read-only completion
producer](authority-current-root-completion.md) authenticates original
pending/plan/grant bytes historically under an independently current exact
pending checkpoint, reads the committed marker and all roots in one admitted
transaction, and requires exact expected-marker/full-after-vector equality.
Only after normal database closure does the enrolled completion key sign the
fresh complete control. Its inner observation record is not independently
signed. This can follow grant expiry but cannot execute, reset or release a
transition without the matched committed marker. The executor's unsigned return
does not replace that readback or grant premature completion authority. The
private recovery composition below connects this production to durable delivery;
it does not activate a serving process or public business finalization.

## Restricted recovery and exact completion reuse

`SuccessorExecutionRecoveryReader.read(...)` retrieves packet originals through
the recovery role's single protected function, with zero direct relation or
sequence privileges. Its actual PostgreSQL transaction is
`SERIALIZABLE READ ONLY DEFERRABLE`, with independently pinned TLS and full
before/after catalog checks. Both custody selectors must be independently held.
Canonical bytes, the framed packet digest and immutable row columns are joined;
historical control expiry is not tested as fresh execution permission. The
returned bytes still require original-signature and proof authentication.

[`recover_and_deliver`](../catchplate/authority_successor_completion_recovery.py)
uses the actual custody reader, committed-state reader, durable delivery owner
and fixed state client. It captures their configurations and independent
history/key/scope inputs before callbacks, then holds the delivery lock across
lookup, reading, completion production, retention and exchange. One unchanged
work ledger and live retrieval window, clipped by the inherited monotonic
deadline, cover the entire sequence; database or transport steps cannot renew it.

Both readers now require an independently supplied structural-catalog pin.
Recovery joins their source query and catalog pins before either database read;
each actual connection checks its complete catalog before and after its own
observation. Different role/TLS configurations remain separate. Matching pins
do not establish database provenance or independent latest-state currentness.
The [catalog-admission note](authority-catalog-admission.md) describes the
restricted-role metadata projection and deferred verification boundary.

If a completion is already retained for the exact pending checkpoint, the
composition authenticates that original and joins it to the independently
pinned custody packet, then reuses the identical bytes without another plan
replay or replacement signature. Otherwise it genuinely replays the historical
originals, matches the actual committed marker/full after-vector, and signs a
completion only after normal database closure. The complete control is durably
enqueued before transport; the authenticated original state acknowledgement is
durably retained before a delivered result returns. An already acknowledged
delivery returns that same receipt without another network exchange.

Failures may leave a durable request or acknowledgement. Explicit recovery can
redeliver only the retained original, never reexecute SQL, clear an attempt or
replace an expired never-accepted completion. An unchanged expired original can
succeed only when the state owner had already accepted it and returns its original
receipt. Fresh signed state reconciliation is separate: a retained receipt is
not a fresh state lease or independently current checkpoint.

## Remaining production boundary

Independent caller authorization and key/history provenance, cold configuration,
source-generated catalog/checkpoint admission and measured service ownership
remain prerequisites. The restricted custody reader and private postcommit
recovery/delivery composition are source implementations, not deployed service
admission or public business finalization. An expired or unanswered request
cannot clear a pending fence, reset an attempt or authorize SQL retry. No currentness authority is inferred from
source installation, matching digests or local observation. Independent
production infrastructure/provisioning and the consolidated frozen
build/verification phase remain outstanding.
