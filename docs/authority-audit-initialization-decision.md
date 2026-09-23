# Independent audit initialization decision requirements

Status: protocol requirements, not an implemented service or admitted wire
contract. The [signed consumer](authority-audit-initialization-evidence.md)
authenticates an exact calculation but consumes no initialization entitlement.
The [local journal repair](authority-witness-journal-durability.md) supplies no
independent rollback authority. Production counter installation remains disabled.

## Independently enrolled identity

The entitlement must be keyed by an independently provisioned stable database
enrollment, its accepted generation and the fixed global audit counter identity.
A request nonce, DSN, caller-chosen generation or currently absent SQL row must
never create an unused entitlement. Enrollment must bind the identity, monotonic
generation sequence/digest and predecessor ancestry, the source/schema/import
closure, expected initializer and signer identities, trust policy and an
independent rollback-resistant decision head. Restoring the examined database
must not restore this authority to an earlier unused state.

Generation handover must carry consumed identity and unresolved decisions;
missing local files or a newer request-selected generation cannot establish
fresh genesis. The enrollment loader and independent latest-head authority are
not implemented or provisioned. The current startup witness floor is not a
substitute for a latest head advanced by every acknowledged decision.

## Required irreversible sequence

| Durable state | Meaning | Allowed progression |
| --- | --- | --- |
| `UNUSED` | Independent enrollment has no initialization decision | Admit one exact decision |
| `COMMIT_DECIDED` | Exact decision is durable and externally anchored before SQL commit | Materialization or independent recovery; never reopen entitlement |
| `APPLIED` | Authenticated postcommit materialization is durably anchored | Historical receipt lookup, never another initialization |

`RECOVERY_REQUIRED` describes uncertainty while preserving the irreversible
decision; it is not a state that restores `UNUSED`. A reservation/preparation
step, if introduced, must reserve all terminal/recovery storage capacity before
acceptance. Only a failure proven to precede the irreversible decision may
reopen admission under its own exact protocol.

The dependency order must remain acyclic:

`enrollment + predecessor head → checkpoint → preparation → authorization → durable decision → SQL materialization → APPLIED`

The current `initializationAncestryDigest` can bind independently accepted
predecessor ancestry. It must not refer circularly to the new decision containing
that authorization. A purpose-specific database materialization marker likewise
cannot require its own final root/signature as part of the row being committed.

The exact decision must retain the original checkpoint and authorization bytes,
not a reconstructed equivalent envelope. Bind the enrolled identity/generation,
fixed counter, sequence/predecessor head, exact canonical request, operation and
nonce, fence identity/generation, preparation/full-row digests and exact
before/after root descriptors. Existing authorization signatures authenticate
those calculations, not decision-service storage or latest-head authority.
Decision signing needs its own closed purpose and independently provisioned pin.

## SQL and retry boundary

An admitted installer must acquire actual all-writer exclusion, validate current
schema/source and root descriptors, consume the real complete inventory and
absence proofs, and recheck independent authority/time after potentially long
work. The external service must durably anchor `COMMIT_DECIDED` before SQL may
commit. SQL must atomically materialize the exact row through the actual tree
triggers and record purpose-specific decision/ancestry consumption. Compare
actual row/tree readback, not a manually assigned predicted root.

After SQL commit, independently authenticated materialization must advance the
external decision to `APPLIED` before normal writers are released. The existing
runtime service's SQL-result-then-terminal-witness sequence is not this protocol;
nor may the completed v8-to-v9 migration receipt be silently repurposed.

Exact retry returns the original decision and retained historical receipt. It
does **not** grant permission to execute the INSERT again. In particular, an
absent local receipt plus the original before-root can mean either definite
noncommit or database rollback after an unacknowledged commit. The current
source supplies no independent proof distinguishing those cases. Keep writers
fenced and require purpose-bound recovery; never infer a new entitlement from
absence. Expiry or a fresh signature does not undo a durable decision.

If `APPLIED` exists externally but its database marker is missing, report
rollback/divergence, not permission to reinsert. If normal counter evolution has
occurred after successful initialization, exact receipt lookup must return the
historical materialization without requiring today's row/root to equal the
initial values. A postcommit lost response is an evidence-recovery problem, not
an opportunity to derive a new initial counter.

These requirements still need the actual service/enrollment/transport producer,
independent head backend, signed decision and materialization admission,
purpose-specific database receipt schema/ACL/migration closure, proof-stream
adapter and installer integration, plus concurrency/crash/lost-ack coverage.
No current class, self-digest, local journal or component fixture fills those
roles. Global aggregate online INSERT and initializer activation remain disabled.
