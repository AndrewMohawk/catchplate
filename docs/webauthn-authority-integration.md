# Completing the WebAuthn authority transitions

Status: original implementation design, not an enabled protocol or migration.
The current [startup inventory](authority-transition-startup-blocker.md) has
six missing registered kernels, including the two new evidence-admission
operations. The revision-specific successor status below is authoritative for
current manifests and source work. Registry closure, database admission and
external authority requirements remain enforced. This document does not
authorize registering partial kernels or relabeling local verification as
signed external evidence.

This design records the original gaps. The current
[successor implementation status](webauthn-successor-transitions.md) tracks the
source-only work now implementing its aggregate manifest, queries, signatures,
row effects and private acquisitions. Those additions do not activate the
public protocol or remove the independent authority requirements below.

Source `.84` adds optional purpose-specific policy to signed service
configuration v2: `webauthnEvidenceAdmission`, schema
`serverware.policyAuthorityWebAuthnEvidenceAdmissionPolicy/v1`. Its closed
`registration` and `installation` slots pin an explicit canonical raw Ed25519
public key and matching SPKI digest, signer identity, and bounded age/skew.
Registration RP/origin must equal the existing WebAuthn configuration;
installation pins a target digest. An absent block or null purpose grants no
authority for that purpose. No generic role key is substituted.

The loader and artifact generator validate that optional extension. The private
planner service factory `_webauthn_evidence_planner` owns the full payload before
launch/descriptor callbacks and captures generation last. The purpose-specific
mapper checks the actual configuration commitment and launch membership on the
same work, then constructs the real `EvidenceAdmissionPlanner` read owner.
Construction opens no SQL and enables no route or kernel. Its actual acquisition
still encounters the registry gate and returns proposed row/root observations,
not persisted evidence. These additions are unbuilt and unexecuted; provisioning,
independent root/time admission and the activation evidence below remain required.

The [startup blocker](authority-transition-startup-blocker.md) and
[unactivated revocation candidate](webauthn-revocation-candidate.md) identify the
current seams. Completing them requires the following coordinated producer,
admission, query-proof, transaction and recovery changes. A new measured
contract must name their exact schemas, domains, limits and migration before
activation; `vNext` below is a design label, not an accepted version string.

## Preserve the actual transaction semantics

Trust staging is not just inserting a publication row. The current
`app.webauthn_trust_publish` transaction consumes the approval, invalidates all
live registration challenges, revokes every affected credential and its
dependent sessions/grants/approvals, emits the corresponding audits, and stages
the publication journal. Independent stage/revoke/approval commits would not
preserve that operation. The old one-publication-mutation reservation could
not represent this aggregate; source `.77` replaces it with the aggregate
manifest and limits described in the successor implementation status.

Use one typed aggregate transaction program, with a deterministic working-state
view and one final mutation per unique row key. Validate actor, MFA, approval,
RBAC and approver credential against the authenticated prestate. Consume the
approval in that working state before deriving dependent revocations. If its
approver credential is withdrawn, that now-consumed approval must not also be
treated as an approved row to invalidate. Merge a signing credential's counter
update and its revocation rather than emitting conflicting writes. Invalidate
the global registration set once, including when no credentials are withdrawn.

Trust withdrawal is the complete result of `credential_trust_status` evaluated
against candidate roots, not merely credentials referencing removed root IDs.
Preserve missing/null root, AAGUID restriction and authenticator-class mismatch
cases, as well as the existing development exception. Prove the complete union
of rejected index partitions/ranges; an operator-supplied address list is only
a signed hint and cannot determine that union.

The [explicit-context classifier](webauthn-credential-trust.md) now implements
that shared decision in the live wrapper and captures one candidate policy for
both publication impact passes. This is classification reuse, not a proof of
the database population or admission of the aggregate authority transaction.

Registration finalization must preserve global credential-ID nonreuse,
including revoked history, and consume the exact unused, unexpired,
user/label-bound registration challenge. OIDC first enrollment additionally
requires the exact pending session authorization, zero credential history for
the user across all statuses, and invalidation of every other live registration
challenge for that user. Its sibling query does **not** exclude challenges with
an approval request. Finalization does not activate the OIDC session.

Explicit credential revocation invalidates live registration challenges for
**all users**, not just the credential owner. Trust withdrawal performs the
same global invalidation once at aggregate scope. Preserve both live OIDC
statuses (`pending_webauthn` and `active`), active grants, approved control-plane
approvals, and each approval's own audit. Standalone self-revocation, admin
revocation, trust withdrawal and lost-key recovery are distinct authorization
paths; the current self-revocation candidate does not substitute for all four.

## Authenticated query and capacity evidence

The existing primary radix proof establishes one row's membership or exact-key
absence relative to a supplied root. Its hashed path does not preserve SQL
predicate order. `LIMIT + 1` and selected-row proofs do not prove that a
malicious database omitted no matching row. The current exact-page helper
checks self-consistent hashes, not a reconstructed complete interval, and is
not a usable completeness authority.

The new [counted-index range component](authority-index-range.md) now implements
bounded sparse-frontier reconstruction for one complete fixed-key interval. It
opens every intersecting nonempty subtree and hashes counts into the computed
root. The separate [fixed-projection join](authority-index-primary-join.md) now
defines eleven selectors and rederives each returned leaf from the actual
primary evaluator's owned verified rows. Both remain unactivated source:
independently admitted same-checkpoint roots remain absent. The
[storage installer and real all-writer trigger](authority-counted-installation.md)
are now wired in source, but unbuilt and unexecuted. Neither replaces the existing query
primitive or enables any missing kernel.

The coordinated index/query manifest must cover at least these fixed selectors:

| Relation | Required complete selection or absence/count fact |
| --- | --- |
| Credentials | Global credential-ID nonreuse; all-status user history; complete live enrolled-trusted withdrawal partitions by root, AAGUID and class, including null roots. |
| Challenges | Exact challenge identity joined to the captured raw challenge; user-wide live registration siblings; global live registration invalidation, with a fixed expiry cutoff. |
| OIDC sessions | Exact first-enrollment session/user/status/expiry; all credential-bound pending or active sessions for cascades. |
| Approval grants | All active grants bound to each affected credential, without inventing an expiry/reservation filter. |
| Control-plane approvals | All approved rows bound to affected credentials, plus exact aggregate approval/RBAC/credential authorization dependencies. |
| Trust publications | Bundle-digest reuse lookup, singleton pending-state absence and monotonic latest/predecessor state, or a reviewed equivalent authenticated singleton projection. |
| Audit outbox | Exact replay/idempotency identities and authenticated pending-plus-claimed cardinality against the existing 100,000-row capacity. |

Use versioned, measured projections with explicit ordering for nulls, UTF-8,
integers and losslessly encoded timestamps, and a deterministic primary-key
tiebreaker. Each index leaf binds its derived index key, business primary key
and authenticated primary-row digest. Roots and nodes bind their index/profile
identity, path/depth and cardinality. Existing primary-tree framing and
transport digests remain distinct; do not silently change persisted roots.

A bounded frontier verifier must reconstruct the independently anchored index
root. Every subtree intersecting an enumeration interval must be opened to its
returned leaves or proved empty: a nonempty opaque interior subtree is not a
terminal page. Join every returned leaf to the exact primary-row proof at the
same checkpoint and rederive its selector from those row bytes. Count-only
proofs may use authenticated subtree cardinalities only under a separately
declared counted-range primitive; a caller's count or SQL aggregate is not such
a proof. This is needed to preserve audit capacity without requiring the whole
outbox to fit a cascade row limit.

The query model must explicitly represent indexed complete ranges. Today
`exact_page` and `secondary_index_name` require different, mutually exclusive
proof primitives; silently overloading either is not an integration. The
[retained query observations](authority-query-read-retention.md) now preserve
individual definitions, ordered member addresses and empty results alongside
the selected-row union. Actual primary verification also precedes the kernel.
Those observations are not authenticated predicate evidence: empty queries
still need range proofs, and closed versioned transport/admission is missing.

All writers must maintain exact OLD/NEW index deltas atomically with primary
row changes: insertion, deletion, status/credential/key/expiry moves, unchanged
index keys whose row digest changes, recovery, challenge consumption, and
outbox delivery/cleanup. Passage of time changes the query cutoff, not stored
membership. Bootstrap must prove both directions of primary/index mapping
under writer exclusion and independent admission; it must not bless whatever
rows an existing database returns. A changed manifest requires a reviewed
migration, not automatic repair of an accepted database.

The [audit-capacity integration](authority-audit-capacity.md) now shares the
fixed limit and applies global OLD/NEW accounting at common planner/executor
boundaries. Old policy/quota counters have been removed, but authenticated
initialization and general receipt-bound PostgreSQL delivery remain missing.
Legacy SQLite still uses a locked COUNT. A nominal limit and source wiring do
not prove a maintained population.
The [global capacity implementation contract](authority-global-audit-capacity-design.md)
records the compact validators, nineteen-operation scope and coordinated
business/framework bounds. No workflow is admitted without the required
baseline, evidence and complete business kernel.

## Root authority, time and whole-operation bounds

The planner currently reads roots and time from PostgreSQL. The executor's
same-database locks and root comparisons provide a compare-and-swap boundary,
not independent currentness against database rollback. An independent authority
must retain a monotonic root checkpoint and fence for the complete root set.
It must authorize the exact before roots and verify the expected after roots
derived from the complete row/index mutation proof, including unchanged-root
closure. Ambiguous commits must reconcile against the same operation and fence
before issuing new authority. A witness that signs only an operation/result
digest does not establish this root transition.

Keep secret-bearing selected rows inside the measured semantic execution
boundary. The off-host witness receives commitments, bounded root proofs and
the exact attested computation assurance required by its contract, not OIDC
session tokens, credential material or arbitrary selected-row JSON. That
assurance must name its trusted producer and measurement; opaque hashes alone
do not prove that the intended semantic/index mutation was computed.

Bind all time predicates to one independently checked evaluation instant and
the request's deadline. Enforce expiry/deadline again at the authorized commit
boundary. Even a correct range proof can omit live challenges if an untrusted
database supplies a later cutoff. An explicit local verification time removes
a hidden input, but does not by itself make that time an independent authority.

Charge the entire operation for unique selected rows, mutations, new audits,
input bytes, proof/frontier nodes, table/index updates, trace reads and work.
Compute the complete cost before effects; no subset success, independent child
commits, or budget reset per page. Transport pagination retains one query,
checkpoint, cutoff and total budget; gaps, overlaps and duplicate leaves fail.
The [primary read batching implementation](authority-primary-read-batching.md)
now replaces per-row child lookups with bounded shared physical reads while
preserving full proof bytes/evaluator work and the exact global counter trace.
This removes the source's unconditional 65-reads-per-business-row schedule, not
the need to prove full 192-row operation capacity. Other reads and all new index
costs remain charged. Raising one limit or retaining a smaller fixture is not
proof of the declared capacity; changed operation/framework/index bounds still
require explicit reconciliation and versioning.

## Registration verification and acyclic evidence

The registration crypto core must be used by the actual registration path,
not only a fixture. It receives original bounded client-data/attestation bytes,
immutable ceremony scope, explicit RP/origin, validated root snapshot and one
verification time.
It derives credential/key/counter/AAGUID/class and trusted/untrusted attestation
results without database, file, cache or clock access. Preserve ordinary
enrollment versus recovery policy and supported untrusted classifications.
Raw artifact commitments hash the original bytes, never a reserialized JSON
or CBOR object.

Such a result is **not** a verified selected-row snapshot, enrollment authority,
signed receipt, physical-authenticator proof or permission to skip finalization.
The live wrapper still owns challenge/history lookup, current trust loading and
the atomic database finalization. A future measured issuer must independently
authenticate the selected challenge/authorization, trust generation, identity,
time and exact result before signing evidence.

Define an acyclic signing contract in this order:

1. A closed semantic intent commits operation/source/profile, actor/enrollment
   mode, challenge identity and authenticated row digest, user/label, RP/origin,
   original artifact digests and required trust predecessor. It excludes future
   evidence/signature, final request/capability and future commit receipts.
2. Verification claims bind that intent digest, derived result, exact admitted
   trust checkpoint, independently pinned verifier/key/measurement identity and
   validity interval. Sign those claims; hash the claims plus detached signature
   and defined metadata to obtain the external evidence identity.
3. The final typed request includes the intent and evidence digest plus bounded
   lookup hints. Its existing request/capability authentication binds them, and
   the kernel verifies the exact intent/claim/row joins before consumption.

Do not bind the verifier statement to the final request digest when that
request contains the verifier evidence digest. The existing generic
`businessIntent` projection is not automatically the required precursor.
Reserved `signatureDigest` and `verificationReceiptDigest` fields must name
distinct, already-issued evidence or be replaced in the versioned schema; they
cannot name the containing signature or receipt itself.

## Trust installation, completion and crash recovery

The [explicit-context core and real local installer](webauthn-trust-installation.md)
now implement deterministic bundle validation and bounded exact readback with
state-first retry handling. These are source-only prerequisites; their unsigned
local observations do not implement the installation authority described below.

The current producer path cannot yet supply an authoritative committed stage.
The legacy stage returns publication metadata. The v9 writer commit receipt
binds snapshot and before/after roots but is DB-computed and unsigned; the
signed replay witness receipt binds operation/request/capability/result and
generation/log ancestry, not those root transitions or aggregate withdrawal
completeness. The authority service response exposes receipt digests, not the
full independently authenticated stage evidence. Do not wrap this metadata or
the unsigned local installation observation in a new signature and treat that
as the missing root authority.

First commit the complete aggregate stage transaction and its independent root
transition. The installation authority receives that **already committed**
stage receipt, exact predecessor/candidate bundle bytes, signer policy,
epoch/sequence and trusted-time context. It verifies the bundle and stage,
performs durable atomic installation, then signs the actual installed-byte and
target identity evidence. It cannot assert installation before that operation
or infer withdrawal completeness from a caller-supplied list.

Completion consumes the installation evidence and changes publication,
high-water, audit and receipt state in one authorized transaction. High-water
advancement must be a planned mutation before after-roots are computed, not
the disabled legacy post-root side effect. Proof/capacity inputs remain
necessary even if only four business-row mutations are involved.

Completion's four business rows/mutations remain allocated to publication,
high-water, audit and external evidence. Source `.25` explicitly grants one
additional selected aggregate row and counter mutation, its UPDATE/proof
permission and actual framework work allowance: total 5 / 5 / 130. This does
not activate completion or provide the initializer or evidence authority; the
successor's private kernel and acquisition remain unregistered source work.

Keep the digest meanings distinct: `bundleDigest` commits the unsigned bundle;
`payloadDigest` commits the approved control-plane mutation payload, not just
that bundle; the canonical envelope digest also includes its bundle signature.
The reserved verification statement does not bind exact installed file bytes,
an independently configured target, or committed aggregate-stage/root ancestry.
It therefore needs a new closed version, not a reinterpretation of the reserved
v1 fields. The successor now supplies v2 evidence semantics and private
admission acquisition, with purpose-specific key/identity/target/time policy
and a configured read factory in `.84`. Independently provisioned authority,
durable admission and its authenticated root transition, retained semantic
replay and terminal integration remain required. The local bundle signing key
and generic receipt structure checks are not substitutes.

An installed-but-uncompleted crash remains a pending, reconciliable operation;
a local file alone does not publish authority. Retry verifies the same stage,
target, installed bytes and evidence identity without repeating withdrawals or
creating new authority. Conflicting, stale or uncertain outcomes fail closed.

Keep the receipt dependency graph acyclic here too. Installation evidence names
the earlier stage, not its own future completion receipt. A high-water row's
witness digest must name an already-issued reservation/stage receipt, not the
terminal witness that signs the resulting root containing that row. Terminal
root receipts belong to a separately defined append-only framework log; a
subsequent checkpoint can bind them without self-reference.

## Evidence required before activation

Require positive full transactions and controls for omitted interior members
despite valid returned-row proofs; false empty/terminal/count claims; wrong
predicate/root/revision/time; historical credential reuse; cross-user or expired
OIDC authorization; global/sibling challenge scope; approval overlap/order;
per-approval and aggregate audit counts/capacity; every index key/status/expiry
move; total-budget overflow; independent-root rollback; stale/consumed/crossed
evidence; exact replay/conflicting replay; interrupted installation/commit
recovery; and all-or-nothing database rollback.

Then prove the actual producer/admission/planner/witness/executor path and
source-root startup under the prescribed frozen no-build workflow. Pure crypto,
kernel-output, source-wiring and same-database tests are useful components but
cannot independently establish this complete boundary.
