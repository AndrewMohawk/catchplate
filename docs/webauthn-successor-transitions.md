# Successor WebAuthn transition implementation

Status: source `.88`, implementation only. Configured evidence-admission plan
owners now preserve original historical context alongside the signed plan and
detached inputs, with genuine three-original replay against independent pins.
These helpers do not register missing kernels or repair service startup. They
are unbuilt and unexecuted.
The existing registry, query-proof, configuration and release gates remain.

## Evidence without circular dependencies

`authority_webauthn_evidence.py` signs and verifies original canonical envelopes
for two fixed purposes: `registration-attestation` and `trust-installation`.
Both use purpose-specific v2 claims inside
`serverware.policyAuthorityWebAuthnEvidence/v1`. The envelope binds source,
purpose, signer identity and SPKI, claims and issue/expiry times. It has a
4 MiB / 4,096-node / depth-16 limit and at most a 30-second validity interval;
independently configured age/skew may be stricter.

Verification performs actual Ed25519 and SPKI checks, canonical original-byte
checks, complete expected-claim equality and freshness checks on the existing
work allowance. It takes independently supplied key, identity, claims and time
expectations and returns no proof token. Neither decoding an envelope nor
hashing it authenticates its contents. The private signer is signing mechanics,
not evidence that a ceremony, installation or authorized operation occurred.

`authority_webauthn_registration_production.py` now composes the genuine
ceremony parser and attestation verifier with fixed claim derivation and that
original-envelope signer. It returns the original signed bytes and final
registration arguments containing their actual digest/base64 encoding. It owns
the supplied ceremony, row and trust snapshots before callbacks and accepts no
successful-attestation DTO. Those snapshots, enrollment permission and signer
configuration still require independent admission; producing these arguments
does not grant registration or persist evidence.

`authority_webauthn_installation_production.py` derives installation claims
through the same original-byte semantic checks used by completion, then signs
the genuine envelope and produces the final completion arguments. It accepts
no claims or successful-verification DTO. The caller still owns the protected
physical install/readback, independently admitted committed stage and current
rows, target, observation time and signing configuration. Supplied file bytes
are not proof of installation, fsync or runtime activation. Producing evidence
does not persist it or authorize publication.

The separate registration and installation admission composers now derive
their expected claims through those actual semantic workers and verify the
original signed envelope before proposing a custody row. Registration reruns
the real ceremony parser and attestation verifier; neither composer accepts
caller-supplied claims or a successful-verification result. They preserve the
original verification/observation instant and exact producer expiry, including
challenge/OIDC clipping, while checking freshness at a separate admission time.

Their shared row comparison recomputes the exact evidence business primary-key
digest (not the authenticated-tree path digest). An absent selection produces
an ordinary proposed insertion pair. A present selection must equal all 17
unused verified fields to produce a no-op; consumed, revoked or conflicting
rows fail, and every duplicate still goes through genuine verification. These
helpers do not prove the selection or persist it. They are prerequisites for
the fixed admission operations, not registered operations or write authority.

## Evidence admission operation contracts

Two explicit source operations now render those verified effects through
purpose-specific INSERT-only templates. They leave the table-wide default and
consumer permissions UPDATE-only, with no planner/writer ACL expansion.

| Operation | Exact primary-key reads | Maximum rows / mutations / work |
| --- | --- | --- |
| `webauthn.registration.evidence.admit` | Evidence, registration challenge, global high-water, published predecessor, optional OIDC session | 5 / 1 / 128 |
| `webauthn.trust.installation.admit` | Evidence, publication, global high-water | 3 / 1 / 128 |

The registration request has exactly `evidence_digest`,
`registration_challenge_id`, `published_publication_id`, nullable
`oidc_session_id` and `businessIntent`. The distinct challenge argument remains
in request/intent commitments; the legacy authorization-only `challenge_id`
normalization is unchanged. The installation request has exactly
`evidence_digest`, `publication_id` and `businessIntent`.

The private query/kernel adapters own the selected rows and arguments, rederive
business intent, join the actual envelope identity and current row identities,
and call the genuine purpose-specific admission composer. Fresh verification
uses the held database UTC instant, separately from the original ceremony or
installation observation. They propose one real INSERT, or no mutation for an
identical unused verified row; the result reports only the evidence identity
and `proposed-insert` or `already-retained`, never a committed receipt.

Neither operation changes challenges, credentials, sessions, trust publication
or audit-outbox/capacity rows. The executor's framework audit remains required.
Configured read-only ownership, private proof acquisition and signed-plan
replay are described below. Independent request/root admission, serving and
authorized atomic execution remain unfinished.
The adapters do not register configured kernels or supply the two required
callable database handlers. All six missing-kernel closure failures remain;
operator-role admission stays denied. This source does not repair startup.

## Evidence admission read and write-proof acquisition

`authority_webauthn_evidence_acquisition.py` connects both fixed admission
operations to the actual planner read/proof path and their genuine kernels.
It owns the request, manifest, independent root expectations and purpose inputs
before SQL or native callbacks, rederives request/operation commitments, compares
database roots with those expectations and bounds the one database cutoff
against admitted live time and the deadline. Historical ceremony/installation
observation times remain distinct from that fresh admission cutoff.

The actual primary membership engine authenticates selected rows and absences
before either kernel runs. Query-read validation binds those owned rows to the
exact declared queries. The same remaining work then covers genuine evidence
verification and primary before/after-root derivation for the proposed INSERT
or duplicate no-op. The existing indexed-primary writer handles an empty
counted-head inventory because the only writable table has no counted profiles;
there are no invented index reads, complete-range families or capacity effects.

Ordinary query/proof callbacks preserve the existing work allowance. Root-read
callbacks now guard method lookup and exceptional returns as well as success.
SQL/driver work keeps its existing separate bounds; this is not whole-process
resource accounting. Returned acquisitions contain observations and real proof
results, not a signed plan, persistence receipt or current-root authority.
Request permission, independent root/key/target configuration and the read-only
MVCC transaction owner still require admission outside these private helpers.

## Configured evidence read owner

`authority_webauthn_evidence_planning.EvidenceAdmissionPlanner` now owns the
actual read-only transaction for either fixed admission operation. Construction
is inert. Its held configuration pins the database role/TLS/session identity,
connection timeout, evidence key/identity/SPKI and age/skew, plus registration
RP/origin or installation target. Calls cannot replace those settings, supply
a cursor, manifest or trace, or switch operations.

Both methods own the original bytes, root/time expectations and purpose-specific
graphs before native/key/connection callbacks. They check request commitments
and the actual key's SPKI, then enter the real planner registry boundary.
The shared read scope performs actual role/TLS/no-mutation identity checks,
loads both source-validated manifests and holds one `SERIALIZABLE READ ONLY
DEFERRABLE` transaction through genuine acquisition. The existing revocation
producer now uses the same lifecycle body. Results return only after cursor,
transaction and connection exits plus the closed-handle check; cleanup failure
cannot return a successful acquisition. No writer or signer is opened.

The private measured-configuration mapper now derives these pins from the
optional signed policy described below. Its actual service factory requires
the planner role/mode and active launch, holds the complete configuration
before descriptor callbacks, reads only the protected planner read descriptor,
then captures generation immediately before mapping. The mapper owns and
recomputes the full configuration commitment and checks active-generation
membership on the original work allowance. It also requires the selected
operation in the owned signed planner allowlist before key reconstruction or
owner construction. Neither a constructed configuration dataclass nor a
caller-created dictionary supplies root-signature or launch admission.

Connection guards cannot detect a hostile driver's hidden commit-and-BEGIN,
and read-only mode alone does not prove independent root currentness or physical
readback. Request/root and physical-installation admission, serving integration,
durable replay and operation activation remain separate unfinished boundaries.

## Optional signed evidence policy

Service configuration may contain exactly one additional known field,
`webauthnEvidenceAdmission`, with schema
`serverware.policyAuthorityWebAuthnEvidenceAdmissionPolicy/v1` and closed
`registration` and `installation` slots. An absent extension grants neither
purpose; a null slot disables that purpose. A present null extension is invalid.
The old closed payload shape remains supported; arbitrary extension fields do
not. No default signer, role-key alias or installation target is inferred.

Each enabled slot fixes the actual operation and evidence purpose, canonical
raw32 Ed25519 public key, its genuine SPKI digest, the independent signer's
session/measurement/attestation-receipt identity and age/skew bounds. Registration
also fixes RP ID and origin exactly equal to the surrounding WebAuthn settings;
installation fixes the target digest. Both complete input graphs are owned
before actual key reconstruction and DER/SPKI checks. Configuration-loader
validation has a separate bounded meter; the measured mapper uses only its
existing work allowance and never calls that standalone wrapper.

The service loader and artifact generator validate the extension. The actual
service still verifies the surrounding root signature; artifact validation is
not a substitute for that admission. Full canonical configuration bytes,
digest and generation membership bind the extension, requiring configuration
resigning and regenerated bindings. Merely adding a policy does not add a
service operation, registry kernel, handler, permission, SQL write or signer.
Independent infrastructure and evidence signers remain unprovisioned.

## Original inputs and genuine historical semantic replay

The acquisition now encodes held originals before its root/row/proof SQL reads
and returns `original_inputs_bytes` and their domain-separated
`original_inputs_digest` only with the successful kernel/proof observations.
These are ordinary retained data, not a signed plan or durable receipt.

Registration's closed input record preserves the signed evidence envelope,
client JSON, attestation object, credential ID, original transport order,
ceremony authorization bytes and expected authorization, historical UTC time
and actual trust-root DER plus metadata. Only the AAGUID set receives a sorted
unique representation; trust-root and transport ordering are preserved. The
decoder reconstructs actual `CeremonyScope`, `TrustRootSnapshot` and
`VerificationContext` objects on the same work allowance. A reconstructed trust
snapshot still needs independent historical admission.

Installation's separate closed record preserves the signed evidence envelope,
installed bundle and rollback-state originals, original observation time and
exact committed-stage descriptor. It contains no installer key, identity,
target, policy, current root or verification result. A retained stage descriptor
is not proof of a committed stage or physical readback.

Both formats bind source revision and operation. The shared transport uses
canonical JSON, duplicate-rejecting bounded decoding, exact byte counts and
canonical unpadded base64url; times round-trip through integer UTC microseconds
without floating-point conversion and retain the actual semantic nanosecond
range. The 64 MiB / one-million-node transport ceilings are not new work
allowances. Every copy, encoding, parse, comparison and hash uses remaining
caller work; combinations of locally valid maxima can exceed that allowance.

The configured owner's `replay_registration` and `replay_installation` methods
now call the genuine private semantic replay worker. It owns request, selected
rows, expected effects and signer settings before callbacks, recomputes the
typed request/operation and input commitments, reconstructs originals and
invokes the actual purpose-specific kernel. Registration repeats actual
ceremony/attestation and signed-evidence checks; installation repeats actual
bundle/state/stage semantics and signed-evidence checks. The worker compares
complete `mutations`, `result`, `kernelWorkUnits` and `workUnits`, including
recomputed query-plus-kernel work. It accepts no successful-verification DTO.

The historical input commitment, request, selected rows, database cutoff and
signer/configuration history must be independently admitted; copying a digest
from untrusted storage supplies none of that authority. A current configured
owner alone cannot resolve historical keys or policy. These methods do not
verify selected-row/root proofs, grant current execution, sign, persist or open
SQL. The separate signed-plan composition below adds actual proof replay around
these semantic workers. Durable original-input custody and executor/recovery
integration remain missing. V3 cannot silently acquire these fields, and
revocation-only v4 remains unchanged.

## Separate signed admission plans and proof replay

Source `.86` adds `webauthn-evidence-admission-v1`, with closed plan schema
`serverware.policyAuthorityWebAuthnEvidenceAdmissionPlan/v1` and its separate
signed envelope. It binds the typed request, source/operation/query manifests,
configuration and planner identity/SPKI, historical database cutoff, detached
original-input digest, exact selected rows, primary proofs, query observations,
before/after roots and complete proposed transition. It is neither a v3 plan
extension nor a revocation-v4 plan.

The fixed producer in `authority_webauthn_evidence_plan.py` genuinely replays
the raw inputs before signing; a supplied acquisition or payload is not a proof
token. Its private acquisition adapter holds actual request, query, original
input, effect and root observations, constructs the closed payload and invokes
that same full replay before returning the original envelope and detached input
bytes. The real acquisition/planner import gate is retained.
Verification checks the original canonical envelope and independently
pinned planner signature, then runs the same actual replay. The original-input
bytes remain detached and must match their independently held commitment.
Request, root, configuration, evidence-key, purpose and historical-time
expectations cannot be enrolled from the plan itself.

`authority_webauthn_evidence_proofs.py` first verifies real primary memberships
and absences, then joins every actual query observation to the regenerated
exact-PK recipe and proved selected union. Registration uses four or five
queries; installation uses three. Every query has one present or exact-absence
address and every selection has its own primary proof. Both full source root
classes are required, including the OIDC business root in ordinary registration.
The original semantic worker then reruns ceremony/installation and evidence
verification and compares the proposed effects. Finally, genuine primary write
evaluation derives and checks both after-root classes from those actual effects.

The sole writable table has no counted profiles. The real indexed-primary
engine therefore receives an empty counted inventory without skipping primary
verification or its framing work, including on an identical-retained no-op.
All ownership, query restoration, proof phases, semantic replay and signatures
spend the same existing work allowance. The 64 MiB / one-million-node plan
ceiling is not a replacement allowance or a guarantee that combined maxima fit.
Shared key and signature callbacks check allowance preservation on both success
and exceptional return. The signer reserves final output work and remeasures
the actual payload after its callback before canonical serialization.

These are source-implemented signing and replay mechanics, not durable plan or
original-input custody, current-root authority, execution permission, reservation,
terminal witnessing or recovery. Historical trust/configuration admission,
configured serving and the durable protocol integration still remain separate;
no database-schema, privilege, registry or execution-loader activation is supplied here.

## Configured live plan production

Source `.87` adds the private `EvidenceAdmissionPlanOwner`. It holds one genuine
configured read owner plus independent planner signing key, public pin,
identity and configuration digest. Registration and installation methods accept
their existing original inputs and independently admitted request/root/deadline
expectations, not replacement keys, policies, clocks or database descriptors.
The maximum plan age is exactly the selected signed evidence policy's
`maximumAgeNs`; there is no new policy field or per-call age override.

The private service factory holds the descriptor-loaded planner signer and
owns the measured configuration before active-launch/descriptor callbacks,
with generation captured last. Its mapper validates the full configuration
commitment and launch bindings, then uses the same owned graph for the actual
operation allowlist and purpose policy. Planner key, response-SPKI equality,
identity and genuine private/public pairing are checked separately from the
evidence-purpose key. Construction does not open a database or sign a plan.

Each call holds all original bytes and captures variable graphs before clock,
native, key or SQL callbacks. It reconstructs a private actual read owner from
the held configuration and calls the fixed genuine acquisition method; signing
starts only after every read scope exits normally and its connection closes.
The actual database cutoff and original-input commitment come from that local
acquisition. Request and root expectations remain independently held inputs,
not authority derived from an acquisition carrier.

`authority_webauthn_evidence_plan_clock.py` opens one immutable window. Actual
epoch samples are bracketed by actual monotonic samples, and the earliest
opening bracket fixes a conservative monotonic deadline. The epoch deadline
is clipped to the admitted caller deadline, the original evidence expiry and
the configured age. Decoding the original expiry only narrows this bound;
acquisition and signed-plan production still authenticate the same bytes.
Every check enforces both deadlines and bracket-aware epoch/monotonic drift,
including with zero allowed skew. Clock callbacks preserve the existing work
on success and failure. The window cannot be renewed during replay or signing.

The actual plan producer requires that same window and joins its deadline,
age and skew to the held expectations. It samples after input ownership,
immediately before signing after expensive replay/output reservations, after
the signature operation, and after final envelope encoding. The owner also
checks before returning the original byte strings. Fresh checks do not
rewrite signed issuance, original evidence time or historical database cutoff;
standalone retained-plan verification remains historical and independent.

An expired post-sign check withholds output but cannot undo a signature already
computed. No SQL write, persistence, sending or automatic retry occurs here.
Local samples cannot prevent suspension after the last check and are not a
trusted hardware clock or process watchdog. This is configured private source
composition, not a serving route, historical admission, durable custody,
execution capability or completed registry activation. Existing schemas,
permissions, work allowances and release gates remain unchanged.

## Original historical context and retained-record replay

Source `.88` preserves a third original, `evaluation_context_bytes`, after the
producer's existing envelope and input fields. It is encoded from the actual
owned expectations before signing, not reconstructed from a signed response or
database row. The existing live window also covers this encoding work.

The context codec uses the closed flat twenty-field
`serverware.policyAuthorityWebAuthnEvidencePlanEvaluationContext/v1` document:
`schema`, `sourceRevision` and the plan verifier's eighteen exact expectations.
Those expectations preserve request, both before-root classes, original-input
commitment, configuration/planner/evidence pins, original cutoff and evaluation
time/deadline, age/skew and the applicable RP/origin or installation target.
It contains no private/public key bytes, live monotonic window, fabricated
reservation or capability. The actual shared validator closes the request and
root inventories and admits the exact historical cutoff representation.

`authority_webauthn_evidence_plan_retention._verify_record_on_work` takes all
three raw originals, independently admitted expectations and actual public
keys. It owns the independent graph before decoding, checks canonical original
context bytes and complete equality with that graph, then invokes genuine
signed-plan proof and semantic replay using the independent graph, never the
stored context as authority. It subsequently derives both actual raw-key hashes,
three original-byte hashes and a closed sixteen-field record commitment under
`serverware.policyAuthorityWebAuthnEvidenceAdmissionRetainedPlan/v1`.
That commitment binds the original plan identity, request/operation/configuration,
key fingerprints and byte counts/hashes; it is not a signed custody receipt.

The configured owner's `verify_retained` method first joins every independent
configuration/purpose pin and policy bound to its held configuration, then
runs that actual three-original verifier. It uses public keys only and samples
no clock. A matching current owner does not prove historical authority: the
caller must still independently admit the historical configuration, request,
roots, inputs and time expectations. Neither a stored key digest nor successful
local replay enrolls keys, refreshes history or establishes current roots.

Encoding, canonical comparisons, signatures, proofs and record hashes share
the original invocation work. The existing 64 MiB / one-million-node / depth-128
transport ceilings grant no replacement budget. These are custody inputs and
replay mechanics, not durable storage. No SQL, table, privilege, execution
reservation, handler registration or serving route is added by this batch.

## Retained evidence and consumption

The v2 custody projection uses the existing
`policy_authority_external_evidence_receipts` table's exact **17 fields**. Its
`statement_json` retains the whole original canonical signed envelope, not a
claims-only reconstruction. The row binds the original-byte evidence identity,
statement/signature/binding digests, signer identity, source, purpose-specific
type and validity interval. For v2, `verified_at_epoch_ns` is the signed issuance
instant, so repeated verification derives identical unused row material.

Consumption selects that exact evidence-digest primary key, genuinely verifies
the original signature and all independent expectations, and compares all 17
fields against the unused `verified` projection. V1, consumed, revoked or
partially matching rows fail. The held UTC database instant must match the
verification time and lie within the signed interval. The returned effect sets
`consumed`, the deterministic operation ID and consumption time; it is not a
write, receipt token or substitute for selected-row/root admission.

The required dependency order is acyclic:

```text
admitted ceremony or already-committed stage
  -> semantic intent and independently verified operation facts
  -> purpose-specific signed evidence
  -> original-envelope evidence identity and independently admitted custody
  -> final typed request
  -> authenticated complete reads and deterministic row effects
  -> one authorized atomic commit and later terminal witness
```

This is the required production flow, not a claim that its integration is
finished. A statement must not bind its own future signature, evidence identity,
completion receipt, or a final request that itself contains that evidence.
Generic v1 evidence-row hash/status checks are not signature verification and
cannot substitute for independently pinned evidence authority.

## Business semantics

Registration must consume the exact live user/label-bound challenge and prove
global credential-ID nonreuse, including revoked records. OIDC first enrollment
also requires the pending session, zero all-status user credential history and
complete live sibling-registration invalidation, including approval-bound
siblings. It does not activate the OIDC session. Ordinary untrusted attestation
results remain valid where the configured enrollment policy permits them.

Trust staging is one aggregate, not a publication INSERT followed by separate
revocations. Authorization uses the prestate; approval consumption and signer
counter updates enter the working state before withdrawals. Overlapping writes
merge into one final effect per original key. The actual candidate-root
classifier selects withdrawals, and global registration invalidation occurs
once, including when no credential is withdrawn. Request hints are not complete
population evidence. The stored publication audit is emitted at completion.

Completion must bind independently admitted committed-stage/root ancestry,
configured installation target, exact installed bundle/state bytes and their
signed installation evidence. Its adapter now closes four exact primary-key
queries: publication, high-water, absent deterministic audit and retained v2
evidence. It renders publication, high-water, audit and consumed-evidence effects
together through the real mutation templates into `KernelTransition`. The
business limits remain four rows / four mutations / 128 work units; common
audit-capacity finalization remains separate. No unused consumption recipe is
returned, and a local installed file alone is not publication authority.

## Registration read, effect and write-proof integration

Registration now produces actual `BoundedQuery` / `CompleteIndexQuery` objects,
including exact new-credential/audit absence and the real selected-high-water
field join to the published trust predecessor, plus the exact v2 evidence PK.
Its mutation adapter renders credential creation, challenge consumption,
evidence consumption, audit insertion and any sibling invalidations through
existing templates into `KernelTransition`: four to 36 business mutations.
Independent evidence pins remain mandatory; it is not a keyless kernel.

The existing complete-query dispatcher, database acquisition and proof engines
now admit these exact source families:

| Enrollment | Complete roles | Distinct read heads | Largest result |
| --- | --- | --- | --- |
| Ordinary | Credential-ID history; pending publication absence | 2 | 1 row per role |
| OIDC first enrollment | Both ordinary roles; all-status user history; live user registration challenges | 4 | Selected challenge plus at most 32 siblings |

The role inventory follows the actual closed enrollment mode. Every query is
rebound to its actual credential/user, sibling hints and one cutoff before SQL.
Hint lengths are overflow bounds, never proof of population completeness.
Acquisition uses the real counted heads, interval frontiers and exact primary
fetches; verification reconstructs the roots and joins every returned index
member to its primary row. Empty ranges still need proofs. Shared read/write
verification also uses the exact family, without a new budget or proof token.

The private planner acquisition now joins the actual mixed-query read path,
genuine registration kernel, common capacity query/finalizer and indexed-primary
mutation-frontier acquisition. It owns the request and independent pins/root
expectations before callbacks, compares observed primary and counted heads to
those expectations, and bounds the database cutoff against admitted time and
deadline. The counted read phase retains all source write heads, while read
verification checks its exact family; the actual write engine then reconstructs
the affected primary and counted before/after roots. Read and write acquisition
share one physical ledger and original work allowance, with a closed mutation
trace. The returned acquisition object is ordinary observations, not a signed
plan, authenticated-root token or commit authority.

Registration's business bounds remain 112 rows / 40 mutations / 1,024 work units,
plus exactly one framework capacity row, one mutation and two work units. The
ordinary/OIDC query programs have eight/eleven business query objects, with
maximum row sums eight/43. Revocation's existing family and global resource
allowances are unchanged. Both consumers now declare their purpose-specific v2
evidence types; no v1 reinterpretation is permitted.

The attestation core also has a private shared-work path for actual parsing,
hashing, canonicalization and cryptographic verification. Source inputs are
bounded and native calls guard the meter; JSON/CBOR/X.509/EC/RSA internals and native
allocations are **not** represented by invented hash/byte/node charges. These
changes do not establish whole-process CPU, memory or deadline guarantees.

## Completion read, effect and write-proof integration

The private completion acquisition uses the four existing exact primary-key
business queries plus the common audit-capacity query. It does not invent a
complete-range family. The actual primary proof engine must authenticate all
selected rows and absences against independently expected roots before the
completion kernel consumes installation evidence or derives its four effects.
The common finalizer adds the capacity mutation before write-root derivation.

Completion explicitly captures all three publication index heads: bundle
digest, status and generation. These must match independent expectations from
the same checkpoint. The indexed mutation engine then reconstructs primary
and counted before/after roots, including unchanged index keys whose row
digest changes. The private trace admits only this write-head inventory and
source-derived mutation-frontier reads, not complete-range queries or broader
table access. Existing global and operation bounds remain unchanged.
Counted-head and write-frontier acquisition share the same physical ledger;
ordinary primary-key/proof SQL retains its existing separate bounds. Real
primary-proof evaluation is charged to the remaining shared work allowance,
not treated as proof of whole-process CPU or all-SQL accounting.

Original installed bundle/state and signed evidence bytes, committed-stage
ancestry, target and installer pins remain mandatory inputs. The database
cutoff is joined to independently supplied time/deadline. The acquisition
returns ordinary observations, not a signed plan, evidence-storage permission,
authorized commit, registered kernel or physical-installation proof.

## Aggregate trust-stage integration

The stage manifest now represents the aggregate's real read/write tables and
narrow INSERT/UPDATE templates, bound assertion receipt and approval policy.
It replaces the obsolete four-row/one-write declaration with the already
defined aggregate ceiling: 192 business selections, 136 final mutations and
2,048 semantic work units, plus the one common capacity row/mutation and two
framework work units. Global physical/proof limits do not increase.

Five complete base ranges prove the live trusted-credential population, live
global registration challenges, absence of pending publications, absence of
candidate-bundle history, and absence of the candidate generation or a newer
one. Each sorted withdrawal adds four ranges: pending and active bound sessions,
active grants and approved control-plane approvals. Empty ranges still require
proofs. The query family has five read heads without withdrawals and eight
with withdrawals; the acquisition also retains all eleven potential write heads.

The exact `query_hints` object contains `live_credential_ids`,
`registration_challenge_ids` and `withdrawals`; each withdrawal contains its
`credential_record_id`, `oidc_session_ids`, `approval_grant_ids` and
`control_plane_approval_ids`. IDs are sorted and unique. Hints bound overflow
and enter the request's business intent; actual complete proofs and prestate
population comparisons prevent them from authorizing omissions. The existing
conservative sum of every query's maximum rows, including both session statuses
and exact-row scaffolding, must still fit 192. Distinct-address shared limits
are additional checks, not fresh per-credential allowances.

The actual query adapter binds signer/challenge, selected high-water/publication
predecessor, actor and optional approver, candidate publication absence and all
deterministic audit absences. Its mutation adapter renders the merged aggregate
through the source templates. A private planner acquisition now verifies the
pinned, stage-bound assertion receipt before SQL, joins observed primary and
counted roots to independent expectations, then performs these reads, effects,
capacity finalization and real write-proof acquisition on shared ledgers. The
database cutoff is checked against both admitted time and assertion expiry;
clock callbacks preserve the meter on success and failure. This clock guard
also covers the existing private registration/revocation reads.

Candidate admission now takes the original signed bundle, independently
configured key/schema/time and signing-key digest, not caller-supplied
classifier roots. `authority_webauthn_trust_candidate.py` invokes the real trust
core verifier and joins its decoded canonical envelope, digest, sequence,
rollback epoch and signing key to the owned staged arguments. Only roots from
that verification reach the aggregate classifier. This happens before SQL;
the bundle validity interval is checked again at the database cutoff. It does
not establish request permission, current database roots or committed state.

The trust core's private shared-work path accounts for actual source-visible
copies, encodings and hashes on the acquisition's existing allowance. Bounded
native JSON/schema/X.509/Ed25519 operations guard meter continuity but remain
outside that accounting, as with the attestation core. Public default behavior
and existing input/resource ceilings are unchanged.

## Admission and execution still required

Admission has configured read-only and live plan-production owners with
purpose-scoped measured configuration, but no durable evidence INSERT owner. Final registration
still needs its configured acquisition owner. Caller-supplied current roots, signer
pins and request authority remain independent prerequisites, not values
authenticated by copying.
Trust staging still needs its independently configured request/candidate-key
owner and signed-plan/execution integration. Completion needs its independently
admitted committed-stage/physical-installation owner and actual readback wired
to the evidence producer.
Registry and public operation admission, authorized atomic execution, terminal
witnessing and recovery remain pending. The generic evidence signer and ordinary
row/acquisition results cannot fill those gaps or repair service startup.

The evidence-storage integration must connect the private authenticated
acquisitions and genuine three-original signed-plan replay to durable retention and an
authorized atomic commit through authenticated root maintenance. The identical
unused verified-row no-op requires an explicit empty-mutation policy when its
configured kernel is eventually registered. No placeholder handler, keyless
kernel, new ACL or disabled closure check supplies this remaining integration.

The current v9 SQL execution loader accepts its existing v3 plan protocol.
Successor acquisition outputs cannot enter it by being relabelled as v3.
Although v3 can represent the primary INSERT/no-op delta, its closed payload and
kernel interface do not retain or reverify the original ceremony/installation
bytes, historical context and independent purpose pins. Its assertion-evidence
slot cannot carry these different purposes, and re-signing a stored payload is
not genuine semantic replay. Durable original-input/context and signed-plan
custody, historically admitted recovery and executor admission are required
before these outputs can authorize a write; the revocation-only v4 protocol is
not interchangeable either.

Broad fixtures and full verification remain deferred to the consolidated frozen
build. Production acceptance additionally requires independently operated
signing, witness and measured-runtime infrastructure, which is not provisioned.
