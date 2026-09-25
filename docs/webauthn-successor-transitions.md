# Successor WebAuthn transition implementation

Status: source `.103`, implementation only. All six WebAuthn successor operations
now have genuine configured programs in a separate `typed-successor-planning`
registry. This closes the source program inventory, not verified import/runtime
startup or public operation admission. Legacy kernel/planning inventories and
legacy service, SQL execution and witness gates exclude these successors.
Revocation and the two evidence-admission programs produce signed originals;
registration finalization, trust staging and completion now also have separate
signed-plan owners and fixed registry `plan_factory` entries. Their base factories
remain read-acquisition owners. The new plans commit canonical original proofs,
inputs and full evaluation context and genuinely replay them before signing and
after signature verification. All source remains unbuilt and unexecuted.
An optional signed policy now maps these three operations to their real read,
signed-production and configured raw-four verification owners through private
service factories. Authenticated invocation/transport, custody and
successor-execution integration remain unfinished; independent authority and
release gates remain. The three transition operations now also have genuine
configured verifier root observation, not continuing root-currentness authority.

## Genuine successor program selection

`authority_successor_programs.py` declares fixed lazy factories, selected through
the actual registry rather than placeholder legacy kernels. Revocation and
evidence-plan configuration mappers select their real configured producer
factories. Evidence acquisition and retained replay also select the same
purpose-fixed `EvidenceAdmissionKernel` factory before invoking its genuine
original-input computation on the caller's work.

`authority_webauthn_transition_planning.py` supplies
`RegistrationTransitionPlanner`, `TrustStageTransitionPlanner` and
`TrustCompletionTransitionPlanner`. Their actual `acquire` methods call the
existing private proof/effect workers within the shared guarded read scope;
results return only after normal cursor, transaction and connection exits.
Revocation, registration and stage use complete-query traces; completion uses
counted-write tracing; the two evidence-admission operations use ordinary
exact-key traces. No replacement allowance or caller-supplied proof result is
introduced.

These three base owners return ordinary acquisition/retention observations.
Configuration, request/current-root/time authority, assertion/capability bindings and committed
stage or physical-readback provenance remain independently admitted inputs.
Their separate fixed `plan_factory` entries construct the actual
`TransitionPlanOwner` described below. Registry selection does not supply
public invocation, successor reservation, one-use capability, authorized atomic
execution, recovery or independent production infrastructure. Earlier revision
sections below describe their respective source checkpoints, not later closure.

## Independent successor root observations

Source `.103` adds `TransitionRootReader` and its measured-configuration mapper.
Before connection callbacks, the reader owns and commitment-validates the typed
request. Its actual source operation/mode selects all primary tables and full
potential counted heads. Primary SQL uses one globally sorted table union;
returned observations preserve the business and authorization classes.

Exactly two root SELECTs, separate from connection/identity/ACL admission SQL,
run inside one actual PostgreSQL 16 SERIALIZABLE READ ONLY DEFERRABLE snapshot.
They use the existing source-exact verifier privilege surface and original
cumulative work/physical ledger. Counted reads share the actual private
head-reader validation and math, with no fabricated complete query or cutoff.
Normal cursor and transaction/connection exit plus a closed-handle check precede
return. The source contract separately revalidates and owns root/head JSON
projections; neither records nor projections are authority tokens.

The service owns the request before measured callbacks, holds protected verifier
database settings, captures generation last and rechecks active generation after
the closed read. This supplies root observations without admitting request
provenance, holding roots current for a later action, or changing ACLs, network
routes or execution. Authenticated invocation/transport, durable custody,
reservation/capability/atomic execution and recovery remain unfinished, as do
independent infrastructure and consolidated frozen-build verification. Source
remains unbuilt and unexecuted.

## Signed transition policy and configured handoff

Source `.102` adds optional `webauthnTransitions`, schema
`serverware.policyAuthorityWebAuthnTransitionPolicy/v1`, with exactly the
`registration`, `stage` and `completion` slots. Absence grants no transition
authority; null disables that fixed operation. Each enabled slot pins its actual
operation, explicit canonical Ed25519 raw key/SPKI and bounded evidence/assertion
age, clock skew and plan age. Registration pins signer identity and RP/origin
equal to the configured WebAuthn values; completion pins installer identity and
target. Stage pins the candidate signing-key ID and exact development/approval
flags. It deliberately has no `signerIdentity` field: the mapper joins its
explicit assertion key/SPKI to the actual verifier role, then derives session
identity from the held configuration digest and role measurement/attestation
pins. Storing that derived identity inside the configuration would be circular.

The signed service loader validates this extension after actual root-signature,
generation and role-topology checks. The artifact generator retains its separate
canonical/schema/signature-shape boundary; it does not gain root-signature
authority. Both accept exactly the old payload plus either or both independent
evidence/transition policy blocks, with no unknown fields or fallback policy.
The measured mapper captures the full configuration and launch binding, checks
the actual configuration digest, source query manifest, selected planner
allowlist and role pins, and holds database/policy scalars before key callbacks.
It selects real registry base and `plan_factory` implementations, or constructs
the actual public-key-only `TransitionPlanVerifier`, on the same work allowance.

Private service factories hold measured configuration and any existing signer,
check active launch, read only the protected planner descriptor when needed,
and snapshot generation last. The raw-four handoff owns independently supplied
history before launch/key callbacks; configured admission joins every policy
and key pin before actual signed-plan/proof/semantic replay. Neither received
context nor current configuration enrolls historical request, root, cutoff,
capability or committed-stage authority. Verification samples no replacement
clock and renews no plan lifetime.

These additions do not expose a public/network route, retain these plans or
execute business mutations. Authenticated invocation/transport, durable custody,
current-root/reservation/capability/atomic execution and recovery remain pending,
alongside unprovisioned independent infrastructure and deferred frozen-build
verification. All source remains unbuilt and unexecuted.

## Signed transition plans and held production owners

Source `.101` adds the separate
`serverware.policyAuthorityWebAuthnTransitionPlan/v1` payload and
`serverware.policyAuthorityWebAuthnTransitionPlanEnvelope/v1` envelope,
without relabelling any legacy or evidence-admission protocol. The canonical
raw-four result contains the signed envelope, original proof record, original
inputs and full evaluation context. Its closed 14-field payload binds all three
detached byte commitments/counts, operation, source, configuration, planner
identity/SPKI and original issue/expiry times. The context preserves the five
independently supplied plan expectations, including the complete proof policy,
request, input commitment, roots, counted heads and historical cutoff.

`authority_webauthn_transition_plan.py` genuinely replays primary/count/query
proofs, original-input semantics, capacity and indexed writes before signing.
Verification authenticates the planner signature and all detached commitments
before decoding the context, comparing it to independently owned expectations
and repeating the same replay. Context bytes and signatures do not admit their
own historical authority; historical verification does not renew a live window.

`TransitionPlanOwner` holds an actual fixed read owner and separately admitted
planner signer/pins. Its `produce_registration`, `produce_stage` and
`produce_completion` methods own caller graphs before callbacks and preserve one
actual live window through acquisition, replay, pre/post-sign checks and return.
Expiry is clipped to the original evidence/assertion expiry, caller deadline and
configured plan age; original policy time/deadline and database cutoff are not
rewritten. After normal read-scope exits, an encoding-only packer supplies bytes
to the signer, avoiding an extra offline replay while granting no proof authority.
All phases use the original work allowance.

These three signed-plan owners still need service-configuration mapping,
authenticated invocation/transport, durable raw-four custody, successor
reservation/capability/current-root/atomic execution and recovery. Raw proof
records contain selected rows and remain inside the semantic/storage boundary,
not a public response or witness request. No public business path or legacy
executor is enabled. Source is unbuilt and unexecuted; independent production
infrastructure and consolidated frozen-build verification remain required.

## Unsigned transition proof records and replay

Source `.100` extends the three existing `acquire_originals` methods without
changing ordinary `acquire`. After the real read scopes close,
`authority_webauthn_transition_proof_production.py` packages the acquisition as
canonical `serverware.policyAuthorityWebAuthnTransitionProof/v1` bytes and invokes
`authority_webauthn_transition_proof.py` for genuine offline replay before return.
The result keeps the acquisition, input bytes/digest and semantic observations,
and adds `proof_bytes` and `proof_digest`; none is an authority token.

Replay first joins the request, input commitment, historical database cutoff,
primary roots and full potential counted-head inventory to independently held
expectations. Actual primary membership and counted-complete-query proofs precede
the original-input semantic replay. Registration and stage regenerate their
source query declarations and bind ordered query addresses to the genuinely
joined leaves; completion uses its actual exact-key queries. Real kernels,
capacity finalization and complete effect/work comparisons remain mandatory.
Write derivation repeats the original read proofs, then invokes the actual
indexed-write engine on those semantic mutations and compares both after-root
classes and every counted head. Only the actual read/write subset enters the
counted engines; unused potential heads are validated and preserved unchanged.

Encoding, proof math, signatures required by the semantic workers, comparisons
and remaining-clamped mathematical work share the original cumulative allowance.
The record is unsigned: it creates no new signed plan, admitted historical or
current-root authority, custody, reservation, execution capability or public
business route. The `.98` registry split and legacy exclusions are unchanged.
Source remains unbuilt and unexecuted; release and independent-infrastructure
requirements remain in force.

## Original inputs and replay for the three transition owners

Source `.99` adds `acquire_originals` alongside each unchanged `acquire` method.
It owns invocation graphs before callbacks, encodes and hashes the original-input
record before database acquisition, and waits for all genuine read scopes to
close. Before returning, it reruns the actual semantic worker, regenerates and
validates query observations, finalizes audit capacity and compares complete
mutations, result and both work totals with the acquisition. All steps spend the
same caller allowance. The returned carrier contains the actual acquisition,
original input bytes/digest and ordinary replay observations, not proof authority.

The registration record has an empty input graph because its original evidence
is already bound in the request. Stage retains its original candidate bundle,
assertion and verification context. Completion retains only the original
installation envelope, installed bundle and rollback-state bytes; committed-stage
history, installer/target policy and time remain separately admitted inputs.
Completion reuses the actual database cutoff, without inventing a new observation
instant. Decoded records do not enroll keys, roots or historical authority.

This is a foundation for signing, not signed plans for these three operations,
full offline primary/count-proof replay, durable custody or execution. Genuine
proof acquisition remains in the existing read path; the new semantic replay
does not replace those proof engines. The `.98` six-program registry split and
legacy exclusions are unchanged. Source is unbuilt and unexecuted.

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
The database facade now exports `admit_webauthn_registration_evidence` and
`admit_webauthn_trust_installation_evidence` as genuine dispatch-only APIs.
Registration accepts the evidence digest, registration challenge, published
predecessor and optional OIDC session identifiers; installation accepts the
evidence digest and publication identifier. Both submit the fixed semantic
request and return the actual authority-dispatch result. They accept no row,
proof, connection, capability or caller-supplied business intent and perform
no SQL. Execution belongs to the fixed database executor, not a second Python
INSERT implementation. Existing controlled-writer wrapping and privileged-role
dispatch guards still apply.

The configured metered kernel below is not installed into the legacy registry.
All six missing-kernel closure failures remain; operator-role admission stays
denied. Completing the callable API surface does not repair startup.

## Shared metered evidence kernel

`EvidenceAdmissionKernel` holds one fixed operation's evidence public key,
identity/SPKI, age/skew and RP/origin or installation target. Construction is
inert; calls cannot replace those pins. Its explicit `queries_on_work` and
`transition_on_work` methods call the real source recipes and original-input
computation. There is no unmetered fallback or placeholder registry entry.

The shared computation owns request, selected rows and independent input/key
expectations, rechecks request/operation/input commitments and the actual SPKI,
decodes original ceremony or installation bytes, and invokes the genuine
purpose-specific verification and transition logic. It returns the actual
kernel, regenerated queries, input commitment and business work total. It
accepts neither expected mutations as computation input nor a successful proof
or attestation carrier.

Live acquisition holds this configured kernel before SQL and commits its actual
original inputs before reading rows. Genuine root, primary-membership and query
checks still precede the transition. Its regenerated queries are joined back
to the actual SQL observations before real primary-write/root derivation.
Retained replay uses the same kernel, but first owns the complete historical
expected transition and independently compares all effects and work totals
after computation. Both paths spend the same original allowance; the added
real capture, hash and codec work receives no replacement budget. These
interfaces prepare genuine configured planning integration without relabeling
the separate plan protocol as v3 or bypassing capability/current-root execution.

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
these semantic workers. Original-input custody and authenticated material
lookup are described below; authorized executor/recovery integration remains
missing. V3 cannot silently acquire these fields, and
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

## PostgreSQL plan custody

Source `.89` adds `policy_authority_webauthn_evidence_retained_plans`, a separate
twenty-column immutable metadata table. Its sole primary key is the complete
retained-record digest. It stores all three original byte strings as canonical
base64url, their byte counts/hashes, planner/evidence key fingerprints, plan and
request/configuration bindings, source revision and the first retention time.
The source contract and schema fingerprint bind this exact inventory.
Content addressing is not a logical-attempt reservation or exactly-once
execution: different authenticated records can describe the same operation.
No v3/v4 parent, capability or fence is invented for these records.

The private `persist_webauthn_evidence_plan_record` and
`read_webauthn_evidence_plan_record` APIs take independent historical expectations
and actual pinned public keys. Both perform genuine three-original replay;
neither accepts a successful-verification carrier as authority. They require
the actual PostgreSQL facade and an existing SERIALIZABLE, read-write,
non-deferrable planner-writer transaction. Connection/transaction continuity,
driver callbacks and cleanup remain guarded on the existing work allowance.

Writes keep insertion and complete readback inside a nested savepoint. The
live storage window is clipped to the unchanged original deadline and signed
plan expiry; current freshness checks do not rewrite historical issuance,
evaluation time or cutoff. An identical content-addressed retry compares every
immutable field, preserves the first stored timestamp and still passes current
write freshness. Stored timestamps are also validated against their original
interval. Historical reads reverify the original material without sampling a
new clock or treating an absent record as rollback/retry authority.

Returning from these helpers is not a durable commit receipt. The outer
transaction remains caller-owned; post-savepoint failures require caller abort,
and a post-exit check cannot undo a commit already made by a driver. Observed
transaction identity cannot detect a hostile driver's hidden commit-and-BEGIN.
No business evidence row, root transition, execution reservation or terminal
witness is created by retaining a plan.

The new table has source-fixed SELECT/INSERT-only planner-writer privileges;
runtime/executor access follows the existing read-only immutable-table rules.
Generic immutable guards reject UPDATE/DELETE, while role ACLs deny TRUNCATE.
SQLite explicitly rejects insertion. Existing destructive migration paths
reject this custody table and require a separately reviewed migration instead
of dropping or synthesizing retained originals. No schema or grant has been
installed, and no transaction has been executed in this implementation batch.

## Configured plan custody owner

`authority_webauthn_evidence_plan_persistence.EvidencePlanPersistence` holds one
immutable configuration: writer endpoint and timeout, database role/TLS
identity, fixed operation, planner/evidence public keys and identities/SPKIs,
configuration commitment, evidence/plan age and clock skew, and RP/origin or
installation target. Construction is inert. Its fixed `persist` and `read`
methods cannot receive replacement keys, a connection, a signer, a clock or an
operation callback.

Each call owns its bounded original-byte references or retained-record digest
and all eighteen independent expectations before native callbacks. It joins
the held configuration and purpose pins, including the same configured age for
plan and evidence, and checks both actual public-key SPKIs. Neither current
configuration nor a stored evaluation context establishes historical request,
root, time or key admission. The actual store still performs full original-byte
signature, semantic and proof replay on the same invocation work.

The genuine database facade and its existing registry gate are imported before
any socket opens. The bounded PostgreSQL connection uses the actual writer
runner for role/TLS/privilege admission and a SERIALIZABLE, read-write,
non-deferrable outer transaction. The store keeps its nested savepoint. Results
return only after normal outer transaction and connection exits and a closed
handle check. The opener closes any returned handle if its work guard rejects
it. The shared native callback now checks work in `finally`; failure cleanup
still runs even with invalid work. An uncertain commit or failed post-exit
check is not evidence of rollback and does not authorize an automatic retry.

The fixed measured-configuration mapper requires the selected operation in
the signed planner allowlist and its explicit enabled evidence purpose policy.
It checks planner/writer process pins and writer-to-planner key aliases, then
constructs the actual public keys. Relevant scalar settings are held before
native key callbacks. The private planner-writer service factory owns the
configuration before active-launch and protected writer-descriptor callbacks,
and captures generation last. No private signer, route, policy extension,
permission expansion or registered handler is added.

Scoped cross-process retention and authenticated material lookup are described
below. Independent historical provenance, capability/current-root admission
and authorized atomic execution/recovery remain open.
The six missing-kernel startup boundaries remain. The two dispatch-only handler
APIs are now present, but this source has not opened a connection or proved a
committed write.

## Verifier-side original-plan handoff

`EvidencePlanVerifier` holds the same thirteen immutable operation, key,
identity, configuration and purpose-policy pins used by writer custody, without
the writer's DSN, timeout or database identity. Its fixed `verify` method owns
all three original byte references and independently supplied expectations
before key callbacks. It joins every configured pin, checks both actual SPKIs,
then calls the genuine retained-plan verifier: original context equality,
planner/evidence signatures, semantics, queries, primary proofs and resulting
roots are all rechecked on the same remaining work. No verification-result
carrier is accepted as an input.

The verifier mapper owns and checks the full root-admitted configuration and
launch generation, requires the verifier process pins, and uses the same
planner/purpose mapping as the writer. The writer separately retains its
planner-alias, role/TLS and timeout checks before that shared key path. Neither
mapper infers an evidence key from the generic verifier role or accepts a
per-call policy override.

The private verifier service handoff captures all eighteen independent
expectations before factory, launch or key callbacks. Its factory owns measured
configuration before checking the active verifier launch and captures generation
last. No descriptor, private signer, database, new clock sample, network route
or registry activation is introduced. Returned observations establish only the
local historical replay performed by this call, not original-custody durability,
historical input provenance, root currentness, a one-use capability or execution.

## Signed retain-only custody handoff

Source `.93` adds two separate flat controls, not legacy internal/v3 envelopes
or revocation-v4 requests. The 19-field
`serverware.signedPolicyAuthorityWebAuthnEvidenceCustodyIntent/v1` commits the
retained-record identity and the exact byte digest/count of four detached
originals: signed plan, original inputs, evaluation context and independently
supplied historical expectations. The 13-field
`serverware.signedPolicyAuthorityWebAuthnEvidenceCustodyRelay/v1` commits the
complete original intent's digest/count and the same retained-record identity.
Each binds source, fixed retain/relay purpose, configuration digest, generation
sequence/digest, one of the two evidence-admission operations and issue/expiry
times. Each signature uses its own schema as the framing domain.

Controls are canonical, losslessly decoded JSON bounded to 4 MiB, 4,096 nodes
and depth one. Each detached original retains its existing 64 MiB ceiling;
these local ceilings do not expand the cumulative work allowance or promise
that combined maxima fit. Actual raw-byte hashes, codecs, captures, signatures
and repeated plan/proof/semantic replay all use the same remaining work.

The verifier producer owns independent history and genuinely verifies the
three-original record before signing its intent. The planner authenticates the
intent and its configured scope, checks all four original-byte commitments,
then decodes the authenticated history and repeats genuine retained-plan replay
before signing a relay. The receiver verifies both controls and repeats that
same replay; no successful-verification carrier can skip it. Actual verifier
and planner raw32 keys must differ, and each producer checks its private/public
pair. Signing reserves final output work beforehand and rechecks the owned
canonical graph afterward. These checks do not enroll keys or establish the
upstream authority of the verifier's historical inputs.

Each opened local monotonic/epoch window is nonrenewable. Relay signing retains
the authenticated intent's window; the receiver tracks both control windows.
Control age is at most 30 seconds and allowed skew at most five seconds, with
stricter supplied bounds preserved. Intent expiry cannot exceed the original
signed plan expiry or historical deadline; relay expiry cannot extend the
authenticated intent. Pre/post-signing and final verification checks retain
the original times. A new invocation cannot renew a signed lifetime, and a
late rejection cannot undo a signature or establish that a commit did not occur.

`authority_webauthn_evidence_custody_persistence._persist_on_configuration`
composes this handoff with the existing held writer configuration. It verifies
both original controls and genuinely replays the detached originals before the
database import gate or connection. It then decodes the authenticated history
again and joins it to the held purpose policy; no returned verification carrier
supplies the store's expectations. The fixed private operation invokes the real
store inside the actual writer's outer transaction and joins the persisted
record digest to the authenticated controls. Both original control windows
are checked before and after storage while the transaction is still owned,
then again after normal outer exit and connection close. The store's genuine
replay and nested savepoint remain intact. Post-commit expiry or delivery
uncertainty cannot be reported as rollback or automatic retry authority.

These controls confer no registry enablement, execution capability, terminal
witness or durable signed acknowledgment. Content-addressed idempotency is not
exactly-once signing, delivery or execution. The configured serving integration
below preserves those limits and supplies no automatic retry.

## Configured two-hop custody serving

Source `.94` connects the fixed configuration mapper, actions and detached
transport to private `AuthorityProcess` methods and role-restricted socket
branches. The verifier requests a planner relay over the original intent,
plan, inputs, evaluation context and independent history. It genuinely verifies
the returned original relay. A separate explicit call forwards those same five
originals plus the relay to the planner, which authenticates and replays them
before sending them to the writer. Relay preparation never falls through into
forwarding or regenerates controls for a retry.

Service admission requires the exact role/mode and measured configuration. It
owns the full payload/digest and any real signing handle before active-launch,
descriptor or key callbacks. Only the writer reads the protected writer DSN;
generation is captured last. The mapper rechecks configuration/launch bindings,
the fixed operation allowlist, purpose policy, distinct pinned role keys and
verifier-to-planner-to-writer peer topology. Each invocation uses one existing
source work allowance through its captures, signatures and repeated replay.

Distinct fixed message types select preparation, forwarding or retention and
one of the two purposes. All five or six lengths are admitted together before
body allocation: each control is at most 4 MiB, each detached body at most
64 MiB, and their aggregate at most 64 MiB. Exact peer checks precede incoming
prefixes or outgoing bodies. The complete request and EOF precede the server's
single work allocation. Each connection has its own absolute total deadline,
bounded writes, request half-close and mandatory response EOF; there is no
pipelining, fallback or automatic next hop from preparation.

Configured callers genuinely authenticate controls and replay originals before
each request send; the writer does so before database admission. Original
control windows remain in force across I/O and response verification, rather
than being renewed by later replay. The actual writer outer transaction commits
and the connection closes before its response is sent; a nested savepoint alone
cannot release a response. The fixed response contains only the canonical
retained-record digest and positive retention timestamp. Callers join the
digest to their genuine replay and reject timestamps beyond the allowed clock
skew, but an identical retry may report an older immutable first-retained time.
This unsigned peer response is not a durable signed acknowledgment or an
execution result. A late timeout, expiry or lost response leaves an uncertain
outcome, not rollback or automatic retry authority.

All six missing registry entries remain unactivated. These custody branches do
not supply public business invocation, independent request/root provenance,
one-use capabilities, reservations or authorized atomic execution/recovery.
The separate authenticated lookup below retrieves material without establishing
historical key or root admission. External signing/witness/runtime
infrastructure and release admission remain required. This implementation is
source-only, unbuilt and unexecuted; no runtime proof is claimed.

## Independent verifier root observations

Source `.96` adds an actual verifier-owned PostgreSQL 16 SERIALIZABLE READ ONLY
DEFERRABLE snapshot for the two evidence-admission operations. One fixed query
reads only authenticated primary-root metadata: five source tables for
registration (two business, three authorization), or three for installation
(one business, two authorization). Their writable evidence-receipt table has
no counted profiles; read-only tables may have profiles used by other operations.
Exact source ordering, row counts, full root metadata and the query
manifest are checked; the extra-row sentinel cannot silently hide corruption.
No business rows, evidence records or counted heads are read by this owner.

The service holds its measured configuration and protected verifier DSN, then
the mapper checks the actual launch bindings and explicitly configured evidence
policy. The real connection must match the signed verifier role and TLS identity
and pass the existing source verifier privilege check. The query has its own
source-derived physical acquisition caps and shares the original validation
work allowance. Normal cursor/transaction/connection exit and a closed-handle
check precede release of the full observations. No privilege grant or SQL write
is added.

Custody-intent signing now performs this real read and compares its metered
four-field root projection to the independently held historical before-roots.
After the read closes, the service rechecks the active launch and unchanged
generation before passing the same held configuration and signer to genuine
plan replay/signing. It never replaces historical roots, request, input
commitment, database cutoff or time fields with values copied from a plan or a
current observation. Changed roots reject new intent production; historical
retained-original lookup remains a separate operation.

This is an independent snapshot, not a reservation or a guarantee that roots
remain current through signing, later custody or execution. It supplies neither
historical request/time provenance nor successor execution authority. The six
missing registry entries and independent production infrastructure remain
unfinished. The implementation is unbuilt and unexecuted.

## Authenticated evidence-plan production exchange

Source `.97` connects three private service methods and a fixed detached planner
branch. The verifier acquires its genuine independent root snapshot before
signing a closed 14-field request control over the original 8-field production
context and canonical input bytes. Held measured configuration, explicit purpose
policy and launch generation bind the exchange. The planner authenticates this
request before invoking the actual configured original-input production owner;
no received success observation substitutes for proof acquisition or semantics.

The planner's separate 18-field response control binds the original request
control and all three returned originals: signed plan, inputs and evaluation
context. The plan signature alone does not cover that raw context. Response
control expiry equals the original request expiry; the context deadline cannot
exceed it. Signed plan expiry is exactly the minimum of the context deadline
and context issuance time plus configured plan age. Permitted clock skew can
leave that plan expiry earlier than the context deadline. The client separately
enforces current plan freshness and repeats actual live proof and semantic
replay under the original request window; the response control cannot extend
the plan lifetime. It returns all four original byte strings, preserving the response signature;
it does not return independently admitted historical expectations.

Both directions admit every length and the aggregate 64 MiB bound before body
allocation, with 4 MiB control limits, exact peer checks, one absolute connection
deadline and complete EOF. Server work is allocated only after request EOF;
the existing shared allowance covers authentication and production/replay.
This exchange does not automatically retain the result, admit historical
authority or execute it. All six registry gaps, public invocation and successor
reservation/capability/atomic execution requirements remain, as does independent
production infrastructure. No build or execution has validated this source.

## Authenticated retained-original lookup

Source `.95` adds the separate 13-field
`serverware.signedPolicyAuthorityWebAuthnEvidenceCustodyReadRequest/v1` control,
with purpose `read-evidence-plan`. One verifier signature binds the requested
retained-record digest, exact historical-document digest/count, current
configuration and generation, source, operation and issue/expiry times. The
planner forwards those same original control/history bytes to the writer;
there is no additional planner signature or write authorization. Producing a
lookup request cannot claim replay of originals that have not been retrieved.

The actual producer owns independent historical expectations and joins every
configured purpose/key pin before signing. Each receiver verifies the original
signature, canonical bytes and current scope, then the complete history
commitment before decoding that history and repeating the configured joins.
A fresh actual monotonic/epoch read window permits lookup after the historical
plan deadline expires, but renews neither that plan nor its evidence or retention
authority. Its source-capped control age preserves stricter role bounds and
the purpose's clock-skew bound; the same original window is checked around I/O
and after replay. Current configuration/source/generation must still match:
no historical key rollover, root provenance or policy admission is inferred.

The writer authenticates before the real database gate and invokes the existing
store's SELECT lookup and genuine three-original replay. It performs no
application mutation, but deliberately retains the existing SERIALIZABLE,
read-write, non-deferrable writer owner and privileges—not a database READ ONLY
transaction or reduced-privilege owner. Its result escapes only after normal
outer transaction exit and connection close. Both receiving clients repeat
actual configured signature/proof/semantic replay against the authenticated
independent history and join the derived record digest to the requested and
returned identities.

The response contains the original signed plan, inputs and evaluation context,
plus unsigned record/time metadata. The timestamp is checked against the
genuinely replayed plan's historical freshness interval and rejected if beyond
current time plus allowed skew; it remains informational, not a signed receipt.
All request lengths are checked before allocating either body: control at most
4 MiB, history at most 64 MiB, combined at most 64 MiB. Response raw3 lengths and
all metadata are validated before body allocation, with raw3 plus the 79-byte
digest/time metadata bounded to 64 MiB. Fixed peer checks, absolute per-connection
deadlines, request half-close and exact request/response EOF remain mandatory.
Each serving invocation allocates one source work allowance after complete
request receipt; its captures, authentication and replay share that allowance.

Missing or incomplete custody raises; a failed read is not proof of absence,
rollback or permission to regenerate/retry a write. Lookup neither inserts,
reserves, executes nor automatically retries. These private serving branches
do not enable public business invocation, repair registry startup or provision
external infrastructure. Implementation and verification remain source-only;
no runtime, durability or completed execution-recovery claim is made.

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
purpose-scoped measured configuration, but no authorized durable evidence INSERT
executor. Final registration, trust staging and completion now have genuine
configured acquisition, signed-plan and verification owners with private
service-configuration mapping; authenticated invocation, custody and successor
execution remain pending.
Current roots, signer pins, request permission, assertion/capability authority
and committed-stage/physical-readback provenance are still independent
prerequisites, not values authenticated by copying.
Source registry closure is implemented, but import/runtime startup is untested.
Public operation admission, authorized atomic execution, terminal witnessing
and recovery remain pending. Ordinary row/acquisition results do not fill those
gaps.

The evidence-storage integration must connect the private authenticated
acquisitions and three-original plan custody to configured transaction ownership
and an authorized business commit through authenticated root maintenance. The
configured evidence kernel explicitly permits the identical unused verified-row
no-op; successor execution still must admit that policy. No placeholder handler,
keyless kernel, new ACL or disabled closure check supplies this remaining integration.

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
