# ECR publication request and state planning

This component advances the original exact-image publishing workflow; it does
**not** enable AWS publishing in the app. It joins actual verified image content
to a closed ECR SDK request/response contract and proposes bounded upload-state
transitions. Ordinary app startup remains independent of this work and the
native pilot. Encrypted AWS credentials remain storage-only.

## What the planner must preserve

One publication concerns one exact manifest and all its unique blobs, including
the config blob. Repeated layer references retain their original order in the
manifest but do not require duplicate uploads. The publication scope retains
the application/principal, route, policy hash, credential generation, account,
region, repository, tag and publication identifier. Original wall-clock and
monotonic deadlines cannot be renewed by a response or a new signature.

The intended owner permits one active publication for the explicitly selected
application/repository scope and one active upload within it. It must never
select the latest approval implicitly. The pure planner does not implement that
cross-publication ownership rule or create an approval.

| SDK action | Content and state binding |
| --- | --- |
| `BatchCheckLayerAvailability` | Only requested subsets of the verified blob roster; successful observations cannot introduce another digest. |
| `InitiateLayerUpload` | Retain one upload ID and its advertised part size; no concurrent upload within the proposed snapshot. |
| `UploadLayerPart` | Require consecutive inclusive offsets and exact byte equality with at least one surviving verified-blob candidate. |
| `CompleteLayerUpload` | Require exactly one named surviving candidate and its complete expected length; validate the acknowledgment. |
| `PutImage` | Require every unique blob ready, the original manifest bytes and the exact selected tag; validate the returned image. |

Initiation contains neither a digest nor a tag, and its response contains only
an upload ID and part size. Therefore the planner must not invent scope echoes
or assign a blob by upload order. It narrows candidate blobs using actual part
bytes before proposing each send. See the official
[initiation contract](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_InitiateLayerUpload.html).

## Supported wire profile

`ecr_sdk_protocol.py` accepts only the five named actions with an explicit
matching account and repository. Strict JSON rejects duplicate and unknown
fields, invalid types and excessive nesting/work before constructing a result.
Part data uses canonical padded standard Base64, not Base64URL. Original request
and manifest bytes are retained; reparsing a manifest and serializing equivalent
JSON does not preserve its identity.

The supported profile caps request bodies at 16 MiB and decoded parts at
10 MiB. These are Serverware limits, not a claim that every AWS API limit equals
them. The AWS API and service-quota pages currently disagree about maximum
part size; real-provider acceptance must resolve supported sizes and small/final
parts. The advertised `partSize` is validated rather than ignored. See
[UploadLayerPart](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_UploadLayerPart.html)
and [ECR quotas](https://docs.aws.amazon.com/AmazonECR/latest/userguide/service-quotas.html).

Only complete, unambiguous HTTP 200 acknowledgments in the supported response
profile advance a proposal. This is deliberately stricter than some optional
members of the AWS model. Batch results must account for the requested digests;
nonempty failures or unsupported availability states do not establish success.
Provider errors, a lost response and an already-exists exception must not be
converted into success or automatic replay. Response limits account for JSON
escaping of the original manifest rather than assuming the enclosing response
is no larger than the manifest itself.

## Proposal is not permission

`ecr_image_custody.py` captures the actual verified streams into process-owned
Linux memory files and applies write, grow, shrink and further-seal restrictions
before returning them. Range reads check the retained file identity, size and
seals. Closing the owner releases those handles. Changes to the original stream
do not change the captured bytes. This is process-local content immutability,
not durable storage, attested execution or protection from a hostile process
owner modifying the program itself.

The planner performs no network, database or credential operations. A bare
verified image is only a point-in-time byte observation. The planner's
`read_blob` interface requires trusted access to those same immutable bytes;
an arbitrary callback reading the original mutable stage does not satisfy that
contract. The SDK harness uses the sealed capture owner above. The caller must
also supply trusted clocks.
Private constructors, immutable Python values and exact in-process request
identity are integrity conveniences, not an authority boundary.

An accepted proposal is not an authorized send. Re-evaluating the same immutable
inputs is reproducible; it cannot consume a grant or prevent replay of an old
state. Before any dispatch, an authoritative owner still needs all of:

1. Genuine exact-image review and hardware assertion verification, bound to the
   original publication and scope.
2. One authoritative parent reservation and atomic one-use grant handling,
   preserving the existing release/uncertain-outcome model. Standalone
   `jit.consume` is intentionally disabled; do not enable it as a shortcut.
3. Durable, compare-and-swap child reservations with their own actual request
   digests, ordering, bounded work and authenticated current state. Persist the
   pending state before sending; do not keep a database lock across network I/O.
4. Fresh policy, application, credential-generation and revocation checks before
   each final send, followed by dedicated AWS custody and exact-byte signing.
5. Durable acknowledgment/audit integration. A possible write with an unknown
   outcome terminates continuation; it does not clear an upload slot for retry.

Those changes belong in the existing authority contract, primary-row contract,
release transition kernels, transition registry, measured PostgreSQL writer and
Rust final-send path. A separate SQLite ledger or `approved=true` field would
not implement them. The generic AWS credential-release refusals stay in place.

### Approval-writer prerequisites

Tracing the actual approval path found a shared v9 writer defect: its stored
assertion check compared the capability's `WebAuthnReceipt/v1` digest with the
different, verifier-signed `VerifiedWebAuthnAssertionReceipt/v1` digest. Valid
producer output cannot satisfy that equality. The source now uses
`authority_store/webauthn_receipt_binding.py` in the existing executor guard to
recompute three distinct commitments: the capability receipt, the unsigned
verifier statement, and the complete signed evidence document. It also binds
the exact original fields to their stored columns. Existing signature admission,
current trust, expiry, challenge and counter checks remain required.

The connected source repair now accepts the application's actual
`approve_request` arguments and independently verified assertion evidence. It
derives the raw receipt from the original challenge and credential fields;
the writer retains its genuine capability receipt before the decision's
immediate foreign key. The credential reader supplies its actual stored trust
fields, and grant revalidation uses an explicit projection between the distinct
authority and JIT policy domains, without renaming either commitment.

Challenge receipts hash the verifier reader's original ten fields. The seven
additional retention fields remain present in the selected row and the writer's
full-row compare-and-swap; they are neither discarded nor silently added to the
historical receipt format. Credential binding retains its separate,
length-framed digest format. The reader, kernel and fresh/historical SQL guards
now share those explicit projection definitions.

The first decision can initialize its count only with authenticated aggregate
absence and an independently checked empty decision partition. Subsequent
decisions require the complete bounded voter roster and current eligibility of
each original committed vote. Thresholds up to 16, any-required-role semantics,
one-use review receipts, challenge/counter CAS and original deadlines remain
required. A committed replay checks retained history; it never backfills a
receipt, consumes another counter or renews a grant. Historical receipt and
capability custody remains framework-owned, not an additional business-table
permission for an ECR kernel.

This source connection does not enable ECR or prove the complete installed
authority path. The focused joined fixture begins with a pending approval and
synthetic admission/trust inputs; it does not exercise browser ingress,
`jit.request`, measured writer admission, a physical key or a provider. Genuine
cryptographic verification and actual transaction SQL within that boundary
must not be described as a completed native or production approval.

No installed SQL function, database schema, live grant, AWS capability or native
attempt is changed by this source repair. Updating an existing installed writer
also requires its exact function/manifest repair path; the ordinary app must
not silently reinstall authority functions on page load.

### Real request ingress, not a pre-created approval

The public `ensure_jit_approval_request` facade sends a URL, two JSON documents
and individual approver-policy arguments. The request kernel previously
required caller-supplied commitments, opaque IDs and a combined policy instead.
`authority_jit_request.py` projects the actual marshaled arguments into those
kernel inputs. The first ingress repair preserved raw signed arguments and
business intent; the private-v2 profile below supersedes that production input
shape before either commitment is created. Opaque IDs are deterministic, purpose-separated selections
derived from the authority request envelope; they are not custody receipts.

All three production callers supply the complete policy through
`db.jit_approver_policy_arguments`. The pure projection requires explicit RP and
origin fields instead of consulting mutable environment configuration. Its
policy shape validation does not replace the existing configured-RP, current
trust or assertion checks. Incomplete legacy policy arguments are refused.

This fixes an ingress-shape defect, **not the cold approval workflow**. Genuine
purpose-fixed sealing and authenticated opaque-value registration are still
missing. The stored ciphertext and review reader also need a matched opening
contract, and request/review capacity needs authenticated cold initialization.
Missing custody remains a refusal; the tests must not manufacture admission or
seed a pending approval and call that request-to-review acceptance.

The focused ingress target is `make verify-authority-jit-request`. It exercises
the real facade through dispatch capture, private input separation, pure
projection and actual query selection. It does not execute a successful writer
transaction, review, hardware approval, provider call or deployment. Main's
authority changes still require the separately reviewed retained-v9 migration;
the working ordinary app remains on its compatible UI-only release.

The initial October 12 ingress run passed **32 tests**: eight ingress, eleven
registry, ten policy-projection and three existing decision-component tests.
It used the retained Python 3.11.15 engineering image with network disabled,
read-only source and bounded resources; no build or download ran. All 15 pinned
source files were unchanged afterward and the disposable container was removed.
The first launcher attempt could not read its mounted private evidence directory
and ran no tests; mounting only the nonsecret runner file corrected that harness
permission issue. Both attempts are retained under
`serverware-operator-workspace-evidence/jit-request-ingress.dXd2u4HI`. No database
was started or accessed and no successful cold approval is claimed.

### Private request documents must stay out of signed plans

Sealing only the approval row is insufficient: the planner retains `typedRequest`
and the executor retains the exact request envelope. Including the original URL,
canonical request or display document there would retain plaintext independently
of approval storage.

The actual facade now selects `serverware.policyAuthorityPrivateJitWriterInput/v2`
before intent synthesis. Its transient private channel carries those three
originals; the public arguments use `serverware.jitRequestCommitments/v2`, the
three individual hashes and a commitment to the complete original marshaled
arguments. The actual service reconstructs and validates the originals before
creating the public-only intent and authority request digest. A caller cannot
choose a public hash while supplying different private bytes. Existing payload
and explicit approver-policy limits remain in force.

The planner and both durable writer entrypoints independently refuse old raw
JIT request profiles. They never redact or rewrite an already signed request.
Other operations retain their existing input contracts. The focused target is
`make verify-authority-jit-private-request`.

This is a privacy prerequisite, **not secure storage or a working approval**.
The private documents are still transient service inputs: no native producer
seals them, no opaque custody is admitted and no review-opening contract is
implemented by this change. Missing custody and capacity evidence still refuse
the request. No database migration, installed writer change, live deployment,
pilot, hardware action or provider operation is performed. The retained app
stays on its compatible ordinary-flow release; main is not a deployment bundle.

The focused private-profile run passed **40 tests**: eight new privacy groups,
eight adapted request-ingress groups, eleven registry, ten policy and three
decision-component tests. It used the existing Python 3.11.15 image with no
network, read-only source and bounded resources; no build, download or database
startup ran. All 20 pinned source files were unchanged afterward, and the
disposable container was removed. Logs and pins are retained under
`serverware-operator-workspace-evidence/jit-private-ingress.73a5hKuC`.
Writer tests establish refusal before database access, not successful persistence
or native admission. Independent source review found no raw-JIT bypass through
the operation-specific measured digest callers.

### Review storage and disclosure are separate responsibilities

The review history reader now selects only the ten decision-metadata fields
that its UI formatter consumes. It neither fetches nor decrypts historical
request documents. Four focused controls passed against disposable SQLite,
including a database authorizer that rejects private-column reads and invalid
ciphertext that would fail if the general approval reader were invoked. Existing
scope filters, current-request exclusion, ordering and limits are unchanged.

The pending native storage connection must preserve all three private inputs in
two purpose-separated ciphertexts: a versioned URL-plus-canonical-request
wrapper and the review display. The URL commitment alone cannot reconstruct the
request after restart, and the wrapper's digest is not the canonical request's
digest. Envelope bindings include the complete public request and original
expiry; opening later must not restart the pending lifetime.

Encryption is only the material step. A separate admitted native caller and
fresh native proof, atomic opaque/evidence/approval insertion, authenticated cold
capacity initialization, authorized review opening, and retained writer migration
are still necessary before this becomes a working request-to-review workflow.
The ordinary console must not perform that commissioning on page load.

The new `native_jit_review_material` implements the two randomized AES-GCM
envelopes with independent wrapped data keys, full request/scope bindings and
mandatory readback. `native_jit_review_owner` adds a purpose-fixed sealing state
machine: it validates the original private inputs, pins the configured policy and
key/channel identity, clamps the original deadlines, and burns each request before
encryption or output. Failed or uncertain output poisons the owner. It has no
review/open command. The broker's private dispatcher now connects the seal-only
owner to the actually provisioned helper key and completed service-token phase.
The retained Rust owner now connects an internal private preparation seam to
that actual broker exchange, preserving original private numeric bytes and
checking the complete returned pair and identity bindings. The authenticated
Rust RPC, signing path and writer are still missing; the private `Prepared` and
its unsigned output are not admitted evidence. The [private channel contract](native-broker-runtime-image.md#private-jit-sealing-channel)
records the package and process-test boundaries.

The focused run resolved 31 test groups across two snapshots: four metadata-history,
eleven material, eight owner and eight existing private-ingress groups. The first
material run passed ten groups; the remaining group's test helper accidentally
replaced explicit `None` with a valid fixture. A sentinel-only helper correction
left production code and assertions unchanged. That group and the two previously
unreached eight-group suites then passed; earlier passing groups were not rerun.
The tests use actual encryption and request codecs, with synthetic broker/channel
owners; they do not establish native admission or end-to-end approvals. Both runs
used the existing Python 3.11.15 image, no network, read-only source and bounded
resources. Source pins remained unchanged and disposable containers were removed.
Logs and pins are retained under
`serverware-operator-workspace-evidence/jit-review-storage.rJfXoBjq`.

The focused receipt checks require no pilot or build:

```sh
make verify-authority-webauthn-receipts
# Actual decision-kernel and policy-domain component controls:
make verify-authority-jit-approval
# For an already prepared disposable local Unix-socket PostgreSQL fixture:
SERVERWARE_TEST_POSTGRES_DISPOSABLE=1 make verify-authority-webauthn-receipts-postgres
SERVERWARE_TEST_POSTGRES_DISPOSABLE=1 make verify-authority-jit-approval-postgres
```

The PostgreSQL target also requires `SERVERWARE_TEST_POSTGRES_DSN`; it never
starts a database or falls back to the application's connection configuration.

The October 11 focused run passed all **12 tests** (three signed-producer/source,
five PostgreSQL and four retained optional-guard groups), plus the actual
rollback-only SQL program. That program preserves the no-assertion regression,
reproduces the old unassigned-record error, rejects genuine records under the
old cross-domain comparison, accepts them under the new guard and exercises
five denial controls. PostgreSQL 17.11/Python 3.11.15 ran in the existing pinned
engineering image with no network, read-only source and a disposable Unix-socket
database. The complete job took 16.237 seconds, exited zero without OOM, and
shut down cleanly; the test container was removed and source hashes were
unchanged. No build or download ran. Logs, source pins and execution evidence
are retained in `serverware-operator-workspace-evidence/webauthn-receipt-binding.4DjdDwvh`.
These are signed synthetic-input and actual SQL-guard results, not a complete
authority transaction, physical-key approval, provider request or deployment.

The follow-up JIT source regression run passed **54 tests**: 21 revocation
transitions, 21 work-bound controls, eight receipt-domain groups and four
optional-evidence groups, plus the emitted rollback-only SQL. It completed in
20.584 seconds with the same pinned, network-disabled engineering image and
read-only source; no build or download ran. The preceding focused run also
passed ten policy-projection and six reader-projection tests. Earlier failed
checkpoints are retained, not replaced: a missing first-decision aggregate
INSERT template, an incomplete disposable RBAC fixture, and a stale test-only
query-count oracle. Logs and per-run source pins are under
`serverware-operator-workspace-evidence/jit-approval-integration.H8suZhEl`.

The expanded joined fixture then passed all **eight groups** (three pure and
five PostgreSQL), for **78 passing focused groups** across this source repair.
It exercises genuine signatures, the actual fresh assertion CAS guard,
immediate receipt foreign key, first-decision initialization, threshold-two
approval and real grant revalidation. Refusal controls cover changed prior
voters, roles, trust, counters and writer commitments. Full retention-row CAS
drift and a late transaction cancellation roll back history and completion;
exact replay neither renews a grant nor backfills missing history. The eight
groups took 13.869 seconds; the complete disposable job took 18.299 seconds,
exited zero without OOM and stopped PostgreSQL cleanly. Both source manifests
were unchanged and the container was removed. Its RBAC root admission and
framework completion remain synthetic inputs, not a full installed-writer
acceptance result. No live deployment or real key/provider action followed.

## Verification scope

Run the pure protocol/planner checks without a provider or pilot:

```sh
make verify-ecr-publication-plan
```

The separate stock-SDK harness requires the existing pinned Boto3/Botocore
1.34.46 installation, with no install or dependency resolution during a test:

```sh
make verify-ecr-sdk-publication
```

Its scope is actual SDK serialization and response parsing joined to verified
fixture bytes, proposed transitions and independently checked SigV4. Transport
is intercepted in-process and sockets/DNS are prohibited. Public synthetic keys
are used explicitly; ambient AWS credential discovery is forbidden. It is not
hardware approval, a real authority transaction, TLS/CONNECT proxy transport,
durable crash recovery, Docker push or AWS acceptance. No test result from this
harness should enable an AWS UI permission.

## Verification checkpoint (2026-10-11)

The retained root run passed all **80 tests** against an unchanged source roster:
13 actual-kernel custody checks, 13 wire-protocol checks, 18 planner checks,
7 joined SDK checks and 29 existing artifact/signing/SDK-contract regressions.
The seven sequential test processes took approximately 16 seconds in total,
with finite memory, CPU and wall-time limits. No build or dependency download
was required.

The joined harness calls the actual public Boto3 methods and lets Botocore parse
the synthetic responses. Both long-term and session signing tuples complete the
local flow. Config and two unique layers are uploaded in non-manifest order,
while the original repeated layer and manifest bytes are preserved. The receiver
independently checks assembled blob hashes, and installed Botocore independently
checks the server-side signatures. A separate case mutates every original source
after capture: changed upload bytes are refused, and the sealed originals still
complete the same simulation. Wrong scope/content, premature manifest publication,
wrong acknowledgments and a provider error do not become successful proposals or
automatic retries.

The custody checks exercise real kernel write/truncate refusal, exact reads,
source mutation, positive short I/O, cleanup after failures/cancellation, fork
separation and concurrent close/read ownership. Some fault controls deliberately
mock syscall failures or reduce work limits; they are not real kernel failures.
Planner-only tests use a trusted immutable-byte fixture reader; the joined SDK
tests use the actual sealed capture owner.

Receipts, commands, source hashes and full output are retained outside Git under
`serverware-operator-workspace-evidence/ecr-publication.zJuI7G4q/initial`.
This source-only update changes no deployed service, DNS record, native attempt,
credential grant or AWS destination. The authority and live-transport gaps above
remain open.
