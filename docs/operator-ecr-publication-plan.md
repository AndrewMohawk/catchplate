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

This repair does not complete JIT approval or enable ECR. The application's
`approve_request` arguments still differ from the old `jit.decide` kernel
contract; that kernel lacks the current verified-assertion handoff; and its
decision foreign key requires a historical receipt that the current executor
does not persist. Historical revalidation also equates the distinct authority
approver-policy and JIT approver-policy digest families; it needs an exact policy
projection, not a renamed hash. The next integration must connect those actual
interfaces and prove a committed grant from a raw signed assertion. A fabricated
approved row or a `jit.assertion.issue` receipt is not that proof. Historical
receipt and capability custody remains framework-owned, not an additional
business-table read permission for an ECR kernel.

No installed SQL function, database schema, live grant, AWS capability or native
attempt is changed by this source repair. Updating an existing installed writer
also requires its exact function/manifest repair path; the ordinary app must
not silently reinstall authority functions on page load.

The focused receipt checks require no pilot or build:

```sh
make verify-authority-webauthn-receipts
# For an already prepared disposable local Unix-socket PostgreSQL fixture:
SERVERWARE_TEST_POSTGRES_DISPOSABLE=1 make verify-authority-webauthn-receipts-postgres
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
