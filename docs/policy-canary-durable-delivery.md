# Protected canary delivery slots

This is a source-only controlled-store and receiver slice. It does not claim a
running native sender, actual canary production, provisioned independent
assignments or runtime acceptance. The earlier intake/signing/TLS primitives
are prerequisites, not a substitute for the native contact owner and twelve
genuine exporters still required below. No tests, builds or provider actions
are part of this source handoff.

## Scope and authority

`authority_policy_canary_delivery.py` fixes the original and wire grammars;
`authority_policy_canary_delivery_policy.py` admits the separate
`policyCanaryDeliveryPolicy` in the actual root-signed measured configuration.
Verifier and planner independently admit it and the fixed enabled operations.
The planner retains its actual `MeasuredConfiguration` in a private in-process
admission owner; HTTP cannot create that owner or export a verified token.
There is no audit, intake, OAuth, bearer or human-upload permission alias.

The policy has eleven fields, at most 32 current assignments, 32 historical
assignments and 32 explicit recovery associations. A delivery assignment adds
`intakePurposeAssignmentSha256` to the original twenty-field canary assignment.
Prepare requires both purposes for the same genuine native boot/key/holder,
TLS identity, canary and logical instance. A fresh recovery association permits
observation of a historical slot, not use of that old owner's contact authority.
Historical native evidence is authenticated at its original time under the
explicitly admitted historical trust and assignment; it is not made live again.

The existing cold public-policy owner retains independently pinned read-only
root/configuration originals and the actual custody binding. Optional presence
of this separately enabled policy selects delivery; absence cannot promote an
intake assignment. The listener admits actual TLS 1.3 client certificates from
the selected assignments, then each request proves the exact leaf/SPKI/URI,
role-4 public key and original NSM document against its own purpose. Forwarded
certificate headers and configured identity strings confer no authority.

The companion intake policy is explicitly corrected to
`serverware.policyCanaryIntakeAuthorityPolicy/v2`, exact eight fields. Its old
embedded `controlPlaneConfigurationDigest` was a hash fixed-point requirement:
the actual custody/runtime digest equals the authority digest of the whole
payload, including that policy. The v1 shape is refused, not silently widened.
Both intake and delivery now bind their runtime arguments to the source-computed
digest of the complete independently admitted configuration. No field is
excluded from its signature/hash. The cold receiver's unchanged nine fields
pin the complete signed file, root/SPKI and full digest after the original
exists, and require both configuration-digest pins to equal the custody binding.
The native intake statement/HTTP/signature bytes do not change.

## Fixed sequence and durable ownership

The only added HTTPS endpoint is POST
`/api/data-plane/policy-canary/delivery`. It accepts canonical ASCII JSON with
exactly `apiVersion`, `operation`, `request`, `nativeEvidence`; content type,
Content-Length and an empty query string are required by the actual app path.
The controlled caller constructs outer arguments from its actual custody
digest, the request and the native proof. It cannot choose SQL, roots or policy.

| Operation | Exact request fields | Effect |
| --- | --- | --- |
| `policy.canary.delivery.prepare` | `httpOriginal`, `expectedHeadSha256` | Atomically persist one original, slot and current head |
| `policy.canary.delivery.recover` | `slotId`, `httpSha256`, `partCount` | Complete an authenticated read; audit only |
| `policy.canary.delivery.claim` | `slotId`, `httpSha256`, `partCount`, `slotSha256`, `headSha256`, `prepareCompletionOriginal`, `readCompletionOriginal` | Irreversibly mark the exact prepared slot/head claimed |

The stable head is SHA-256 of the fixed head domain plus the canonical
`[deploymentId, canaryId, instanceId]` tuple. Assignment, boot and request ID do
not change this key. A new preparation requires either an authenticated absent
head or the exact consumed predecessor head digest. A prepared/claimed head
cannot expire, be removed, reset or be bypassed using a new request ID/boot.
There is no cleanup/delete/reset operation. Sequence overflow refuses.

`slotId` is the original intake batch request ID. Prepare stores the exact
future HTTP3 intake body, including its native intake proof and unchanged batch.
The body is segmented into deterministic 64 KiB ASCII parts only to satisfy the
existing row ceiling. All parts and the slot/head are one atomic transaction;
segmentation never splits a batch, its effects or authority. Reassembly checks
the exact byte count, every part hash/order and whole-original hash. There is
no partial-preparation success or reconstructed equivalent JSON.

The original intake issued/expiry times, native owner and configuration digest
are retained in the slot. Prepare/read/claim do not renew them. The caller must
complete these operations and its one intake contact within the original
window, not begin a new thirty-second window at each phase.

Before claim, the native owner obtains an actual completed recover/read of
the persisted prepared slot/head/parts. Claim consumes two completion originals:
the actual prepare completion and the completed read. If the prepare ACK was
lost, the first may instead be an explicitly labelled completed `recover`
proving `prepared`; it is never relabelled as `prepare`, and the second still
must be a completed read. Both must agree on exactly the current rows/HTTP and
same current native owner under the still-live original expiry. The transaction
rechecks the actual current rows and atomically changes both to `claimed`.

Only a definite verified claim response held by the same native one-attempt
owner may precede intake contact. A claim timeout, disconnect or lost response
leaves consumed uncertainty; later observation of `claimed` does not authorize
contact. No repeated claim/intake, transparent retry, re-signing, splitting or
fresh request ID repairs that uncertainty. A consumed slot remains immutable
history even if a later head points to another slot.

## Actual completion and persisted-row proof

The response schema is the distinct closed
`serverware.policyAuthorityCanaryDeliveryRuntimeResponse/v1`: the existing
sixteen runtime fields plus `authorityConfigurationOriginal` and
`deliveryOriginals`. The latter has exactly:

- `signedMeasuredPlanOriginal` — actual signed planner response;
- `executorCompletionOriginal` — actual validated executor return, receipt and result;
- `witnessRequestOriginal` and `witnessResponseOriginal` — exact signed terminal
  external-witness request/response retained by the execution owner.

The existing runtime response schemas are not widened. The purpose-fixed cold
client preserves the original request/response bytes; the HTTP envelope returns
their canonical base64url encodings in exact
`apiVersion`, `requestOriginal`, `responseOriginal`. The authority root for the
returned configuration is independently cold-pinned, distinct from the runtime
transport root. HTTP 200 or a result boolean alone is insufficient.

`authority_policy_canary_delivery_completion.py` independently verifies the
root-signed full configuration, verifier signature, original request commitment,
signed planner identity and complete root transition, exact executor commit
receipt/result, and external witness signature/head/reservation/fence bindings.
It checks the original source/manifest/profile rather than weakening an old
live-planner clock check. The prepare's after-root mutations establish its slot,
head and parts. The separate recover's actual selected rows and before-root
multiproofs establish persisted readback; it may not mutate those relations.
The resulting exact originals must agree in the claim transaction. A planner
before-proof by itself is not a post-commit read proof. No SELECT is relabelled
as a writer receipt, and no synthetic completion is signed.
The retained runtime attestation-consumption receipt keeps its original trust
and assurance labels. Known controlled commit/read evidence is not promoted to
physical or hardware-backed authority merely because it carries those bytes.

The completion wrapper has exact `schema`, `requestOriginal`, `responseOriginal`
strings. The claim's complete originals remain in the genuine typed request /
planner / executor journal; the business slot records their exact hashes rather
than duplicating unbounded proof bodies in one row. Fresh recovery grants only
processing/read authority. Expired original action authority is never reused.
Current source/manifest and independently pinned authority-root continuity are
required for claim proof admission; unrelated root/cohort migrations are not
implicitly trusted and need an explicit future migration profile.

## Atomic intake consumption and observation semantics

The actual twelve-kind intake kernel requires the exact claimed slot and head
before any evidence effect. It compares the complete immutable HTTP digest,
native owner, assignment, canary boot, configuration and original expiry. The
batch row/result, all admitted evidence effects/audits and slot/head consumption
are one controlled transaction. Generic runtime DML is not restored. Parts are
immutable and were authenticated on claim; intake does not invent another
part inventory or contact permission.

The delivery result has exactly `ok`, `operation`, `requestDigest`,
`auditEventDigest`, `idempotentReplay`, `status`, `observation`. Observation is
exact `slotOriginal`, `headOriginal`, `httpOriginal`, `intakeOriginal`. Statuses:

- `unknown`: no authenticated slot; slot/HTTP/intake are null. A retained head
  may still block progress. Absence is not permission to reset or send.
- `prepared`: exact persisted original, still subject to same-boot live claim.
- `claimed`: contact has been irrevocably consumed; never resend authority.
- `consumed`: exact committed intake row/result, not permission to repeat it.

The older intake `/inspect` remains an authenticated observation only, not a
fresh writer receipt/read proof. It cannot substitute for this completed
recover operation. Fresh new-boot recovery is read-only even for prepared
history. A failed HTTP operation returns 409 where caught; disconnect, other
error, invalid proof and no response are likewise unknown, not retry permission.

## Protected storage and bounds

The source DDL, protected relation registry, exact primary keys, fixed query
program, mutation kinds, planner and audit joins include:

- `policy_canary_delivery_slots`: 29-field immutable identity/original plus
  monotonic phase/proof/result fields; primary key `id`;
- `policy_canary_delivery_heads`: 8 fields, stable logical tuple unique,
  positive sequence and exact current slot/status; primary key `id`;
- `policy_canary_delivery_parts`: exact `slot_id`, `ordinal`, `original`,
  `original_sha256`; compound primary key `(slot_id, ordinal)`.

The paired schema is `policy-canary-durable-delivery.v1.schema.json`. Delivery
uses at most 48 selected rows, 24 business mutations and 8192 work units. HTTP
original is at most 1 MiB + 192 KiB, argument/body at most 3 MiB, each claim
completion at most 768 KiB, and both together at most 1536 KiB. The whole signed
runtime response and complete base64 HTTP envelope must each fit 6 MiB, the
existing transport ceiling. No global ceiling is increased. The complete
evidence intake now includes slots/heads among its 46 retained relations, still
32 rows per relation, 240 selected rows, 96 mutations and 8192 work units.

Closed input bounds run before planner contact. Once the actual signed plan
exists, conservative full-response/proof accounting runs before execution
reservation, delivery business mutation or native contact. This does not claim
absence of prior generic planner/witness preparation records. Their existing
monotonic cleanup and uncertainty rules remain. Actual emitted byte bounds are
checked again. An otherwise individually valid batch may be too large for its
full future proof and is refused before business effects; it is not truncated,
split or retried. These are explicit temporary capacity limits. Durable-history
capacity lifecycle and production-scale proof/storage work remain unfinished.

## Required native continuation

The source-selected native implementation must join the genuine existing
role-4 signer and dedicated TLS owner, using separate phase signature/NSM
domains. Each statement has 25 fields (the intake 22 without `batchSha256`, plus
`slotId`, `requestSha256`, `httpSha256`, `originalExpiresAtEpochNs`). Native
`bootId` and `canaryBootId` retain their distinct encodings. The signature is
over `serverware.nativeCanaryDeliveryStatement/v1/PHASE`, NUL and the full
canonical ASCII statement. NSM nonce is SHA-256 of
`serverware/canary-delivery-PHASE-attestation/v1`, NUL, nonce32,
SHA-256(statement) and signature64. Phase is `prepare`, `claim` or `recover`.

Before any intake send, that actual native owner must verify the separately
pinned signed configuration and every completion/root/row binding above,
retain the exact HTTP bytes, original absolute deadline and same boot/key/TLS
owner, consume a one-attempt contact state before network contact, and validate
the exact intake ACK or preserve uncertainty. A new process cannot infer that
an old claimed contact was unsent. Root owns this native verifier/contact and
lost-ACK integration; it is not supplied by the receiver or an in-memory DTO.

All twelve genuine canary exporters remain required as listed in the companion
intake guide. Protected candidate artifact production, Setup continuation and
materializer evidence, real onboarding canaries, measured JIT and final
proxy-ready receipt also remain separate required work. Nothing here claims
completed Setup, external provisioning or a testable pilot.
