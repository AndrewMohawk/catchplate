# Native first ingress and shared ledger spool

This is a source-connected successor for first ingress and LedgerAppend
reserve/append. It is not a claim that the pilot has been built, deployed,
provisioned, or runtime-accepted. Missing later event owners remain unavailable.
Legacy Fleet evidence and the old CommitRequest, retrieval, five-child and
six-child profiles keep their original meanings.

## Actual owner path

The existing production BeginIngress caller reaches a separately inspected
IngressAdmission endpoint. A fresh independently verified generation origin
comes from the **actual installed gate**, not a caller generation object or a
renamed Fleet load receipt. DurableRecoveryStore allocates the shared event
ordinal and ingress sequence under its real retained durable journal. The
separately assigned LedgerAppend owner computes the fixed early sampling HMAC.
IngressAdmission retains that exact allocation/sample and signs its own opening.

The same DurableRecoveryStore subsequently allocates LedgerAppend reservations
and appends. A reservation is a real pending allocation; the append must match
its actual request/event/predecessor. Ingress and Ledger do not maintain private
parallel heads. CurrentSignatureAuthority independently verifies the actual DRS
transition and performs its own durable transition. Their independent service
keys and history roots are not native signer aliases.

Every completed operation traverses:

1. Actual request and original deadline, inspected endpoint and current grant.
2. DRS durable allocation, retaining an unresolved slot on uncertainty.
3. The appropriate native role's exact one-shot prepared core.
4. Retrieval's actual write, fs-verity, fsync and held-original readback.
5. The appropriate native role's complete final signed receipt.
6. DRS durable head/transition and CurrentSignatureAuthority durable transition.
7. Native Finish checking both genuine service transitions, followed by the
   existing Persistence owner committing the complete response original.

Only that final definite response reaches the existing caller. No RPC retry,
timeout reconciliation, replacement head, lost-ACK success, or role-substitution
path is added. Every complete endpoint frame still has the existing 8 MiB cap.

## Acyclic storage and complete signatures

`ledger_spool_values::Core` contains the exact dispatch request, allocation hash,
event bytes, generation/ordinal/predecessor, observation, scope and signer.
It deliberately contains **no** storage receipt or retrieval address.

The typed core identity uses `serverware.nativeLedgerSpoolCore/v1`; retrieval ID
and proof use `serverware.nativeLedgerSpoolRetrievalId/v1` and
`serverware.nativeLedgerSpoolRetrievalProof/v1`. They use the existing framed
domain-hash helper, not plain concatenation. Storage writes the canonical full
core, measures its actual fs-verity SHA, retains its inode and returns a separately
signed `serverware.nativeLedgerSpoolStorage/v1` original. The native final receipt
then signs **all** final fields, including every storage/retrieval reference.
`require_final_payload` reconstructs and compares that complete final payload
from the retained core plus full storage original. No signed field is dropped,
filled with a predicted hash or replaced by a generic successful proof.

Prepared/storage signatures use existing signed-envelope framing with domains
`serverware.nativeLedgerSpoolPreparation.signature/v1` and
`serverware.nativeLedgerSpoolStorage.signature/v1`. The final assigned-role
signature and final spool receipt/head calculations remain their actual existing
algorithms. The new retrieval selector, not the old retrieval reader, admits the
acyclic storage relation; old retrieval objects remain separately checked.

Core and prepared originals are each bounded to 512 KiB before the first write.
The retrieval store is complete and bounded to 128 entries/32 MiB. DRS history is
complete and bounded to 256 records/64 MiB; the current-authority journal is
bounded to 128 records/64 MiB. Overflow refuses before the corresponding effect;
there is no truncation or proof/frame-cap increase. Partial files, orphaned
records and unknown transitions refuse restart rather than being repaired.

## Explicit profiles

| Owner | Explicit successor |
| --- | --- |
| Native parked cohort | `nativeShadowProofCohortConfiguration/v4`, fixed seven; release/terminal/cleanup wire v3 |
| Native bridge | `nativeProofBridgeLaunch/v3`, production RPC runtime/v7 |
| Ledger + fixed sampling | `nativeShadowCommitRequestGuestLaunch/v2`, own LedgerSpool grant |
| IngressAdmission | `nativeShadowIngressGuestLaunch/v1`, own key and grant |
| Retrieval writer | `nativeShadowRetrievalGuestLaunch/v2`, own spool retrieval grant |
| Ordinary DRS/current | service runtime/v7, ordinary guest launch/v5, inspected only |
| Ordinary five launcher | `custodyFiveServiceLaunch/v5` at `/etc/serverware/custody-spool-five.json` |
| HMAC permission | `nativeShadowRequestCommitmentAssignment/v2`, `native-shadow-request-and-ingress-commitments` |
| Protected opening | `nativeCustodyOpening/v2`, exact early-context event |

All API names above have the `serverware.` prefix. The bridge runtime's only new
top-level field relative to v6 is `spool`, exact four fields:
`apiVersion: serverware.nativeSpoolServices/v1`, `headGrantOriginal`,
`currentGrantOriginal`, `originFdName: generation-origin`. The two originals are
raw canonical ASCII strings. `generationAdmission` and `commitRequest` remain
required with their real original contracts. The complete runtime still must
fit the existing bound; bounded component sizes do not authorize an oversized
aggregate.

The seventh child's socket is
`/run/serverware-shadow-ingress-admission/listener.sock`, activation
`ingress-admission-listener`, bridge directory
`ingress-admission-peer-directory`, inspection API
`serverware.nativeShadowIngressAdmissionInspection/v1`. It is a ParentSigner
IngressAdmission endpoint, **not** a fifth proof enum. Ledger retains its distinct
`commit-request` socket. Actual Selection excludes these native signers from
ordinary outgoing endpoint construction. `generation-origin` is a data socket,
not an outgoing service endpoint. Bridge attachment returns a native signer map
in place of the former optional Ledger session; the separately implemented
facade acceptor remains a distinct third result when composed.

## Public input and resource producers

`FiveServiceLaunch.start_spool()` and `GenerationInputs` retain the existing five
actual ordinary children and business resources. Only DRS and current authority
add their own spool journal plus sealed grant memfd. Root-signed Head/Current
grants bind actual C9 originals, runtime/history originals and the independently
authorized scope. The head grant pins all three actual native grants (Ingress,
Ledger, Retrieval), not their shape alone. Current embeds the exact head grant
and the real DRS authority epoch/public material.

`native_shadow_spool_artifacts` provides explicit supplied-key authoring calls:
`sign_sampling_assignment`, `sign_sampling_delivery`, `sign_commit_service_grant`,
`sign_ingress_service`, `sign_ledger_service`, `sign_retrieval_service`, and
`sign_and_seal_service_grant`. These require independently approved original
bytes and actual opaque authority keys; invoking these functions is an operator
authority action, not performed by this source implementation. No key is created,
derived from an Ed25519 seed, returned as plaintext, or implicitly provisioned.

`ParkedProofCohort.prepare_spool_inputs()` creates an actual retained `SpoolInputs`
owner. `additions(role)` returns only source-fixed named descriptors, to the
existing actual C9/activation signer and transfer owner:

| Role | Additional retained resources |
| --- | --- |
| Retrieval | `ledger-spool-store`, `ledger-spool-lock` |
| IngressAdmission | `ingress-admission-listener` |
| Bridge | `ingress-admission-peer-directory`, `generation-origin` |

Retrieval's full activation order is its old listener/objects followed by store
and lock. `ledger.lock` is a zero-length, guest-owned 0600 regular file. The parent
acquires EX flock before transfer and the native writer retains that exact open
file description continuously. A second OFD must conflict. No close/reopen
interval is permitted. Public grant memfds remain fully sealed and bounded;
the new lock allowance does not admit arbitrary regular activation files.

The store parent `/var/lib/serverware/native-ledger-spool` and fixed listener
parent must be independently provisioned root-owned 0711 directories. The owner
creates only a fresh invocation directory and never adopts/unlinks an old one.
The writer requires writable ext4 or btrfs with working fs-verity and actual
durability semantics; filesystem magic alone does not attest power-loss safety.
`initialize_store` verifies the signed retrieval C9 original, original cohort
window and real descriptors, then writes an empty **storage** genesis. This does
not initialize the shadow ledger or invent a shadow genesis hash.

All five ordinary services must genuinely authenticate and listen before the
seven-child release. The release owner compares actual retained transfer types,
all original grants, original lifetime and spool resource identities. Seven-child
cleanup retains all seven real PIDFD/start/terminal/reap owners; five/six cleanup
cannot settle this cohort. The store, lock and origin channel are not released
until actual cohort cleanup/reap. Files remain for explicit reconciliation.

## Installed generation origin

After a genuine generation installation, the operator explicitly invokes
`ParkedProofCohort.deliver_generation_origin()` once. Construction/readiness is
not installation and does not trigger this operation automatically. The actual
authenticated management route is `POST /v1/native-generation-origin`.
`with_native_generation_origin` holds the real installation/retained-generation
guards through the native signature/quote, checks current assignment/trust,
immutable loaded bytes and actual complete zero-ingress ledger baseline. Its
raw originals include actual installation request, assignment, load, runtime,
publication, configuration, trust and baseline. This is a distinct role-4 purpose;
the observation-only `/native-loaded` result is not reused as effect permission.

`issue_native_generation_origin.py` is the independent issuer's fixed source
entry: protected config FD3 at
`/etc/serverware/native-generation-origin-issuer.json`, sealed independently
provisioned seed FD4, genuine accepted TCP transport FD5, isolated interpreter.
It issues one random signed challenge, verifies the actual role-4 signature,
Nitro quote/PCR/EIF/module/root/collateral revocation and exact target originals,
then signs one exact native origin. Issuer authority, origin key, native role-4
key and control-plane response key are independently pinned/distinct. Config
authority lasts at most 300 seconds; the operation/challenge is at most 30
seconds and never renews original cohort/assignment/service lifetimes.

Frames are fixed tags `SWNGOC1\0`, `SWNGOE1\0`, `SWNGOR1\0`, uint32 big-endian
length and canonical ASCII, at most 2 MiB. Evidence is at most 1 MiB, its nested
original string at most 768 KiB and the request at most 4096 bytes. Issuer
signatures use the existing signed-envelope preimage and dedicated
`nativeGenerationOriginIssuerAuthorization.signature/v1`,
`nativeGenerationOriginChallenge.signature/v1`, and
`nativeGenerationOrigin.signature/v1` domains (all `serverware.` prefixed).
The measured statement uses its separate source-fixed statement/NSM preimages.

The fixed root-protected relay config
`/etc/serverware/native-generation-origin-relay.json` contains only a fixed
issuer IP/port and admitted local management URL/token. It forwards exact raw
evidence, verifies the issuer's signed result and makes one seqpacket handoff.
It never vouches for the measurement. Missing response, partial contact, expired
window or unknown send consumes the attempt and does not permit another request.

The [independent immutable issuer image and launch owner](native-generation-origin-runtime.md)
are source-connected through a separate fixed runtime profile and offline
artifact targets. Signing keys, cold targets, network placement and deployment
remain independent provisioning requirements; no artifact was built or run.
Native bridge current
configuration activation, final driver and after-drop inspected connections
retain their separately implemented owners and must be composed unchanged.

## Honest remaining boundary

The early HMAC covers the actual assignment/runtime/generation, request binding,
allocated ingress sequence, basis points, key ID/epoch and trusted observation.
It is **not** the later protected request-facts commitment. The existing later
CommitRequest producer remains separate. The v2 opening consumer recognizes the
exact early event and its assigned signature; it does not infer protected facts,
route details, response facts or successful readiness from that HMAC.

This batch does not create native Terminal, Unavailable, Barrier or Compaction
event producers, full detailed-request/response completion, or final pilot
readiness. Unsupported families continue to refuse; an unresolved shared-head
allocation cannot be reset by timeout or another grant. The paired schemas are
`native-ledger-spool.v1`, `native-generation-origin.v1`,
`native-shadow-proof-cohort.v4`, and `native-policy-canary-opening.v2`.
