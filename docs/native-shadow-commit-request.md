# Native LedgerAppend CommitRequest family

This is source implementation, not executed acceptance or complete custody.
The implemented family is `ClosedProductionDispatchRequestV4::CommitRequest`
under the existing LedgerAppend parent signer. The other nine signer endpoints
and LedgerAppend's other operations are not manufactured by this service.

## Connected effect path

The explicit `nativeProofBridgeLaunch/v2` owner retains the four existing
proof endpoints plus an independently inspected LedgerAppend connection. Its
production runtime is `serverware.policyCustodyProductionRpcRuntime/v6`:
existing generation admission remains required and `commitRequest` selects
`serverware.nativeCommitRequestServices/v1` with exactly two raw, canonical
ASCII `serviceGrantOriginals`, keyed by `durable-recovery-store` and
`current-signature-authority`. It is not an incoming per-request enable flag.
The old proof bridge/v1 and production runtime/v4-v5 retain their old meaning.

1. `ConcreteFiveV3ProductionAuthoritiesV4::call_dispatch_endpoint` sends
   `PrepareCommitRequest { request }` to the actual inspected LedgerAppend
   process, preserving the existing request/replay and absolute deadline.
2. `native_guest/commit_request.rs` validates its independently signed
   operation scope and computes the existing request commitment with its real
   non-exporting HMAC owner. It retains and signs a fixed computation original;
   it does not accept an uploaded HMAC/success as its computation.
3. `dispatch_service_client.rs` forwards that exact computation on the
   existing authenticated DurableRecoveryStore and CurrentSignatureAuthority
   sessions. The current five-service generation must already be committed.
4. Each actual service loop admits its own sealed operational grant, checks
   the signed computation and original owner state, appends the complete
   computation and its own existing transition signature to its separate
   `dispatch-journal`, and requires fsync/readback before returning it. The
   ordinary service keys remain their own already-provisioned keys.
5. `FinishCommitRequest { computation, service_transitions }` returns to the
   native endpoint. Only its exact retained computation and both independently
   verified actual transitions produce the existing dispatch response. The
   normal endpoint v4 signature and old dispatch/transition domains remain.
6. The actual bridge commits the complete final signed request/reply originals
   through the selected Persistence endpoint before returning the result.
   Persistence also compares the finish computation/result/transition originals.

The computation is exact seven fields: `apiVersion`, `nativeGrantSha256`,
`request`, `result`, `resultSha256`, `computedAtBoottimeNanos`, and
`signatureBase64url`. Its signature uses the existing protocol signature
framing and domain `serverware.nativeShadowCommitRequestComputation.signature/v1`
over the ordered canonical tuple of the first six fields. The service command
is exact `{apiVersion:"serverware.custodyCommitRequestTransition/v1",computation}`.
Existing typed request/result decoders, not arbitrary JSON, govern those fields.
The original request commitment context deliberately retains its existing
snake_case serialization. No old domain or signature recipe changes.

The native fixed service launch is exact
`{apiVersion:"serverware.nativeShadowCommitRequestGuestLaunch/v1",keyAdmission,commitRequest}`.
Its single activation is `commit-request-listener`; the existing retained
privileged inspector is FD4. Its fixed socket is
`/run/serverware-shadow-commit-request/listener.sock`, fixed directory
`/run/serverware-shadow-commit-request`, and inspection domain
`serverware.nativeShadowCommitRequestInspection/v1`. It uses the real native
key/closure/time/parent owner and original startup/lifetime, not a reconstructed
production driver. The local Ed25519 inventory is exactly LedgerAppend.

## Separate HMAC custody

The HMAC is independently provisioned 32-byte nonzero secret material. It is
not derived from, equal to, exported with, or treated as an Ed25519 signing
seed. The actual assignment's observation-window key ID and epoch are
independently authorized by
`serverware.nativeShadowRequestCommitmentAssignment.signature/v1`; that key ID
must differ from all eighteen custody Ed25519 roles.

The public commitment is SHA256 of
`b"serverware/native-shadow-request-commitment-secret/v1\0" + secret32`.
The additive encrypted-delivery/v2 profile extends the fixed local inventory
and private bundle with `requestCommitment`. KMS context purpose is exactly
`native-shadow-local-role-keys-and-request-commitment/v2`; assignment purpose is
`kms-recipient-shadow-local-keys-and-request-commitment`. The admitted helper's
real RSA recipient quote binds the complete inventory, real final-role
recipient and same original deadline. The v2 NSM nonce is SHA256 of
`b"serverware/native-shadow-kms-nonce/v2\0" + originalChallenge32`.

The existing isolated offline encryption entry consumes sealed FD3 public
inventory, FD4 independently provisioned private bundle and FD5 KEK. It emits
ciphertext only. The existing pinned helper obtains the real KMS Recipient
ciphertext and confines plaintext to helper/final-role memory. The Rust HMAC
owner has no raw-key getter, generic MAC/sign API, cloning or serialization.
Its only operation computes the existing typed protected-request commitment.
The v1 encrypted profile and old production-driver constructor do not admit
this extra key. The Ed25519 possession quote still proves only its assigned
Ed25519 subset; this does not invent a nineteenth role or HMAC TEE result.

## Ordinary-service inputs and fixed entry

Only DurableRecoveryStore and CurrentSignatureAuthority select ordinary
runtime `serverware.policyCustodyServiceRuntimeConfig/v6`. It requires both
`generationAdmission:{grantFdName:"generation-grant"}` and
`dispatchAdmission:{grantFdName:"dispatch-grant"}`. The two-role activation
inventory is the existing role-specific business inventory followed by
`generation-journal`, `generation-grant`, `dispatch-journal`, `dispatch-grant`,
in signed contiguous FD6 onward slots. Each directory has its actual pinned
device/inode/mount/filesystem owner as required by the existing journal owner;
`dispatch-grant` is final-role-owned, mode0600, zero-link fully sealed memfd,
nonempty and at most64KiB. The actual grant FD identity is allocated before C9
signing and its public contents sealed afterward, avoiding a C9 hash cycle.

The two existing fixed binaries have explicit `--guest-c9-commitment` and
`--guest-c9-commitment-inspected` entries. Launch/v3 is closed
`{apiVersion,deliveryConfiguration,delivery}`; inspected launch/v4 adds exactly
`peerInspectionCredential:"peer-inspection-policy"`. The genuine C9 owner,
actual parent channel, original kernel timers and permanent final-role drop
are retained. Inspected entry uses the existing dedicated pre-drop root
inspector, not service capabilities or a same-UID/dumpable fallback. The
listener is re-listened under final-role credentials before its distinct
listening notice; that notice is neither service readiness nor a new deadline.
Legacy generation-only launch/v1-v2 and their Python input APIs remain closed.

`native_shadow_commitment_artifacts.py` supplies purpose-fixed offline public
input authoring: independent supervisor HMAC/native grants, explicit encrypted
delivery/v2, and the two ordinary service grants under their actual separately
pinned authority-history roots. Its explicit `sign_service_delivery` and
`sign_service_generation_grant` preserve the old C9/generation domains while
admitting only this exact successor's two roles and inventory. No key is
generated or returned, and public authoring is not runtime/resource evidence.

## Failure and remaining connected work

The native computation owner retains at most256 attempts in memory; this is
not durable recovery. Reuse of operation/replay labels, a changed computation,
missing service transition, stale peer/authority/owner or original deadline
expiry refuses. Each service journal independently retains definite effects;
an uncertain durability or bridge contact poisons its owner, with no automatic
rerun or orphan repair. Nothing reconstructs a successful native computation
from a journal DTO after process loss. Restart/settlement needs its own real
authorized continuation; existing driver/cleanup obligations remain.

The older five-child proof cohort does **not** contain a LedgerAppend child.
The explicit [six-child successor](native-six-proof-cohort.md) now owns that
actual endpoint, and the [ordinary commitment launcher](custody-commitment-inputs.md)
creates and transfers both additional grants and journals before its one-shot
release. The generation-only operator must not be relabeled or fed extra FDs.
These parent/resource producers do not complete final driver admission,
remaining signer families, per-operation settlement or full bridge readiness.
The new helper bytes also require normal independent image rebuilding/admission
and actual HMAC/KMS provisioning. No build, parser,
test, runtime, launch, installation or provider call was executed for this
slice; connected pilot acceptance remains unverified.

Closed data schemas:
[endpoint/grants](../schemas/native-shadow-commit-request.v1.schema.json) and
[HMAC/encrypted successor](../schemas/native-shadow-commitment-keys.v1.schema.json).
