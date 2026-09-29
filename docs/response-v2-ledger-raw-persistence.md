# Private ledger raw-response publication

This source path connects a genuinely captured target response to the ledger's
private immutable CAS, a persistence-role receipt and ArtifactCommit, and the
existing protected `ObjectCommitRaw` state transition. It is not a generic blob
upload, a provider artifact-store alias, or proof of runtime/pilot readiness.
No build, test, provider contact, or deployment is included in this source slice.

## Independent admission and actual producer

The signed-delivery-bound cold custody configuration must explicitly contain
`ledgerRawPersistence: {"apiVersion":"serverware.responseV2.ledgerRawPersistence/v1"}`.
Omission preserves the previous profile; explicit null refuses. Selection also
requires the separately assigned `targetDispatch` native capture purpose, actual
guest delivery, and `ledgerExactRead`. Selection is not write permission.

The measured gate retains actual upstream send/currentness/broker owners and TLS
capture. CredentialTransport owns the genuine staged request and one-use signed
DispatchBegin permit, not a claim that it captured TLS bytes. The router only
authenticates and routes its actual session. It has no new signing key.

The ledger independently consumes `target_dispatch::verify_capture` with the
closed capture request and actual sealed raw-response descriptor. Its non-Clone
owner retains the original signed native evidence, separately assigned gate key,
permit, exact full signed DispatchBegin frame and state receipt, session, target,
request, TLS evidence, hash/length, and unchanged original deadlines. The caller
also retains a duplicate of that same validated descriptor through the result
join. Neither a result DTO nor an unsigned capture digest constructs this owner.

`services::ledger_put::put(config, request, raw_file, deadline_ns)` uses the actual
role-to-role ImmutablePut channel. The closed request has no pathname, object
kind or storage locator. Raw bytes remain private to these measured owners and
the ledger; the return value contains only signed evidence and object identity.

## Fixed irreversible order

1. Verify actual delivery, capture originals and signed current DISPATCHING
   attempt/revision/fence under the same exact-millisecond CLOCK_BOOTTIME bound.
2. Hold a nonblocking ledger-private publication lock. Create and fsync a
   permanent generation/attempt/fence claim containing the original request.
   An existing claim refuses, including after missing acknowledgement.
3. Create the fixed canonical CAS blob and exact content-scoped receipt with
   exclusive creation, full writes, file and parent-directory fsync, mode0400,
   and independent named readback while retaining the originally created FD.
4. Only then sign the attempt-scoped ArtifactCommit using the actual independently
   assigned `persistence` key. Preserve that original and the exact signed state
   request before the single protected ObjectCommitRaw call.
5. Preserve the authenticated state response. Require APPLIED with the exact
   frame digest and successor revision; query and verify that successor state.
   Fsync the full result original and recheck held/named identities before return.

The result is exact8: `apiVersion`, `captureSha256`, `object`, `storageReceipt`,
`artifactCommit`, `stateRequest`, `stateResult`, `postState`. The state receipt
commits the entire actual signed `RpcRequestFrame`, including authentication.
The consumer reconstructs expected request content and independently verifies
that exact frame hash against the protected state's signed receipt. Unsigned
request-body equality alone is insufficient. Dispatch outcome must consume the
returned post-state revision, not the pre-persistence DispatchBegin revision.

Every effect uses the original deadline and retained capture owner. There is no
fresh allowance, recovery-triggered mutation, retry, overwrite, unlink or rename.
An unrelated operation cannot retarget a path or change fixed `raw-response` /
`http11-response` semantics. Emergency upstream/child cleanup remains independent
of whether persistence succeeds or can report its result.

## Content reuse and protected evidence

The receipt is deterministic within the exact signed generation, full cold
configuration, persistence service/key, content identity/kind/length and media
type. A private signature candidate names the existing CAS layout; it is not
returned as a durability observation before the blob and receipt are durable.
The locator remains the existing
`v1/<generation-hash>/<object-id-hash>/<receipt-hash>/<content-hash>.blob`.
This does not weaken that layout or turn a flat provider artifact into raw CAS.

A later genuine capture may reuse only a complete, authenticated, exact
blob-plus-receipt pair under a fresh one-use attempt claim. Missing, partial or
mismatching bytes, receipt, protection or identity refuse without repair. Each
attempt still needs a newly signed ArtifactCommit and protected state transition.
Byte-identical reused files and their parent receive a fresh fsync barrier under
that claim; merely seeing complete files is not proof an earlier fsync finished.
This does not rewrite bytes, modes or names, or complete a partial pair.

ObjectCommitRaw now stores the exact already-verified ArtifactCommit in the same
transaction as the object association and revision bump. Existing direct-row
lookup remains; a reused content row also requires the exact protected evidence
association for generation, attempt, object ID, kind, digest, length and receipt.
Content hash or association existence alone never supplies release authority.
The existing proof consumer still verifies the original signed artifacts.

## Custody, interruption and limits

The private CAS root is preprovisioned at the signed ledger process's existing
`state_directory/objects`, with exact nonroot ledger UID/GID and mode0700. All
ancestor directories are held and protected, all traversals are no-follow, and
created descendants remain on that filesystem. Regular records are single-link
and mode0400; the held empty mode0600 lock is fixed `raw-put.lock`. Claim records
live only under `raw-claims`. No operator-supplied pathname is accepted.

Raw responses are bounded to 34,603,008 bytes; each canonical metadata original
is bounded to 262,144 bytes before publication. I/O is chunked and rechecks the
actual capture and absolute deadline. Fsync and readback failures remain
uncertain; they do not certify success or remove the claim. Kernel I/O itself
is not claimed to be preemptible at an exact userspace deadline.

The `.claim`, `.artifact`, `.state-request`, `.state-result` and `.result` originals
preserve which steps were observed. Missing local result or stdout/RPC response
does not prove missing state commit. Existing authenticated state/replay readers
may observe an already committed transition; this path provides no resend or
repair endpoint. Retention capacity, archival, partial-CAS repair and operational
recovery tooling are separate work, not permissions inferred from these records.

Only actually selected cold profiles advertise TargetDispatch / ImmutablePut.
Legacy capability and role/key identity hash recipes remain unchanged, and old
profiles cannot submit the new effect. This slice does not close N06 or replace
the outstanding real producer, deployment, end-to-end runtime and production
acceptance work.
