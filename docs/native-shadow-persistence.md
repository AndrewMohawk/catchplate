# Native generic receipt persistence

This source slice connects the actual production dispatch caller to an independently admitted native persistence endpoint. It is not a retrieval/fs-verity claim, a native activation journal, a provisioning result or runtime acceptance.

The explicit `nativeShadowPersistenceGuestLaunch/v1` retains the original encrypted-key admission and selects a separately signed persistence assignment. Its permissions are exactly read-only `verify-persistence`, or ordered `store-dispatch-original` plus `verify-persistence`. The genuine assigned `CustodySupervisorCapability` signs this purpose; only the independently assigned, externally attested `CustodyStoreResponse` private owner signs persistence originals and replies. No key generation or export is added.

## Actual callers and effects

The explicit `nativeProofBridgeLaunch/v1` retains the actual admitted guest and four inspected endpoint sessions. Only that source-owned selection enables `ConcreteFiveV3ProductionAuthoritiesV4::call_dispatch_endpoint` to retain the exact independently verified signed Dispatch endpoint request/reply, issue `StoreDispatchOriginal`, and withhold the dispatch result until the store returns a definite signed commit reference. Old host/bridge profiles remain unchanged. The original operation/replay identity and absolute deadline are copied, not renewed.

The endpoint independently verifies the assigned endpoint signature, complete dispatch request/reply/result association, current assignment/proof scope, actual inner receipt signature and key, trusted time/checkpoint, and exact typed payload. All current generic receipt kinds are handled:

| Actual dispatch | Retained typed receipt |
| --- | --- |
| Recover state / commit publication | Publication reconciliation |
| Begin ingress | Opening spill or unavailable-generation receipt |
| Reserve spool | Spool append reservation |
| Append spool / append terminal | Exact spill receipt, including true terminal fork outcome |
| Compact spool | Spool compaction |
| Append active-effect barrier | Barrier receipt |
| Commit / reconcile active effect | Commit receipt |
| Consume and publish activation | Existing generic activation-publication receipt |

The ten receipt signing roles remain distinct. Verification-only results, prepared publication and request HMAC are retained as actual dispatch originals with no invented persistence receipt. They cannot satisfy a receipt lookup. Existing five-service transition/sealed-artifact checks and final semantic receipt checks remain in the normal caller; this store does not replace them or authorize effects. The separate newer native activation journal and publication protocol are unchanged.

`VerifyPersistence` and `VerifyAssignmentBoundPersistence` only compare an already committed exact receipt. The assignment-bound call also requires byte-identical protected scope and signing preimage. Neither call writes, adopts supplied bytes, supplies missing evidence, or repairs storage. The existing receipt's `persistence_receipt_sha256` is its signed immutable lookup reference, not a fixed-point hash of the payload containing it. A separate full signed commit SHA binds payload, role, actual effect originals, sequence, predecessor head, actual guest and original deadline. A reused lookup reference with different bytes is rejected.

## Durable boundary and uncertainty

The role receives only the admitted `persistence-listener` and `persistence-journal` FDs. A root inspector retains actual socket/PIDFD/peer measurement and current original files; fixed `/run/serverware-shadow-persistence/listener.sock` is not caller-selected. Inspection occurs at connection, dispatch and reply. No header, caller PID or UID-only assertion substitutes for it.

The final role opens the held mode-0700 directory on an explicit durable filesystem (ext4, XFS or Btrfs), an existing mode-0600 exclusive lock, and an independently pinned mode-0400 genesis/current head. Record names are source-derived sequence numbers. It creates the exact ordered request/reply original pair with `O_EXCL`, syncs and reads it back, signs the purpose-fixed commit, syncs/read-backs that original and the linked immutable head, and syncs the directory before acknowledgement. Held FDs, names, identities and exact bytes remain checked. Existing exact commits may be observed; their signed originals are never reconstructed or re-signed. Reusing an effect replay ID with different request or reply bytes refuses, even when a receipt lookup reference happens to match.

Any partial write, extra file, missing chain member, conflict, expiry or unknown outcome closes the service. Nothing is unlinked, repaired, truncated or retried as a new effect. A lost ACK never authorizes repeating the original dispatch. Restart requires a new independently admitted exact existing head under the same genuine scope/guest; incomplete records remain unresolved. These local durable originals do not by themselves provide an independent monotonic/rollback witness or cross-boot handover authority.

Capacity is deliberately finite: 128 commit records, 32 MiB total retained original/head bytes, and the unchanged 4 MiB whole endpoint frame/file ceiling. Base64 and full signed reply overhead reduce usable payload capacity; no batch splitting or global limit increase is added. Store input and predicted whole commit bounds are checked before its first filesystem write. The earlier dispatch is already an effect; a response too large to persist is an unresolved dispatch, never retry permission.

## Acceptance boundary

This batch is source-only. It requires the actual native proof bridge owner/client and independent signed launch/grant/key/peer/journal provisioning. The full multi-child parked release producer, all selected signer services, signed filesystem syscall closure, genuine durable storage deployment, current trust/time/assignment delivery and runtime acceptance must exist; this endpoint does not manufacture them. No builds, tests, service launches, key operations or provider calls were run. Legacy profiles, immutable Retrieval objects and native activation's separate journal remain strict and unchanged.
