# Consume execution reserver bootstrap

This root-original profile admits the scope for the dedicated consume reserver.
Its [fixed OS delivery](oidc-session-activation-delivery-execution-reserver-delivery.md)
and [cold service](oidc-session-activation-delivery-execution-reserver-service.md)
are connected in source. The independently pinned SQL receiver has its own
[bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md), but its
actual cold pending consumer remains open, so token-release row 12 stays in
progress. Source is unbuilt, unexecuted and unprovisioned.

[`oidc_session_activation_delivery_execution_reserver_bootstrap.py`](../serverware/oidc_session_activation_delivery_execution_reserver_bootstrap.py)
genuinely verifies its own launch, the four detached receiving originals and
three enrollment originals. It accepts no successful material in place of
those bytes, and neither observes nor chooses its own expected checkpoints.

## Fixed role and twelve descriptors

The closed signed-envelope, payload and launch schemas are:

- `serverware.signedOidcSessionActivationDeliveryExecutionReserverBootstrap/v1`;
- `serverware.oidcSessionActivationDeliveryExecutionReserverBootstrap/v1`;
- `serverware.oidcSessionActivationDeliveryExecutionReserverLaunch/v1`.

Role/process mode is `oidc-session-activation-delivery-execution-reserver`,
UID/GID 65499:65499, control-plane peer 65532:65532, and operation only
`oidc.session.activation-delivery.consume`. The listener is
`/run/serverware/oidc-session-activation-delivery-execution/reserver.sock`, named
`serverware-oidc-session-activation-delivery-execution-reserver`. The journal
directory is fixed to
`/var/lib/serverware/oidc-session-activation-delivery-execution-reservations`.

| Launch field | FD | Original/resource |
| --- | --- | --- |
| `rootPublicKeyFd` | 198 | Independent root public key |
| `bootstrapFd` | 199 | Reserver role original |
| `listenerFd` | 200 | Activated listener |
| `custodyFd` | 201 | Consume reserve-purpose receiving original |
| `plannerBootstrapFd` | 202 | Consume-planner original |
| `plannerHistoryCustodyFd` | 203 | Consume-planning history original |
| `receivingHistoryCustodyFd` | 204 | Consume-reserve history original |
| `executionBundleKeyFd` | 205 | Consume execution-bundle AES key |
| `historicalBundleKeyFd` | 206 | Historical activation-bundle AES key |
| `deliveryKeyFd` | 207 | Activation delivery AES key |
| `signingKeyFd` | 208 | Current-root computation private key |
| `journalDirectoryFd` | 209 | Dedicated local reservation journal directory |

The launch's exact remaining fields are `schema`, `processMode`, `serviceUid`,
`serviceGid`, `peerUid`, `peerGid`, `inheritedFileDescriptors`, `listenerPath`,
`requestTimeoutSeconds`, `listenerSocketDevice`, `listenerSocketInode`,
`listenerPathDevice`, `listenerPathInode`, `journalDirectoryPath`,
`journalDirectoryDevice`, `journalDirectoryInode` and `journalMaximumRecords`.
The FD list is exactly 198–209 in order; timeout is an integer 1–30 seconds;
device pins are UInt64 including zero and inode pins are positive UInt64.
Journal capacity is 2–1024 records and must equal the actual current-root
enrollment's `maxRecords`. The fixed cold delivery independently inspects the
real process, descriptors and paths; signed metadata alone is not that check.

No grant, planner, state or completion signer, DB credential or journal-encryption
key is in this role's descriptor inventory. No secret is serialized in the
bootstrap.

## Independent originals, purpose and key joins

The exact envelope is `{schema, payload, signatureBase64Url}`, with the envelope
schema also its signature domain. The 4 MiB role payload contains `schema`,
`sourceRevision`, `role`, `operation`, `receivingCustody`, `plannerBootstrap`,
`plannerHistoryCustody`, `receivingHistoryCustody`, `receiverIdentity`,
`configurationDigest`, `generationDigest`, `runtimeClosureDigest`, `databaseId`,
`currentRootEnrollment`, `grantEnrollment`, `authorizationEnrollment`,
`computationSpkiDigest`, `computationMeasurementDigest`, `statePredecessor`,
`reservationCheckpoint`, `stateEndpoint`, `issuedAtEpochNs`, `expiresAtEpochNs`,
`trustMode`, `launch` and the five false assurance fields below.

The four detached descriptors are each exactly `{byteCount, bytesDigest}`:
receiving custody is capped at 16 KiB, consume planner at 4 MiB and each history
at 8 MiB. Actual immutable byte counts and raw SHA-256 are verified. Each
embedded enrollment is exactly `{base64Url, byteCount, bytesDigest,
identityDigest}` under its actual source cap; raw and authenticated framed
identities both join. Total role/original inventory is capped at 64 MiB on the
same supplied work ledger.

Admission calls only the receiving bootstrap's explicit
`_verify_reserve_on_work`: receiving v2 `reserve` and historical v4
`consume-reserve-history`, both bound to the fixed 65499 process and the exact
consume request. A grant-purpose or planning-purpose receipt cannot substitute.
The genuine consume planner supplies configuration, generation, runtime closure,
policy, key, state enrollment and complete before-vector. The role independently
joins those facts and its expected receiver identity; it does not adopt a
receiver-produced success assertion as authority.

Current-root enrollment must byte-match that planner's retained state enrollment.
Actual consume caller and grant enrollments bind the same configuration,
database, generation, current-root identity, consume planner and root operation
key. The computation public key comes only from genuine current-root enrollment.
Its SPKI and measurement pin must match the role, and its measurement must match
the independently root-asserted receiver identity. Actual private-key pair and
raw AES-key hash checks are performed by fixed delivery/private owners.

Computation is separated from current-root state/completion keys and additionally
from root, both dedicated planners, caller, consume-grant authorizer and all
admitted generic/enrollment/evidence/transition signing keys. The role's UID/GID
cannot collide with configured generic roles. This does not require distinct
artifact measurement bytes merely because two roles have different purposes.

## Two checkpoints, neither derived from an ACK

`statePredecessor` is exactly `{sequence, headDigest, nextFence}`;
`reservationCheckpoint` is exactly `{sequence, headDigest}`. Both are independent
root assertions, not values derived from a received ACK or recovered journal.
Each sequence is bounded by genuine enrolled capacity; a zero sequence requires
the actual enrollment digest as genesis head, and a genesis state predecessor
requires next fence one. The local journal checkpoint does not establish the
state authority's current predecessor, or vice versa.

`stateEndpoint` is exactly `{socketPath, requestTimeoutSeconds, serviceUid,
serviceGid, listenerUid, listenerGid}`: fixed current-root path
`/run/serverware/current-root/state.sock`, timeout 1–30 seconds, service
65516:65516 and root-owned listener 0:0. The separate
[state v8 profile](current-root-delivery-reserve-peer.md) must admit the consume
reserver. The actual locked state owner still has to match the exact current
predecessor, fence and full vector and durably publish its signed ACK. Neither
this bootstrap nor a signed head observation performs that state transition.

## APIs and original time bounds

```text
_verify_on_work(*, bootstrap_bytes, custody_bytes, planner_bootstrap_bytes,
    planner_history_custody_bytes, receiving_history_custody_bytes,
    root_public_key, work, live_window=None, transport_deadline_ns=None)
    -> _ReserverMaterial

_produce_on_work(*, payload, custody_bytes, planner_bootstrap_bytes,
    planner_history_custody_bytes, receiving_history_custody_bytes,
    root_private_key, root_public_key, work,
    live_window=None, transport_deadline_ns=None) -> bytes

_construction_on_work(work) -> (window, deadline)
_fresh(interval, work, opening=None)
```

Input originals and producer graphs are owned before cryptographic callbacks.
The producer repeats real admission before root signing, uses the actual
sign-and-verify primitive, then reads back and joins the canonical output.
Only neutral byte/clock helpers are reused from the authorizer bootstrap, not
its role admission or signer material.

The supplied window is never replaced. The optional cold form creates one real
source-max opening; actual cold delivery must instead establish that opening
before root/key I/O and carry it through all work. The role's static signed
interval never restarts processing. It is at most 300 seconds and must fit
inside all fresh receiving, consume-planner, planning-history and reserve-history
intervals, checked with their original brackets through return. The older
activation planner is historical only; no old clock or expired interval becomes
current. No replacement work ledger or automatic retry is created.

Frozen private `_ReserverMaterial` holds all original bytes and genuine
`custody_material`, independent receiver identity, configuration/generation/runtime
graphs and digests, three enrollment originals, planner/root-operation/computation
public keys, computation pins, database/generation/enrollment identity, caller
age/skew limits, `state_predecessor`, `reservation_checkpoint`, `state_endpoint`,
`attestation_interval`, `opening_sample` and `launch`. It appends the three
detached planner/history byte fields; it is ordinary owned data, not a proof token.

`trustMode` is `trusted-host-local`; `hardwareBacked`, `nativeStageZero`,
`hsmBackedKeys`, `teeVerified` and `externalWitnessVerified` must all be false.
This profile alone does not provide the OS delivery or startup lifecycle; the
linked cold service composes them. The current pending consumer, consume SQL,
completion/recovery, plaintext release, public permission and production gates
remain unfinished.
