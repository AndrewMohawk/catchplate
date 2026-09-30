# Native complete-ledger heartbeat

This source profile adds a genuine native heartbeat, not a replacement signature
on the old Fleet heartbeat. Fleet heartbeat/checkpoint/readiness verification is
unchanged: it still requires its independently assigned Fleet key and full Fleet
ingress originals. A native opening receipt is never called that envelope.

## Cold selection and independent permission

Only explicit outer `serverware.nativeStartupConfiguration/v20`, selected by
`--canary-heartbeat-v20` / `--native-canary-heartbeat-startup-v20`, admits
required `measuredCanaryDelivery.apiVersion=serverware.nativeCanaryDurableDelivery/v2`.
The rest of the closed v19/v18 owners are retained. V19 explicitly requires
delivery/v1; all older profiles remain unselected. There is no HTTP/env/default
upgrade, new native lifetime or policy hot reload.

Delivery/v2 retains the same ten cold fields and exact independently root-signed
authority configuration original. In addition to separate intake and durable
delivery permissions it requires `policyCanaryHeartbeatPolicy`:
`serverware.policyCanaryHeartbeatAuthorityPolicy/v1`. The optional authority/v6
field is validated by the real artifact producer and authority service. Its own
Nitro roots, complete role-4 assignment, actual boot/key/CP key, measured binary,
canary assignment/boot, deployment and instance are mandatory. Assignment
selectors are derived from the signed original, not supplied by a batch.
The signing key is the actual retained native role-4 key under this NEW explicit
purpose; no Fleet, audit, intake or currentness permission is substituted.

Deployment must supply this independently signed configuration, current Nitro
trust inputs and a real admitted native generation/custody owner. This change
does not generate keys, deploy roots, enroll a workload or establish runtime
acceptance. Public cold roots/pins remain separately admitted inputs.

## Actual producer and durable caller

The source-owned generation control holds installation and retained-generation
guards, revalidates actual assignment/load/key trust, then asks
`ShadowRuntime::native_accounting_snapshot` for its complete retained signed
ledger history. Trusted time is sampled UNDER that same ledger lock, not after
it is released. The snapshot has no public constructor or deserializer.

`native_canary_heartbeat::checkpoint(state, original_deadline)` signs a dedicated
32-field statement and fresh purpose-bound NSM quote from the real native
identity/key owner. It binds the original baseline, exact head/ordinal/count,
actual opening receipt (required-null pair when none in the complete range),
generation, runtime identity, assignment, load and publication, and the exact
snapshot time. No counts, epochs, readiness flags or process identities arrive
from an HTTP caller. Observed time equals statement issue time.

The existing scoped compaction/checkpoint worker is the real caller: after its
definitely consumed interval delivery, it calls heartbeat with the SAME original
operation deadline, then uses the returned sealed snapshot for cumulative
accounting. There is no competing heartbeat timer or fresh deadline on failure.
The returned `RetainedHeartbeat` exposes only `snapshot()`, `original()` and
`sha256()`; construction requires definitely consumed existing durable
prepare/claim/intake completion. The digest is SHA-256 of the complete canonical
ASCII record, not just its statement, signature or opening receipt.

## Admission, storage and failure

The closed nine-field `nativePolicyShadowHeartbeat/v1` record travels as the
existing `custody` kind. Both real verifier and planner reverify its separate
heartbeat assignment/signature/quote against their actual signed configuration.
The kernel joins current protected assignment/load/publication, complete prior
heartbeat originals and committed results, and latest durably observed opening.
The exact original and result are retained in the EXISTING protected
`policy_canary_intake_batches` journal by the same atomic intake transaction;
no generic table, public success DTO or readiness row is introduced.

An embedded heartbeat in `nativeCumulativeCheckpoint/v1` is independently
reverified under the current heartbeat policy before the protected consumer
requires its exact prior committed original/result. Current policy validation
does not renew the heartbeat's original expiry or turn observation into effect
permission. All old intake kinds and their old authority checks remain intact.

Limits are explicit: 32 heartbeats, 64 KiB each and 512 KiB aggregate retained
heartbeat originals, on top of the existing finite batch/query/frame limits.
Accounting retains at most 64 receipt originals / 512 KiB under the existing
shared shadow queue budget. Nothing truncates, evicts, overwrites or widens the
global proof ceiling. Capacity exhaustion, changed generation, a continuity gap,
attempt uncertainty or signing/delivery failure permanently poisons the local
heartbeat chain. One lost acknowledgement never opens a replacement contact.
Authenticated observation of existing delivery state cannot construct a new
heartbeat sender after process loss.

## Remaining acceptance

This produces and independently consumes native heartbeat evidence and connects
it to the complete-ledger cumulative path. It is not itself a full native
checkpoint/readiness seal. Idle/final sealing cadence, complete cumulative
coverage/currentness/counters and the corresponding final readiness consumer
remain required; an absent idle heartbeat is not no-ingress proof. Runtime
build, consolidated tests and real deployment acceptance are deferred. No
provider/network/cloud operation was performed while authoring this slice.
