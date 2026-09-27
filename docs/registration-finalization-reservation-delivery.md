# Finalization reservation originals and delivery

The fixed `webauthn.registration.finalize` profile has a separate local record
domain, delivery owner and Unix exchange. It reuses the actual current-root
journal and decision client, not an unsigned success carrier. This is
source-only implementation; no build, runtime, provisioning or production
acceptance evidence is claimed.

The [producer and receiving admission](registration-finalization-reservation.md)
perform genuine finalization original replay. The
[cold reserver](registration-finalization-reserver.md) owns its independently
admitted computation key, predecessor scope and separate journal. These
components do not execute SQL, complete registration or activate an OIDC
session.

## Fixed original exchange

The [transport](../serverware/authority_registration_finalization_reservation_transport.py)
accepts exactly ten immutable originals, in order:

1. Dedicated finalization caller authorization.
2. The seven original finalization custody frames, unchanged.
3. Complete before-vector.
4. Original signed finalization execution grant.

It returns exactly three originals: signed reserve request, canonical
computation snapshot and signed state acknowledgment. These bytes still require
receiving authentication; socket identity is not grant or currentness evidence.

Request/response magic is `SWRFRQ01` / `SWRFRR01`. The only endpoint is
`/run/serverware/registration-finalization/reserver.sock`, with the activated
listener's expected peer UID/GID `0:0` and configured timeout of 1–30 seconds.
`_socket_request(endpoint, *, originals, deadline_ns)` requires the caller's
existing absolute monotonic deadline and clips the exchange to it; it cannot
open a replacement request window.

All original, group and aggregate lengths are checked before body allocation.
The request uses the existing finalization raw10 bounds, including the raw7
group checks and 64 MiB combined ceiling. The response caps are 256 KiB for the
reserve, 16 KiB for the snapshot and 16 KiB for the acknowledgment. Exact framing,
request half-close and response EOF reject trailing or truncated inventories.
There is no JSON parser, signing, work allowance, callback-selected operation,
alternate endpoint or retry in this transport.

## Separate durable profile

The [record codec](../serverware/authority_registration_finalization_reservation_records.py)
fixes these values:

| Field | Value |
| --- | --- |
| Operation | `webauthn.registration.finalize` |
| Record schema | `serverware.registrationFinalizationReservationRecord/v1` |
| Framed local identity domain | `serverware.registrationFinalizationReservationRecordIdentity/v1` |

The canonical local request has 11 fields; the acknowledgment adds only the
original receipt. Records are bounded to 1 MiB, 32 JSON nodes and depth two.
Actual enrolled reserve signatures, exact canonical snapshots, full-vector
digests, original interval containment and signed acknowledgment joins are
verified. `executionRecordDigest` is only the local finalization-grant locator:
the codec has no grant original and cannot establish grant provenance or replay
it from that locator.

The [delivery owner](../serverware/authority_registration_finalization_reservation_delivery.py)
is `FinalizationReservationDelivery`, constructed with the actual
`CurrentRootJournal`, original enrollment/root key and independently current
`expected_local_sequence` / `expected_local_head_digest`. Its directory must be
separate from evidence reservation, state, completion and SQL-attempt journals.
At genesis the local head is the actual enrollment digest; later heads use the
distinct local record identity domain. Authentic recovery of a prefix does not
establish that it is the current prefix.

Private shared mechanics select only the three exact source-owned delivery
classes and fixed record profiles. Existing evidence-reservation public APIs,
formats and domains remain unchanged; callers cannot supply a codec or
operation. This avoids duplicating the durable state machine while retaining
separate finalization records and owners.

```text
genuine original replay + independently admitted predecessor/head/fence
  → enqueue: authenticate and durably retain reserve + snapshot
  → explicit deliver: send that original through CurrentRootDecisionClient
  → authenticate and durably retain state acknowledgment
  → return unchanged originals
```

`enqueue(...)` reserves space for both request and acknowledgment, and one
unresolved request blocks another. The local journal capacity must equal the
enrollment's admitted capacity. Exact unchanged enqueue is idempotent; remapped
originals/scope and repeated operation, capability or state ancestry fail.
`deliver(...)` accepts the actual decision client and supplied live window/work
budget. Neither phase learns an independently current predecessor from the
returned acknowledgment.

`originals(request_digest)` and `inspect()` expose ordinary retained historical
data and local metadata, not a current-head lease or execution permission. They
perform readiness/owned-journal checks without opening new verification work.
The private `_original_for_execution_on_work(...)` lookup additionally requires
the independently supplied predecessor/head/fence and existing work budget.
Cold construction/recovery performs original record authentication; request
verification and delivery retain the request's supplied work/window.

## Recovery and remaining boundaries

Network or verification uncertainty keeps the pending original. Local
publication uncertainty poisons/closes the owner; a late failure can occur after
durable publication. There is no pending reset, automatic cleanup, replacement
signature, automatic retry or lookup-peer widening.

A separately admitted, explicit unchanged redelivery can recover a receipt
that the state owner already accepted, including after the original expired.
It cannot authorize an unaccepted expired reserve or renew its grant lifetime.
Recovery across cold starts still requires an independently current local
journal checkpoint and the same admitted original predecessor scope. A genuine
historical acknowledgment is not independently current pending-head authority;
a live receiver may reject it after expiry.

These APIs do not provision keys, directories, socket access or database roles.
They do not activate a public reservation caller, grant present execution
consent, perform one-use SQL, sign completion or finalize a credential. Native
filesystem/network calls still require an external watchdog; bounded checks do
not prove hard-kernel termination.

## Deferred frozen verification

After source freeze, planned coverage includes unchanged evidence-profile
compatibility; cross-profile and signature/snapshot/scope tampering rejection;
raw10/raw3 bounds, peer, EOF and inherited-deadline failures; independent
checkpoint admission, conflicts, partial publication and cold recovery;
same-original expired-receipt recovery; and absence of automatic retry or SQL.
This is planned coverage, not executed verification.
