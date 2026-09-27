# Registration evidence execution reservation

This source-only slice connects genuine original registration grant verification
to a signed current-root reserve and separate durable reserve delivery. It is
unbuilt and unexecuted. It does not add a public execution action, a cold caller
coordinator, SQL execution or credential finalization.

The fixed operation is `webauthn.registration.evidence.admit`. Its business
effect is admission of the registration evidence receipt, not creation of a
credential or activation of an OIDC session. The distinct
`webauthn.registration.finalize` operation must not consume this grant as its
own permission.

The [cold reserver service](registration-execution-reserver.md) now composes
these components behind a fixed private raw10-to-raw3 exchange. Its independent
cold authority and provisioning remain separate from public caller activation,
protected SQL execution and credential finalization.

## Produce the actual reserve

[`authority_registration_execution_reservation._produce_on_configuration`](../serverware/authority_registration_execution_reservation.py)
accepts the original planning request3/response4, complete before-vector,
dedicated caller authorization and original execution grant. Configuration,
generation, runtime-role identities, root and enrollment originals come from
independently admitted configuration, not from a posted grant or expectation
dictionary.

The producer authenticates the verifier-signed request and planner-signed
response, genuinely replays the plan, and derives the historical expectations
from those originals. It verifies the separately enrolled
[`authorize-registration-evidence-execution`](registration-execution-authorization.md)
authorization and joins the actual request/operation identities and original
issue/expiry intervals. The grant's original identity becomes the reserve's
capability commitment; a caller cannot substitute a capability digest or a
successful-verification object.

The actual independently enrolled computation key signs the reserve. Its
predecessor sequence, predecessor head and next fence are independently held
inputs. Neither the incoming grant nor its observed before-vector establishes
the latest state or supplies that checkpoint. The existing state owner must
still perform its serialized current-vector, predecessor, fence and one-use
checks when accepting the reserve.

The result contains the original signed reserve request and computation
snapshot. It is not a pending-decision receipt or permission to execute SQL.
Original authorization, planning and grant expiries and the supplied absolute
deadline can only narrow the operation; loading retained bytes does not renew
them. The producer does not generate a replacement grant after expiry.
The same caller work allowance covers original admission, replay and signing.

## Separate durable delivery

```text
retained grant originals + independently admitted scope/key/checkpoint
    -> genuine replay and signed reserve request + snapshot
    -> enqueue: authenticate and durably retain exact originals
    -> explicit deliver: fixed state peer, original reserve only
    -> authenticate and durably retain original state acknowledgment

protected SQL issuance/execution and credential finalization: separate steps
```

[`RegistrationReservationDelivery`](../serverware/authority_registration_reservation_delivery.py)
owns an actual `CurrentRootJournal` in a separate preprovisioned directory.
It requires the original enrollment/root and an independently current exact
local sequence/head. This is neither the control-plane grant-retention journal
nor the state owner's journal or checkpoint. A valid old local prefix cannot
declare itself current.
At local sequence zero the expected head is the actual enrollment digest;
later heads are framed reservation-record identities. Capacity must equal the
enrolled `maxRecords`, and a new request needs two slots for request and
acknowledgment. An unresolved pending original cannot be replaced.

The fixed owner API is:

```text
RegistrationReservationDelivery(*, journal, enrollment_bytes, root_public_key,
    expected_local_sequence, expected_local_head_digest)
enqueue(request_bytes, *, snapshot_bytes, execution_record_digest,
    expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
    live_window, work, transport_deadline_ns=None) -> original request digest
deliver(request_digest, *, client, live_window, work,
    transport_deadline_ns=None) -> original state receipt bytes
originals(request_digest) -> RegistrationReservationOriginals
inspect() -> RegistrationReservationObservation
close()
```

The originals container has `execution_record_digest`, `request_bytes`,
`snapshot_bytes` and nullable `receipt_bytes`. Reading it after expiry returns
history, not renewed authority. Inspection contains only `sequence`,
`head_digest`, nullable `pending_request_digest` and `acknowledged_count`;
it is unsigned. These library methods add no public route exposing originals.

`enqueue` authenticates the signed reserve and its exact snapshot under the
independently held predecessor/head/fence and `executionRecordDigest`. That
digest identifies the separately retained grant bundle; it is not a grant
verification receipt. Enqueue durably retains the originals before any network
send. New canonical chained records use the dedicated
[reservation record codec](../serverware/authority_registration_reservation_records.py),
not the old grant-retention format or completion-delivery format.

The closed `serverware.registrationExecutionReservationRecord/v1` request
record has eleven fields: `schema`, `kind`, `enrollmentDigest`, `sequence`,
`previousRecordDigest`, `predecessorSequence`, `predecessorHeadDigest`, `fence`,
`executionRecordDigest`, `requestBase64Url` and `snapshotBase64Url`. An
acknowledgment adds `receiptBase64Url`. The separate framed identity domain is
`serverware.registrationExecutionReservationRecordIdentity/v1`.
Original limits are 256 KiB for the reserve, 16 KiB for the snapshot and 16 KiB
for the state receipt; a canonical local record is capped at 1 MiB, 32 nodes
and depth two.
Base64url preserves the exact originals. The codec authenticates reserve and
acknowledgment signatures and the snapshot joins, but the original grant is
absent from this record. Its locator never substitutes for genuine grant replay.

`deliver` sends only the retained reserve bytes through the existing
[`CurrentRootDecisionClient`](authority-current-root-delivery.md#fixed-decision-exchange).
The returned bytes are not trusted because a socket call succeeded. The owner
authenticates the state signature and joins the original request, scope,
predecessor, sequence, fence, vectors and original interval, then durably
records the acknowledgment before returning it. Local storage and an unsigned
inspection result are not independent state authority.

There is no automatic send/retry loop, lookup-peer widening, replacement
signature, pending clear or SQL dispatch. A failure may occur after the state
accepted the reserve or after local durability; it does not establish absence.
Explicit redelivery uses the same exact original. After expiry it can recover
only an already accepted original receipt through the state owner's idempotent
history. An expired, never-accepted reserve is not renewed by a new transport
window or by local retention.

Filesystem durability depends on the provisioned filesystem honoring its
barriers. Local journals are not hostile-host rollback protection. Deadline
checks cannot interrupt every blocked filesystem, socket or driver call;
hard termination still requires an external watchdog.

## Remaining integration

The existing [public preparation handlers](control-plane-registration-execution.md#public-preparation-endpoints)
only prepare and retain grants with their associated signer originals. This
slice does not connect those handlers to reservation delivery or add permission
to execute from a local digest alone.

Before a real execution coordinator can use this path, it still needs:

- Provisioned, independently admitted computation-key custody, state endpoint,
  peer identity, state/local checkpoints and protected journal delivery for the
  [implemented cold reserver](registration-execution-reserver.md). Completion
  remains a separate cold role and key. The existing caller bootstrap supplies
  the caller key and three enrollment originals, not these additional owners
  or authority; its public execution handoff is still unwired.
- The actual [protected successor issuer/executor](authority-successor-execution.md),
  distinct PostgreSQL roles and TLS identities, independently admitted complete
  structural-manifest digest, and a separate durable attempt owner/checkpoint.
  Reservation acknowledgment does not prove SQL commitment; uncertain attempts
  must not be retried automatically.
- Genuine committed-marker/full-vector observation and the distinct
  [completion producer and delivery](authority-current-root-completion.md).
  Completion after expiry can attest an actual prior commit, not revive execution.
- Genuine finalization replay of the original signer request8/response2.
  Prepare-and-retain now durably stores and
  [associates those originals with the grant](control-plane-custody-journal.md#associated-registration-preparation),
  but storage does not authenticate them for later use. The grant raw10 remains
  a different inventory—authorization, planning7, before-vector and grant—and
  must not be reinterpreted as signer originals. Credential finalization still
  requires the evidence-admit business row actually committed and its separate
  operation/purpose admission; it is not activated here.

Independent provisioning, currentness/rollback authorities, deployment and
consolidated frozen-source verification remain outstanding. This source slice
does not close a production acceptance gate.
