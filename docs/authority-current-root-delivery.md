# Current-root decision transport and completion delivery

Source `.137` adds a fixed private Unix-socket exchange and a durable local
completion-delivery owner. This is source implementation, not a built, tested,
provisioned or running service. It does not enable successor SQL execution,
public finalization, a listener or a production deployment.

## Fixed decision exchange

[`CurrentRootDecisionClient`](../serverware/authority_current_root_transport.py)
holds the admitted socket path, timeout and exact server UID/GID. Its fixed
exchange sends original request bytes and returns original receipt bytes.
These bytes remain opaque to the transport; peer credentials do not replace
the actual request and state-receipt signature checks.

| Frame | Eight-byte magic | Original body bound |
| --- | --- | --- |
| Reserve request | `SWCDRS01` | 256 KiB |
| Complete request | `SWCDCP01` | 256 KiB |
| State receipt response | `SWCDOK01` | 16 KiB |

Each magic is followed by one unsigned 64-bit big-endian body length and the
exact original bytes. Lengths are checked before body allocation. The client
checks the actual peer before sending bytes, half-closes its write side and
requires response EOF. The server requires request EOF. One supplied absolute
monotonic deadline covers the exchange; the configured timeout can shorten it
once but cannot renew it. There is no fallback, retry or error-response frame.

[`CurrentRootDecisionService`](../serverware/authority_current_root_service.py)
admits an actual peer against the configured reserve/completion peer pairs
before reading the prefix, then requires the action's assigned peer. It calls
the actual [durable decision owner](authority-current-root-decisions.md), whose
same-work canonical/signature verification binds the transport action to the
signed request. A receipt is sent only after that owner returns from its
durable publication path. The service owns and closes each accepted socket on
success, failure or cancellation; it does not provision or open the listener.

## Separate local delivery custody

[`CurrentRootCompletionDelivery`](../serverware/authority_current_root_delivery.py)
takes ownership of a fresh, unrecovered actual `CurrentRootJournal` in a
**separate, preprovisioned directory**.
It does not reuse the state owner's journal directory or treat local storage
as state authority. Its local chain records the original complete request
first, followed by the corresponding authenticated acknowledgment record.
The [closed record codec](../serverware/authority_current_root_delivery_records.py)
uses `serverware.policyAuthorityCurrentRootDeliveryRecord/v1`: request records
have eight fields; acknowledgment records add the original receipt as a ninth.
Base64url fields preserve original signed bytes, not reserialized payloads.

Two independent checkpoints are required and have different meanings:

- The exact local sequence/head admits the latest delivery-journal history.
- The exact state pending sequence/head identifies the independently admitted
  reservation being completed.

A valid old signed receipt cannot choose either checkpoint. The local owner
also requires the independently admitted original enrollment and root key.
Journal recovery authenticates originals and their joins; a replayed local
chain alone is not antirollback or independent latest-checkpoint evidence.
At local sequence zero the expected head is the enrollment digest; later heads
are framed original delivery-record identities, not state-receipt identities
or raw filename hashes. Journal capacity must equal enrolled `maxRecords`.
Each new request reserves two record slots, and no new pending completion can
replace an unacknowledged one. Consumed state positions must advance.

The fixed owner API is:

```text
CurrentRootCompletionDelivery(*, journal, enrollment_bytes, root_public_key,
    expected_local_sequence, expected_local_head_digest)
enqueue(request_bytes, *, expected_pending_sequence, expected_pending_head_digest,
    live_window, work, transport_deadline_ns=None) -> original request digest
deliver(request_digest, *, client, live_window, work,
    transport_deadline_ns=None) -> original state receipt bytes
inspect() -> CurrentRootDeliveryObservation
close()
```

The inspection dataclass has `sequence`, `head_digest`,
`pending_request_digest` and `completed_count` fields; it is unsigned, not an
authority token. Live methods use the caller's original work and window.
Cold recovery has the existing fixed allowance per bounded record.
The owner is PID-bound; it neither creates directories nor restarts itself.

The explicit sequence is:

1. `enqueue` authenticates and durably records the exact signed complete
   request before any network operation. It does not sign, send or execute it.
2. `deliver` sends those unchanged bytes once through the fixed client, then
   genuinely verifies the returned state signature and exact request,
   enrollment, scope, sequence/head and original-time joins.
3. Only after the acknowledgment record is durably appended may delivery
   return as acknowledged. `inspect` reports local metadata, not a new state
   receipt or currentness proof.

Re-enqueueing the identical retained bytes and pending scope is idempotent.
Delivering an already acknowledged identity returns its retained original
receipt without another network exchange; it is not a fresh state assertion.

## Ambiguous outcomes and expiry

A disconnect or timeout may occur after the state owner accepted completion.
Before local acknowledgment publication, such a network failure leaves the
exact request pending locally. Local publication failure poisons and closes
the owner and requires checkpoint-admitted recovery. A late failure may follow
durable acknowledgment publication; failure does not prove that publication
was absent. Clock checks do not interrupt native filesystem work or undo
durability barriers.
There is no automatic send loop, replacement signature, request rewrite,
pending clear or re-execution.

The caller may explicitly redeliver that same original request. After its
original expiry, this succeeds only if the state owner already accepted those
exact bytes and returns the original receipt. An expired request that was
never accepted remains blocked and needs independently authorized recovery;
neither a new transport window nor local pending state renews its authority.
Delivery failure is not proof of state noncommit.

## Remaining boundary

This source path does not supply cold enrollment/key custody, authenticated
configuration delivery, trusted measurement, provisioned socket/peer identities,
independent current checkpoints, native durability/host antirollback proof or
an operational recovery procedure. The [completion producer](authority-current-root-completion.md)
still depends on genuine committed-state reads and the original plan/grant
joins. Protected execution/capability custody, installed successor SQL and
triggers, real writer/outer-commit orchestration and public finalization remain
separate prerequisites. The consolidated build/verification phase has not run.
