# Current-root decision transport and completion delivery

Source `.137` adds a fixed private Unix-socket exchange and a durable local
completion-delivery owner; `.138` adds signed read-only lookup and explicit
reconciliation. This is source implementation, not a built, tested,
provisioned or running service. Source `.139` separately adds [protected
successor execution](authority-successor-execution.md): immutable custody,
actual owners, catalog checks, durable pre-database attempts and fixed SQL
source installation. Neither path supplies public finalization, a provisioned
listener or a production deployment.

Registration evidence grants have a separate
[reserve producer and durable reservation-delivery owner](registration-execution-reservation.md).
It uses the existing reserve transport without changing this completion owner
or widening the lookup peer; SQL execution and cold provisioning remain separate.

## Fixed decision exchange

[`CurrentRootDecisionClient`](../catchplate/authority_current_root_transport.py)
holds the admitted socket path, timeout and exact server UID/GID. Its fixed
exchange sends original request bytes and returns original receipt bytes.
These bytes remain opaque to the transport; peer credentials do not replace
the actual request and state-receipt signature checks.

| Frame | Eight-byte magic | Original body bound |
| --- | --- | --- |
| Reserve request | `SWCDRS01` | 256 KiB |
| Complete request | `SWCDCP01` | 256 KiB |
| State receipt response | `SWCDOK01` | 16 KiB |
| Read-only lookup query | `SWCDQR01` | 4 KiB |
| Signed state observation | `SWCDST01` | 32 KiB |

Each magic is followed by one unsigned 64-bit big-endian body length and the
exact original bytes. Lengths are checked before body allocation. The client
checks the actual peer before sending bytes, half-closes its write side and
requires response EOF. The server requires request EOF. One supplied absolute
monotonic deadline covers the exchange; the configured timeout can shorten it
once but cannot renew it. There is no fallback, retry or error-response frame.

[`CurrentRootDecisionService`](../catchplate/authority_current_root_service.py)
admits an actual peer against the configured reserve/completion peer pairs
before reading the prefix, then requires the action's assigned peer. It calls
the actual [durable decision owner](authority-current-root-decisions.md), whose
same-work canonical/signature verification binds the transport action to the
signed request. A receipt is sent only after that owner returns from its
durable publication path. The service owns and closes each accepted socket on
success, failure or cancellation; it does not provision or open the listener.

Lookup is restricted to the configured completion peer, checked before its
body is read. The service calls the exact owner's `lookup`, without a service
parser or second work allowance, and sends the resulting signed observation.
It does not route a query through `apply` or append a state decision.

## Read-only signed lookup

[`CurrentRootDecisionOwner.lookup`](../catchplate/authority_current_root_decisions.py)
accepts the canonical five-field query: schema, source revision, enrollment
digest, requested request digest and a 32-byte challenge encoded as 64 lowercase
hex characters. The [dedicated lookup protocol](../catchplate/authority_current_root_lookup.py)
binds the exact query digest and challenge in a separate state-observation
signature domain, using the already enrolled state key.

Under its existing lock, PID and journal-continuity checks, the owner derives
the observed sequence/head/vector/fence, pending identities and queried history
from its actual state. One fresh observation window is bounded by enrolled age
and the original transport deadline. Lookup does not append, change a fence or
reset pending state.

`accepted` includes the exact original recorded receipt, which is authenticated
again under the enrolled state key. It may be expired; the new observation does
not renew that receipt. `notRecorded` reports only that this serialized history
did not contain the requested identity when observed. It is not proof of SQL
noncommit, cancellation, independent latest-head authority or permission to retry.
Startup still requires an independently current exact checkpoint; a signed
lookup cannot cure startup from a valid but rolled-back journal prefix.

## Separate local delivery custody

[`CurrentRootCompletionDelivery`](../catchplate/authority_current_root_delivery.py)
takes ownership of a fresh, unrecovered actual `CurrentRootJournal` in a
**separate, preprovisioned directory**.
It does not reuse the state owner's journal directory or treat local storage
as state authority. Its local chain records the original complete request
first, followed by the corresponding authenticated acknowledgment record.
The [closed record codec](../catchplate/authority_current_root_delivery_records.py)
uses `catchplate.policyAuthorityCurrentRootDeliveryRecord/v1`: request records
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
reconcile(request_digest, *, client, live_window, work,
    transport_deadline_ns=None) -> CurrentRootDeliveryReconciliation
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

## Explicit read-only reconciliation

`reconcile` always makes a fresh nonce-bound lookup, including when the local
acknowledgment is already durable. It verifies the original signed observation
against its independently admitted enrollment and exact query. Any accepted
receipt must also match the retained original completion and pending scope.
An observed sequence below the retained pending checkpoint (or durable receipt
sequence), or a conflicting head at that same sequence, is rejected.
Contradictions deny the operation; they are not converted into an acknowledgment.

The returned ordinary `CurrentRootDeliveryReconciliation` has fields `status`,
`request_digest`, `state_sequence`, `state_head_digest` and `receipt_bytes`:

The sequence/head describe the fresh state observation, not the local journal.

| Status | Meaning |
| --- | --- |
| `acknowledged` | The original acceptance receipt is authenticated and locally durable. A first acknowledgment is appended before return; an existing acknowledgment must have byte-identical originals and causes no extra append. |
| `pendingUnaccepted` | The queried request is `notRecorded` and the retained expected pending state still matches. This is informational, not database noncommit or retry permission. |
| `stateChanged` | The request is `notRecorded` and the observed state no longer matches that pending scope. It does not authorize replacement, cancellation or reset. |

The latter two statuses carry no receipt. A locally acknowledged request
contradicted by the fresh lookup is an error, not `pendingUnaccepted` or
`stateChanged`. Reconciliation never resends the completion control or executes
SQL; another already in-flight delivery may still be accepted after a lookup.
Recovery for an expired, never-accepted completion remains unimplemented;
a new challenge or observation lifetime does not supply that missing authority.

## Remaining boundary

This source path does not supply cold enrollment/key custody, authenticated
configuration delivery, trusted measurement, provisioned socket/peer identities,
independent current checkpoints, native durability/host antirollback proof or
authorized expired-unaccepted recovery. The [completion producer](authority-current-root-completion.md)
still depends on genuine committed-state reads and the original plan/grant
joins. The `.139` protected execution source path includes actual outer-commit
ownership and maintained SQL effects, but independently admitted cold
configuration, deployed services, authenticated custody recovery and public
finalization/orchestration remain separate prerequisites. The consolidated
frozen build/verification phase has not run.
