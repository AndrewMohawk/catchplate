# Activation reservation originals and durable delivery

The fixed `oidc.session.activate` profile reuses the actual current-root journal
and decision client with a separate record domain and exact delivery class.
This is source-only implementation: no build, runtime, provisioning or production
acceptance is claimed. It does not perform SQL, completion or token release.

## Fixed records

[The codec](../serverware/authority_oidc_session_activation_reservation_records.py)
fixes `serverware.oidcSessionActivationReservationRecord/v1` and the separate
`serverware.oidcSessionActivationReservationRecordIdentity/v1` local identity
domain. Shared mechanics select only three source-fixed profiles; existing
evidence and finalization schemas, formats, domains and public constructors
remain unchanged. No operation or codec can be supplied by a caller.

The canonical request record has 11 fields; acknowledgment adds only the
original receipt. Limits remain 1 MiB, 32 JSON nodes and depth two, with original
reserve/snapshot/receipt caps of 256 KiB / 16 KiB / 16 KiB. Actual original root
enrollment, reserve and state signatures are checked, together with canonical
snapshot commitments, vector digests, original plan interval containment and
the independently supplied predecessor sequence/head/fence. Acknowledgment
sequence and pending-request joins use those originals, not receipt-derived
expectations.

`_verify_on_work(...)` returns ordinary request payload/digest and optional
receipt payload/digest. `executionRecordDigest` is only a local association;
this codec receives neither the grant original nor encrypted activation bundle
and cannot authenticate either from its locator. The actual producer and
receiving admission must perform genuine original authorization/grant/plan
replay under separately admitted private custody.

## Actual owner and supplied lifetime

[The delivery class](../serverware/authority_oidc_session_activation_reservation_delivery.py)
is `OidcSessionActivationReservationDelivery`. Its keyword-only constructor
requires `journal`, `enrollment_bytes`, `root_public_key`,
`expected_local_sequence`, `expected_local_head_digest`, `live_window`, `work`
and `transport_deadline_ns`. It takes ownership of an actual `CurrentRootJournal`,
including close/poison cleanup on failed construction. The directory must be
independent of state, evidence/finalization reservation, completion, execution
bundle and SQL-attempt journals.

The original enrollment and all recovered records consume the supplied cold
work allowance, with the same original clock window and inherited deadline
checked around recovery and each record. No per-record replacement budget or
clock opening is introduced for activation. Exhaustion or expiry fails closed.
The independent local checkpoint must exactly match recovery; authenticating
a valid prefix does not prove that it is current. At local sequence zero, the
head is the actual enrollment digest. Journal capacity must equal enrollment
capacity, and each request reserves space for its acknowledgment.

`enqueue(request_bytes, *, snapshot_bytes, execution_record_digest,
expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
live_window, work, transport_deadline_ns)` authenticates and durably retains the
first exact request/snapshot before any network exchange. Exact repeats are
idempotent; changed scope or repeated operation/capability/state ancestry fails.
One unresolved request blocks another.

`deliver(request_digest, *, client, live_window, work, transport_deadline_ns)`
uses the actual `CurrentRootDecisionClient` and sends only retained bytes.
Activation requires a positive inherited absolute deadline in both phases;
the bound is the minimum of that deadline and the supplied window's original
monotonic limit. The live caller must preserve its original window/work/deadline
through production, enqueue and delivery, not open a fresh allowance here.
The signed state acknowledgment is genuinely verified and durably retained
before return. An already durable acknowledgment is returned unchanged.

## Uncertainty and original recovery

Network or verification uncertainty preserves the pending original. Local
publication uncertainty poisons/closes the owner; a late failure may follow
durable publication. There is no automatic resend, regenerated request,
replacement signature, pending reset or implicit retry.

An independently admitted, explicit unchanged state exchange can retrieve a
receipt already accepted by the state owner. It cannot make an unaccepted
expired reserve valid. Recovery of stored bytes is not expiry renewal, fresh
latest-head authority, historical execution permission or a reason to repeat
SQL. State reservation idempotence requires no new local SQL-attempt marker.

`originals(request_digest)` and `inspect()` expose ordinary held originals and
local metadata, without creating new verification work. The private
`_original_for_execution_on_work(...)` also requires the independent
predecessor/head/fence and supplied work. Neither local storage nor a genuine
historical acknowledgment supplies independent action-time pending authority.

Cold role wiring, state-peer admission, socket/directory provisioning and
public present-purpose permission remain separate integrations. Native I/O
still needs an external watchdog; source deadline checks are not proof of
hard-kernel termination.

## Deferred verification

After source freeze, coverage must exercise unchanged earlier profiles,
cross-profile/signature/snapshot/scope rejection, shared recovery-budget and
deadline exhaustion, exact checkpoint/conflict recovery, partial publication,
uncertain network outcomes, unchanged explicit state recovery and absence of
automatic retries or SQL. None of that verification was run for this source batch.
