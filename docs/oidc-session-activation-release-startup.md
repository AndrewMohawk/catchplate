# Root-selected release construction

`oidc_session_activation_release_startup.py` constructs the actual private
outcome store and exactly one root-selected live-release or recovery owner.
It is source-only, unbuilt, unexecuted and uninstalled. Diagnostic 16.1 supplies
resource construction; the finite [service](oidc-session-activation-release-service.md)
now uses its single-connection continuation for 16.2/16.3. Independent response
verification and authorized caller handoff remain separate 16.4/16.5 scopes.

## Actual originals and resources

```text
start_on_work(*, work, live_window, transport_deadline_ns) -> _StartedRelease
start_from_resources(actual_resources) -> _StartedRelease
```

The public entry calls the actual [sealed resource intake](oidc-session-activation-release-resources.md).
The internal alternative accepts only its exact private resource-owner type,
not a caller-supplied bootstrap material or successful verification object.
Intake authenticates public originals before key reading and permanently drops
to UID/GID 65502 in the same PID. Startup independently authenticates the exact
[root bootstrap original](oidc-session-activation-release-bootstrap.md) again.
It never opens a new work allowance or clock bracket after that drop.

The fixed inherited resources are root 198, bootstrap 199, sealed delivery AES
key 200, exact outcome directory 201 and preauthorized listener 202. The actual
startup now accepts and owns one connection for the finite worker; framing and
response I/O remain in the separate service/transport. Its fixed source endpoint is
`/run/catchplate/oidc-session-activation-token-release/release.sock`, with the
separately pinned private peer 65532. There is no public or browser endpoint.

The root-selected `live-release` profile constructs a genuine
`ReleaseOutcomeStore` at checkpoint zero and the actual
`OidcSessionActivationReleaseCustody`. The `recovery` profile instead requires
the separately root-authorized checkpoint-one store and constructs the actual
`OidcSessionActivationReleaseRecovery`. The root original supplies every scope,
caller, producer identity and state-receipt expectation. Incoming proof or record
bytes cannot choose these values or switch profiles.

The sealed composition retains the actual resource/store/selected-owner
configuration identities. Its exact expanded descriptor inventory is the five
inherited descriptors plus the store's one actual `CurrentRootJournal` directory
descriptor, and only while accepted, its one actual owned socket.
`WitnessJournalIO` borrows that same directory descriptor. A fixed 16-entry
proc-inventory bound covers these resources, standard descriptors and the scan
itself without an unbounded repeated metadata walk. Inherited resources, the
owned 0700 directory and the accepted socket are checked against their held
identities; unexpected descriptors or changed owner configuration fail closed.

`accept_on_work()` waits with descriptor-free `select.select` under the original
allowance, then owns a nonblocking CLOEXEC Unix stream. Its native socket and
peer UID/GID 65532 are checked before any header or body. Acceptance has a
separate spent flag: neither a failure nor closing the first connection permits
another accept. The service borrows the socket; it cannot detach or close it.
`close_connection()` performs identity-bound normal close, unregisters that
socket, then rechecks the remaining exact inventory and original allowance.
Uncertain cleanup is sticky and never closes a replacement occupying an old FD.

## Original-only operation continuation

The returned private composition exposes two fixed methods, each admitted only
for its root-selected profile:

```text
open_committed_on_work(*, proof_bytes, proof_enrollment_bytes,
    intent_bytes, intent_enrollment_bytes, old_token_bytes, envelope_bytes)
    -> exact private token bytes

recover_on_work(*, record_bytes, proof_bytes, proof_enrollment_bytes,
    intent_bytes, intent_enrollment_bytes, old_token_bytes, envelope_bytes)
    -> unchanged private token bytes

processing_context() -> (actual_work, original_narrowed_window, deadline_ns)
request_profile() -> root-selected profile under the current guard
accept_on_work() -> one actual startup-owned socket, or failure
close_connection() -> None, or sticky cleanup failure
close() -> None
```

The methods accept bounded immutable originals only. No caller supplies a key,
store, current scope, expected producer/caller, work object, deadline or new
window. They invoke the exact existing [live release owner](oidc-session-activation-release-custody.md)
or [recovery owner](oidc-session-activation-release-recovery.md); no second proof
replay or successful result input substitutes for that original admission.
Recovery additionally compares the record's producer, producer identity, receipt,
caller and complete release binding to independent cold pins before actual
recovery authentication. That data comparison is not itself authority.

The wrapper is spent before the original operation begins. A successful call
leaves the checked composition alive, but cannot authorize a second operation.
`processing_context()` remains available for the fixed response integration;
it returns the held original allowance, not permission to reset it. No future
request receives a new ledger or clock opening. Framing is implemented in the
separate [transport](oidc-session-activation-release-transport.md), not this owner.

## Lifetime, private return and cleanup

Root launch, nested current authorization and live delivery bounds narrow the
same construction window. Post-operation continuation also adopts the actual
store/recovery owner's retained narrowed lifetime. In the live profile this
preserves the genuinely checked intent/proof expiry; historical recovery does
not substitute old expired deadlines for its fresh recovery authority.

Both actual owner and store clock observations are checked against the
pre-operation startup observations. Their maxima are retained before the final
root/resource/current-clock suffix, without incorrectly requiring the earlier
store sample to follow the later custody sample. All epoch/monotonic guards stay
sticky; original first-three clock samples and cumulative work are unchanged.

The token is held locally until the final suffix succeeds. Any post-call root,
resource or clock failure withholds it and closes the acquired owners while
preserving the durable outcome. Explicit close shuts down the accepted socket,
selected owner, store and owned resource descriptors; uncertain cleanup remains
an error across repeat close calls. No file is deleted, replaced or retried.
A failed construction cannot restart in the same process. Python byte objects
cannot be guaranteed erased from memory.

Private method return is not network receipt, one-egress acknowledgment,
present public permission or current-session confirmation. Source integration
does not establish deployment, hostile-host isolation or production acceptance.
