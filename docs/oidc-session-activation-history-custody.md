# Private historical activation custody

The default `OidcSessionActivationHistoryCustody` constructor is a source-only owner for fixed
purpose `completion-history`, process `oidc-session-activation-completion` and
UID/GID 65503. It does not relabel or widen the three live receiving roles.
The owner itself performs no key delivery or provisioning. The dedicated
[completion delivery](oidc-session-activation-completion-delivery.md) and
[cold service](oidc-session-activation-completion-service.md) now compose it in
source; no public route, installation or runtime result is supplied.

The constructor requires original `custody_bytes`, an independently held root
public key and `expected_receiver_identity`, distinct original 32-byte bundle
and delivery keys, and mandatory current `live_window`, inherited monotonic
deadline and cumulative work. It genuinely verifies the separate
[historical receiving bootstrap](oidc-session-activation-history-custody-bootstrap.md)
and joins the independent receiver identity and actual raw-key digests.

Private sealed configuration retains the original root/bootstrap, AES keys,
canonical historical policy, complete vector, state enrollment and both original
intervals. Exact class, PID, real/effective/saved UID/GID, empty supplementary
groups, fixed process mode, nonblocking lock and unchanged configuration are
checked. Close invalidates configuration and all retained guards.

Two explicit factories use the same exact owner class for different root-signed
request-bound purposes: `for_consume_planning` selects v2 at UID/GID 65501;
`for_consume_grant` selects v3 at UID/GID 65500 and mode
`oidc-session-activation-delivery-execution-authorizer`. Both additionally
require an independently captured `expected_consume_request`. Neither factory
accepts the other purpose's original or reclassifies an existing owner.
See [request-bound consume history](oidc-session-activation-delivery-history-custody.md).
Private configuration appends the exact `consumer_role` discriminator while
retaining the old `consume_planning` flag strictly for v2. Snapshots check their
consistency alongside the original process, PID, seal and request scope.

## Static context and current role admission

`bind_context_on_work(*, root_public_key, current_root_enrollment_bytes, work)`
compares the independently supplied actual root SPKI and exact state enrollment
with the held originals. It returns no permission and performs no replay.

`processing_bounds_on_work(*, live_window, transport_deadline_ns, work)` genuinely
reauthenticates the outer bootstrap and returns `(narrowed_window, bound)`. This
ordinary data preserves all three opening samples and takes the smaller caller
and root-admitted planner age/skew limits. It clips to the fresh outer epoch
expiry, its original monotonic cap and the
earlier inherited deadline. Protected readers, signers and transports must use
these bounds before blocking I/O, not rely only on a post-I/O expiry check.
The pair is narrowing data, not an accepted authority carrier.

`check_on_work(*, live_window, transport_deadline_ns, work)` reauthenticates the
original bootstrap, independent receiver identity, policy/vector/enrollment and
private-key pins under the owner's lock. It returns a guard for current custody
only, suitable before protected reads or exact retained completion reuse. It
does not prove a pending reservation, SQL commit or completion outcome.

Only the fresh outer bootstrap interval authorizes this process now. Its first
actual opening samples are retained; reauthentication never replaces them.
The historical planner interval is original metadata and is never passed to a
freshness check. Sticky epoch/monotonic checks retain the supplied processing
window, cumulative work and earlier inherited/outer deadline through return.

## Genuine historical exchange

`verify_exchange_on_work` requires raw2 `(signed_plan, encrypted_bundle)`,
independent request/scope/journal expectations, complete before-vector, signed
caller authorization and grant, all three original enrollments, actual root,
planner and operation keys, configuration digest and current window/deadline/work.
It accepts no previous material, admission or replay result. Both AES keys stay
inside the owner; they are not method inputs or serialized outputs.

All received graphs and immutable originals are held before callbacks. After
fresh outer reauthentication, the owner binds the supplied root/operation and
planner keys, configuration and fixed policy to the admitted historical cohort.
The before-vector and state enrollment must equal independently root-pinned
originals; a vector learned only from the reservation cannot supply that pin.

The actual [historical caller/grant exchange](oidc-session-activation-historical-exchange.md)
then performs genuine signature, encrypted-original and complete semantic/proof
replay on the same allowance. Its signed plan interval must remain inside the
genuine original planner launch; an independently supplied scope ceiling may be
wider, but neither signed interval is widened. No old expiry clips or renews
the current processing window.

Only the genuine same-call `_HistoricalExchange` facts return. Their `live()`
guard additionally reacquires this owner's nonblocking lock and checks original
outer/current liveness, configuration continuity and the actual exchange guard.
It cannot be called recursively while the owner is in use. No successful result
is accepted as authority at another input boundary, and no generic executor or
live-plan result is produced.

For v2/v3, `bind_consume_request_on_work` must join the independently expected
typed consume request to the root-signed canonical original. Before private
opening and after actual activation replay, the owner also joins subject IDs,
token/assertion digests and the deterministically derived delivery ID to that
request. The current `check_on_work`, `processing_bounds_on_work` and replay
APIs genuinely reauthenticate the appropriate v3 original just as the distinct
v1/v2 paths do, retaining the first outer opening and inherited allowance.

`require_consume_grant_on_work(*, work)` accepts only actual v3 custody;
`_require_consume_planning_on_work` stays v2-only and
`require_completion_on_work` stays v1-only. The private
`_require_consume_history_on_work` permits explicit v2/v3 only for the shared
read-only completed-activation provenance suffix. These static gates return no
proof and do not replace original reauthentication, request binding or full
semantic replay. In particular, v3 cannot enter completion production/recovery,
and historical custody itself neither signs a consume grant nor supplies the
separate consume execution-bundle key.

## Dedicated completion composition

The `.156` [completion bootstrap](oidc-session-activation-completion-bootstrap.md)
independently pins one historical original, packet/authorization/pending scope,
enrolled completion signer, two read-only reader configurations and local
journal checkpoint. Seven fixed descriptors deliver the root/bootstrap,
listener, completion key, journal and distinct bundle/delivery AES originals;
five fixed TLS files support the protected readers after permanent UID/GID
65503 drop. Actual startup constructs this exact owner, not a received material
or successful proof object.

The dedicated [completion/recovery library](oidc-session-activation-completion-recovery.md)
uses real pending and immutable commit admission, completion signing, first-exact
retention and signed state reconciliation. [State v6](current-root-activation-completion-peer.md)
separately fixes activation complete/lookup to peer 65503. The
[private response verifier](oidc-session-activation-completion-response.md)
requires this actual historical owner and genuine original replay too; it is
not a public AES handoff. Existing generic activation completion APIs still
reject rather than acquiring a historical fallback.

This closes step 19's source criterion when `.156` is committed; protected token
release (step 20), public permission/recovery and portal confirmation remain
open. The owner neither retries SQL nor releases tokens, establishes current
session state or resolves unknown historical source/configuration cohorts.
Source is unbuilt, unexecuted and uninstalled; no tests, provisioning or runtime
verification were performed.
