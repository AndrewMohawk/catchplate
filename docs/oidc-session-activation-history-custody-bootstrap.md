# Historical activation custody bootstrap

These source-only profiles admit separate fresh, independently root-authorized
receiving purposes for historical activation completion and request-bound
delivery-consumption planning or grant receiving. None extends the live
execution-custody consumer map, relabels a live SQL issuer or renews an expired
planner launch. It is unbuilt and unexecuted; no key, account, descriptor,
filesystem path or service is provisioned by this module.

## Fixed purpose and original bytes

`oidc_session_activation_history_custody_bootstrap.py` defines:

- Envelope/signature domain
  `serverware.signedOidcSessionActivationHistoryCustody/v1`, with payload schema
  `serverware.oidcSessionActivationHistoryCustody/v1`.
- Operation `oidc.session.activate`, consumer role `completion-history`, process
  mode `oidc-session-activation-completion`, and fixed UID/GID `65503:65503`.
  This dedicated identity was unused in the existing scoped process/unit source;
  declaring it is not account or ACL provisioning.
- An 8 MiB outer original bound, 256 JSON nodes and depth four. The embedded
  planner original retains its actual 4 MiB bound and is represented by exact
  canonical base64url, byte count and SHA-256 digest. The outer decoder/canonical
  encoder uses its own 8 MiB allowance, not the inner 4 MiB decoder.

The closed payload binds source revision, operation, consumer/process/UID/GID,
the exact three-field receiver identity, configuration/generation/runtime-closure
digests, independent bundle/delivery key digests, the original planner-bootstrap
descriptor, and issue/expiry. `trustMode` is exactly `trusted-host-local`;
`hardwareBacked`, `nativeStageZero`, `hsmBackedKeys`, `teeVerified` and
`externalWitnessVerified` must all be false. Receiver identity is an independent
root assertion, not measurement evidence or proof of hardware custody.

Both layers require actual original root signatures and canonical bytes. The
embedded original must be planner bootstrap **v3**, with its genuine
configuration and runtime cohort, dedicated planner key/identity, RP/origin and
non-weakened authentication/trust policy, database/read-role/TLS declarations,
complete vector and independently signed state enrollment. All inner resource
fields retain their closed source grammar; historical admission does not open
those resources. Bundle/delivery key pins must match between the fresh outer and
genuine inner original and remain distinct from each other and the inner journal
key. No private key bytes occur in either payload.

## APIs and separate time obligations

`_verify_on_work(*, custody_bytes, root_public_key, work, live_window,
transport_deadline_ns)` accepts only immutable original bytes and the actual
independent root key. `_produce_on_work(*, payload, root_private_key,
root_public_key, work, live_window, transport_deadline_ns)` captures and admits
the same independent claims and original inner bytes before actual root signing.
Both require the supplied current window and a positive inherited absolute
deadline. They share cumulative work and never open another allowance.

The frozen ordinary `_HistoryCustodyMaterial` contains `custody_bytes`,
`planner`, `consumer_role`, `process_mode`, `service_uid`, `service_gid`,
`receiver_identity`, `bundle_key_digest`, `delivery_key_digest`,
`attestation_interval`, `opening_sample` and `consume_request_bytes` (exactly
`None` for v1). No verifier accepts this result as
an incoming proof. A real process-bound owner must independently receive and
compare its expected receiver identity, reauthenticate the originals, and join
the actual nonserialized keys before any private opening or retained-outcome I/O.

Only the **fresh outer** interval authorizes current receiving use. It must be
live, at most 300 seconds long, and remain inside both its original bracket and
the caller's unchanged processing bound throughout admission/signing/return.
Exported `_fresh(interval, work, opening=None)` is for that outer interval only.
The new interval need not fit within the expired planner interval: it authorizes
a separate historical purpose, not more time for the old live purpose.

The narrow `oidc_session_activation_planner_bootstrap._verify_historical_on_work`
requires `bootstrap_bytes`, `root_public_key`, `live_window`,
`transport_deadline_ns` and `work`. It authenticates the genuine original before
using the shared purpose-neutral configuration/policy/key/vector/enrollment
admission. The original planner interval must still be positive and source
bounded, and its issue cannot be in the future against the actual current clock.
Past expiry is permitted without calling the live verifier at an old time.

Its ordinary `_PlannerMaterial.attestation_interval` remains the original old
interval. Its `opening_sample` is a real **historical-processing** sample, not
evidence that the old launch is live; it must not be passed to `_fresh` to obtain
current authority. The receiving owner retains the outer opening separately.
Original plan/row/state lifetimes remain algebraic obligations of the
[historical exchange](oidc-session-activation-historical-exchange.md).
Existing planner live verification and production retain their unchanged
signatures and expiry gates.

## Separate consume-planning v2

The v1 helpers and default `OidcSessionActivationHistoryCustody` constructor
remain completion-only at UID/GID `65503:65503`. They never auto-detect or accept
the new profile. Explicit `_verify_consume_on_work` and
`_produce_consume_on_work` use the same original-input signatures but select only:

- `serverware.signedOidcSessionActivationHistoryCustody/v2` and
  `serverware.oidcSessionActivationHistoryCustody/v2`;
- operation `oidc.session.activation-delivery.consume`, consumer role
  `consume-planning-history`, process `oidc-session-activation-delivery-planner`,
  and UID/GID `65501:65501`;
- one additional `consumeRequest` original descriptor, with canonical base64url,
  byte count and SHA-256 digest. Its decoded original is bounded to 2 MiB and
  shares the outer 8 MiB/cumulative work allowance.

Admission verifies the current source's exact typed consume request, handler,
manifest, request digest, operation ID, argument grammar and business intent.
This is an expected request identity, not proof of present token possession,
current rows, a consumption commit or release permission. The genuine nested
planner remains historical **activation** evidence. The fresh consume purpose
does not renew that planner or allow signing completion.

The fixed `OidcSessionActivationHistoryCustody.for_consume_planning` factory
requires an independently supplied `expected_consume_request` as well as the
existing original bootstrap/root, expected receiver identity, separate bundle
and delivery keys, and unchanged current window/deadline/work. It joins the
independent request to the root-signed canonical original before key use and
retains it immutably. The same owner class retains exact purpose-specific
UID/GID, process mode, no supplementary groups, PID, lock and configuration-seal
checks; it does not accept a subclass or a successful material carrier.

See [consume-planning history custody](oidc-session-activation-delivery-history-custody.md)
for the actual replay and caller-purpose joins.

## Separate consume-grant receiving v3

`_verify_consume_grant_on_work(*, custody_bytes, root_public_key, work,
live_window, transport_deadline_ns)` and the analogous
`_produce_consume_grant_on_work(*, payload, root_private_key, root_public_key,
work, live_window, transport_deadline_ns)` select only:

- `serverware.signedOidcSessionActivationHistoryCustody/v3` and
  `serverware.oidcSessionActivationHistoryCustody/v3`;
- operation `oidc.session.activation-delivery.consume`, consumer role
  `consume-grant-history`, mode
  `oidc-session-activation-delivery-execution-authorizer`, and UID/GID
  `65500:65500`;
- the same exact request-bound payload grammar and original byte/cumulative
  work caps as v2, including the independently root-signed `consumeRequest`.

This fresh signature is a separate receiving-purpose authorization, not a v2
planning launch renamed by the caller. It genuinely admits the historical
activation planner original, exact configuration/runtime/source cohort, vector,
enrollment and historical bundle/delivery key pins. The unchanged material
fields expose the actual v3 `consumer_role`, process/UID/GID and immutable
`consume_request_bytes`; no material is accepted as proof input.

`OidcSessionActivationHistoryCustody.for_consume_grant` has exactly the same
keyword arguments as `for_consume_planning`, including independent expected
receiver identity and consume request. It retains the fresh v3 opening and
current inherited bound, never the expired historical launch as a clock.
Private configuration appends `consumer_role`; the legacy `consume_planning`
flag remains true only for v2 and is checked for consistency at each snapshot.
Dispatch uses exact fixed roles. Existing bool-only helpers still reject a
string or any other truthy substitute; v1/v2 entrypoints do not accept v3.

The grant receiving path must additionally require the exact v3 owner and bind
the independently expected request. `require_consume_grant_on_work(*, work)`
remains v3-only. The shared read-only
completed-activation provenance suffix accepts explicit request-bound custody;
planner construction remains v2-only and completion/recovery remains v1-only.
Neither this history admission nor that semantic suffix issues a consume grant,
executes or completes consumption, or releases a token. The new consume-bundle
key, receiving execution authority and cold grant service are separate joins,
not supplied by these two historical activation keys.

## Separate consume-reserve v4 and SQL-issuer v5

`_verify_consume_reserve_on_work` / `_produce_consume_reserve_on_work` and
`_verify_consume_sql_issuer_on_work` / `_produce_consume_sql_issuer_on_work`
retain the same explicit original/key/work/window/deadline signatures, but select
only separately signed fixed profiles:

| Version | Consumer role | Process mode | UID/GID |
| --- | --- | --- | --- |
| v4 | `consume-reserve-history` | `oidc-session-activation-delivery-execution-reserver` | 65499 |
| v5 | `consume-sql-issuer-history` | `oidc-session-activation-delivery-execution-sql` | 65498 |

Their schema prefixes are unchanged, with the explicit `/v4` and `/v5` suffixes.
Both bind the real canonical `consumeRequest`, independently expected receiver
identity, exact historical activation planner and private key pins, using the
same bounds and current outer-lifetime checks. Existing v1–v3 APIs never accept
these profiles automatically. The `for_consume_reserve` and `for_consume_sql_issuer`
owner factories use the same explicit arguments as `for_consume_grant`; no owner
is relabeled or borrowed across processes.

The private semantic replay gate admits only v3/v4/v5 receiving histories; v2
planning remains excluded. The outer receiving owner and grant admission still
enforce the exact separately requested purpose. This library scope does not
construct a cold SQL consumer, authorize SQL, prove a latest pending head or
release a token. See [independent consume pending admission](oidc-session-activation-delivery-pending-admission.md).

## Scope and remaining boundary

The outer root independently pins the exact configuration/generation/runtime
cohort and the actual original planner bytes. Both layers require the current
source revision, and every outer pin must equal genuine inner admission. This
is strict same-source, same-configuration history, **not H05 cross-version/key
cohort resolution** and not permission to adopt historical inputs as current
state. The complete vector is original evidence, not a latest-head guarantee.

This bootstrap does not provide a cold FD/key loader, a completion signing
service, a protected committed-marker reader, durable completion delivery or
reconciliation. Generic activation completion APIs remain rejected; the dedicated
completion path requires its separate v1 historical custody. Token release, public caller
permission/recovery, portal integration and production verification remain
separate. Neither a root-asserted host identity nor historical replay establishes
TEE execution, off-host freshness or a one-use delivery result.
