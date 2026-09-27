# Historical activation custody bootstrap

These source-only profiles admit separate fresh, independently root-authorized
receiving purposes for historical activation completion and request-bound
delivery-consumption planning. Neither extends the live
execution-custody consumer map, relabel a live SQL issuer or renew an expired
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
