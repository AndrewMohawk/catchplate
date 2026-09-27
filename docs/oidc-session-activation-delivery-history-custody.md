# Request-bound consume history custody

These source-only prerequisites add distinct root-signed history purposes for
`oidc.session.activation-delivery.consume`. They do not authorize completion signing,
protected consumption execution, committed-release admission or token release.
No keys, account, descriptors or service are provisioned here; the source is
unbuilt and unexecuted.

The [historical bootstrap v2](oidc-session-activation-history-custody-bootstrap.md#separate-consume-planning-v2)
authenticates a fresh outer interval and actual historical planner original on
the supplied current work/window/deadline. It fixes UID/GID `65501:65501` and
mode `oidc-session-activation-delivery-planner`; the v1 completion profile remains
fixed at `65503:65503`. Neither the live execution-custody consumer map nor the
completion signer purpose is widened.

The separate [historical bootstrap v3](oidc-session-activation-history-custody-bootstrap.md#separate-consume-grant-receiving-v3)
fixes role `consume-grant-history`, UID/GID `65500:65500` and mode
`oidc-session-activation-delivery-execution-authorizer`. It uses the same closed
consume-request grammar, but requires a new genuine root signature for that
receiving purpose. There is no v2-to-v3 fallback or shared UID allowlist.

Separate v4 `consume-reserve-history` (reserver mode, UID/GID 65499) and v5
`consume-sql-issuer-history` (SQL mode, UID/GID 65498) use their own root-signed
originals and the same canonical consume-request grammar. Their exact process
modes are `oidc-session-activation-delivery-execution-reserver` and
`oidc-session-activation-delivery-execution-sql`. New `for_consume_reserve` and
`for_consume_sql_issuer` factories use the same explicit arguments below, not a
borrowed grant/planning owner. V1–v3 APIs and fixed purposes remain unchanged.

## Exact original and owner joins

All root-signed v2–v5 payloads bind the canonical typed consume request original,
not just caller-selected user IDs. Actual source commitment and argument checks
cover delivery/session/user/credential/challenge, old/new token and assertion
digests, and the business intent. The material's `consume_request_bytes` is
ordinary immutable original data, never an incoming admission token.

`OidcSessionActivationHistoryCustody.for_consume_planning` and the separate
`for_consume_grant` factory require the same explicit keyword arguments:

```text
custody_bytes, root_public_key, expected_receiver_identity,
expected_consume_request, bundle_key, delivery_custody_key,
live_window, transport_deadline_ns, work
```

Both expected identity and request are independently supplied, bounded and
captured before callbacks. They must match genuine root admission. The factory
returns the existing exact owner class, sealed to its fixed purpose/process/PID and
originals. The ordinary default constructor remains v1-only. Each current use
reauthenticates the original outer signature, policy, original vector/enrollment,
request and actual separate AES keys without accepting a supplied success DTO.

`bind_consume_request_on_work(*, expected_consume_request, work)` compares an
independently captured typed request to that retained original and returns
`None`. This static join does not replace current reauthentication. Actual
`processing_bounds_on_work`, `check_on_work` and `verify_exchange_on_work` retain
the original processing samples, inherited deadline and sticky clocks. Only the
fresh outer interval constrains current use; old planner/plan lifetimes remain
historical algebraic checks, never fake clocks or renewed execution authority.

Before private opening, and again against the genuinely replayed activation
request, the owner joins all eight subject/rotation/assertion fields. It derives
the delivery ID from that actual activation request digest and requires equality
with the root-bound consume request. This ties the new purpose to the original
activation rotation, not an arbitrary activation encrypted under the same key.

## Purpose-specific consumers

The consume plan captures and binds its actual request before using the owner.
The original-only delivery-provenance response suffix explicitly receives that
request, requires explicit request-bound custody, and then performs the real historical
exchange and signed completion/ACK joins. It returns diagnostic identities and current processing
liveness only—no original plaintext token, selected rows or executable proof.

Actual planner construction still requires the strict v2-only
`_require_consume_planning_on_work` gate. The receiving replay separately requires
the private `_require_consume_receiving_on_work(*, work)` before opening and binds
its independent request; only v3/v4/v5 pass that receiving gate. The separate
`require_consume_grant_on_work` remains v3-only; analogous reserve and SQL-issuer
guards are v4-only and v5-only. The outer receiving owner and grant admission
enforce the exact independently root-signed consumer role. V1 completion and v2
planning owners cannot enter receiving execution replay. The shared
read-only semantic suffix is not consume execution, completion or grant issuance.
The appended private `consumer_role` is exact and consistent with the retained
v2-only `consume_planning` flag; no arbitrary truthy purpose selector is accepted.

Standard completion admission, response verification, request transport,
production and retained recovery require v1 before protected I/O or signing.
None of v2–v5 can enter those paths, and v1 cannot be relabeled for a consume
purpose. Generic activation completion APIs remain rejected; the dedicated
completion path requires v1 historical custody.

The owner does not create fresh consume read proofs, grant permission, persist a
new signed plan, execute SQL or release plaintext. The separate configured
planner/cold-delivery and durable-original integration must retain these exact
original and purpose joins. Current root/head admission, consumption commit and
one-use release remain separate obligations; local root assertions are not
hardware, off-host freshness or production verification.
