# Request-bound consume-planning history custody

This source-only prerequisite adds a distinct root-signed history purpose for
`oidc.session.activation-delivery.consume`. It is not completion signing,
protected consumption execution, committed-release admission or token release.
No keys, account, descriptors or service are provisioned here; the source is
unbuilt and unexecuted.

The [historical bootstrap v2](oidc-session-activation-history-custody-bootstrap.md#separate-consume-planning-v2)
authenticates a fresh outer interval and actual historical planner original on
the supplied current work/window/deadline. It fixes UID/GID `65501:65501` and
mode `oidc-session-activation-delivery-planner`; the v1 completion profile remains
fixed at `65503:65503`. Neither the live execution-custody consumer map nor the
completion signer purpose is widened.

## Exact original and owner joins

The root-signed v2 payload binds the canonical typed consume request original,
not just caller-selected user IDs. Actual source commitment and argument checks
cover delivery/session/user/credential/challenge, old/new token and assertion
digests, and the business intent. The material's `consume_request_bytes` is
ordinary immutable original data, never an incoming admission token.

`OidcSessionActivationHistoryCustody.for_consume_planning` requires:

```text
custody_bytes, root_public_key, expected_receiver_identity,
expected_consume_request, bundle_key, delivery_custody_key,
live_window, transport_deadline_ns, work
```

Both expected identity and request are independently supplied, bounded and
captured before callbacks. They must match genuine root admission. The factory
returns the existing exact owner class, sealed to the fixed v2 process/PID and
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
request, requires v2, and then performs the real historical exchange and signed
completion/ACK joins. It returns diagnostic identities and current processing
liveness only—no original plaintext token, selected rows or executable proof.

Standard completion admission, response verification, request transport,
production and retained recovery require v1 before protected I/O or signing.
The v2 owner cannot enter those paths, and v1 cannot be relabeled for consume
planning. Generic activation completion APIs remain rejected; the dedicated
completion path requires v1 historical custody.

The owner does not create fresh consume read proofs, grant permission, persist a
new signed plan, execute SQL or release plaintext. The separate configured
planner/cold-delivery and durable-original integration must retain these exact
original and purpose joins. Current root/head admission, consumption commit and
one-use release remain separate obligations; local root assertions are not
hardware, off-host freshness or production verification.
