# Read-only delivery-consumption acquisition

This `.158` source adds a real configured PostgreSQL reader for
`oidc.session.activation-delivery.consume`. It is unbuilt and unexecuted. It
does not sign a plan, consume a delivery, mutate SQL, release plaintext or
establish fresh user permission.

`OidcSessionActivationDeliveryReadPlanner` in
[`authority_oidc_session_activation_delivery_planning.py`](../catchplate/authority_oidc_session_activation_delivery_planning.py)
holds the exact configured read DSN, connection timeout, database/TLS identity
tuple and clock-skew policy. The actual shared reader opens one SERIALIZABLE
READ ONLY DEFERRABLE transaction, checks the configured identity and source
manifests, and closes its cursor, transaction and connection before returning.
It accepts no caller cursor, SQL, callback or successful-verifier object.

## Explicit original-input calls

```text
acquire(*, request, business_before_roots, authorization_before_roots,
        expected_counted_heads, live_window, transport_deadline_ns, work)

acquire_transition(*, request, business_before_roots, authorization_before_roots,
        expected_counted_heads, old_token_bytes, expected_delivery_id,
        expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id,
        authn_policy, trust_policy, live_window, transport_deadline_ns, work)
```

Each call owns mutable inputs before callbacks and retains the original work,
window and absolute deadline. Exact class/PID/configuration and a nonblocking
owner lock protect the invocation. Sticky clocks and cumulative-budget checks
surround native cursor work and final cleanup; insufficient remaining libpq
connection time fails closed. Observed database time, primary roots and the
exact sorted seven counted heads must match independent expectations.

The real [read declarations and proof engine](oidc-session-activation-delivery-reads.md)
acquire ten primary observations, seventeen QueryReads and seven complete-range
frontiers. Shared transaction, acquisition and trace gates admit this exact
consume family, not a caller-selected profile or arbitrary index subset. Its
five writable delivery indexes are already included in the seven read heads;
the other two heads are read-only. Older operation profiles and bounds remain
unchanged.

The full method genuinely invokes the
[old-token/current-policy transition](oidc-session-activation-delivery-consumption.md)
on those originals before acquiring five actual indexed-write frontiers for
its three effects. It generates no token or ciphertext and uses no AES key.
The actual semantic expiry continues to bound proof acquisition and return;
the audit-capacity effect is not added twice.

## Owned data, not planning authority

`_AcquiredDeliveryReads` contains `request`, `database_now`, `selected_rows`,
`query_reads`, `business_before_roots`, `authorization_before_roots`,
`before_proofs`, `read_heads`, `query_frontiers` and `trace`.
`_AcquiredDeliveryTransition` adds the actual `transition`, seven
`counted_before_heads` and five `write_inputs`. The
[write-original codec/replay](oidc-session-activation-delivery-writes.md) accepts
those original proof inputs, not this result as a successful-admission token.
Downstream signing or execution must independently reverify the originals and
admit caller, completion, current-root and policy authority.

The source registry exposes this real **read-acquisition factory** and a
separate [stateless acquire/sign owner](oidc-session-activation-delivery-plan-owner.md).
That owner genuinely replays original state, completion provenance and indexed
effects through the signed-plan producer; no legacy `kernel_factory` is installed.
Cold custody, durable original retention, authorization, reservation,
protected execution, original commit admission and one-use
[release custody](oidc-session-activation-release-custody.md) remain separate
integration work. No database role, TLS files, account or service was provisioned,
and no test, import, parser, formatter, build or runtime command was run.
