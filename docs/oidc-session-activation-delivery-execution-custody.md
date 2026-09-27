# Consume-grant receiving custody

[`OidcSessionActivationDeliveryExecutionCustody`](../serverware/authority_oidc_session_activation_delivery_execution_custody.py)
owns the separate execution-bundle key and an actual consume-grant historical
custodian. It is source-only: no process, key, account, service or descriptor
delivery has been provisioned or run. It does not issue grants, reserve state,
execute SQL, complete an activation or return plaintext tokens.

## Independent construction

The keyword-only constructor requires four immutable original byte strings:
`custody_bytes`, `planner_bootstrap_bytes`, `planner_history_custody_bytes` and
`receiving_history_custody_bytes`. It also requires an independent
`root_public_key`, `expected_receiver_identity`, the exact32
`execution_bundle_key`, `historical_bundle_key` and `delivery_custody_key`, and
the existing `live_window`, `transport_deadline_ns` and `work`.

The distinct [receiving bootstrap](oidc-session-activation-delivery-execution-custody-bootstrap.md)
authenticates all four originals and their exact joins. The caller cannot pass
a material object, planner owner or claimed verification result instead. Real
key bytes must match the independently root-signed hashes and all three key
purposes must differ. The original consume planner and both historical
purposes are authenticated independently; the receiver does not inherit the
planner's authority merely because the ciphertext came from its service.

Construction requires all real/effective/saved UID/GIDs to be **65500**, no
supplementary groups, and the exact process mode
`oidc-session-activation-delivery-execution-authorizer`. The new
[history v3 purpose](oidc-session-activation-delivery-history-custody.md)
binds this grant role to the actual consume request. Completion-history v1 and
planning-history v2 cannot construct the receiving historical owner. The
historical activation planner remains authenticated old metadata, never a
renewed live execution scope.

The receiver constructs `for_consume_grant` itself from original bytes and
keys, rather than accepting a borrowed custodian. It retains actual private
configuration identities, the original root/enrollment and receiving identity,
and the initial launch clock bracket. Failure closes any constructed historical
owner. Neither construction nor close claims key erasure or malicious-host
protection.

## Genuine original replay

`replay_on_work` accepts only the exact signed `envelope_bytes`,
`encrypted_originals_bytes`, independent closed
`expectations = {request, scope, journalDigest}`, `before_vector_bytes`, and
the existing work/window/deadline. All caller graphs and immutable originals
are held before cryptographic or clock callbacks. The enclosing original
inventory remains bounded to 64 MiB; each existing per-original cap also
applies, and the shared work budget is never replaced.

Each invocation takes the actual owner's nonblocking lock and:

1. Narrows the original allowance to the original receiving/history lifetime.
2. Reauthenticates all four root-bound originals and rejoins the actual
   historical owner, receiver identity, key hashes, request and enrollment.
3. Compares the independently expected request, all six subject identifiers,
   policy, configuration, planner identity/key and complete before-vector with
   those root originals. No stored value becomes an independent expectation.
4. Calls the actual [consume original replayer](oidc-session-activation-delivery-execution-replay.md)
   with the independently admitted planner/root keys, state enrollment,
   activation expectations/scope and actual grant-history owner. The known-plan
   signature precedes ciphertext opening; the original proofs and provenance
   undergo one genuine full replay.
5. Checks the real replay lifetime and returns only its ordinary derived
   metadata, ciphertext originals and a same-call live guard. That guard still
   checks this exact receiver lifecycle and the genuine replay; closing the
   receiver invalidates it. No input accepts this result instead of originals.

`bind_context_on_work` compares an independently supplied root key and exact
current-root enrollment with the retained configuration. It is a static join,
not a live admission or execution permission. `close` invalidates this owner
and closes its historical custodian without deleting ciphertext records.

## Remaining authority boundary

This supplies receiving custody and proof replay, not actual consume-grant
production, verification or its cold service. The generic seven-operation
replay/grant dispatch still excludes consume; the neutral complete-vector
merge used by the private replayer does not change that registry. Fresh public
permission, action-time reservation, one-use SQL, durable completion/recovery,
exact committed-token release and public/portal integration remain separate.
All independent release, hardware and production gates are still open.
