# Retained delivery-consumption plan owner

The `.158` acquisition/signing foundation and `.159` retention source connect the actual
[read-acquisition owner](oidc-session-activation-delivery-planning.md), original
write-proof codec and [consume-plan producer](oidc-session-activation-delivery-plan.md).
It is unbuilt and unexecuted. The owner now requires an actual dedicated
[encrypted journal](oidc-session-activation-delivery-journal.md) and retains exact
originals before returning a plan. It grants no execution, consumes no delivery
and releases no token. The returned journal digest identifies exact ciphertext,
not successful execution or permission to retry.

`OidcSessionActivationDeliveryPlanOwner` holds the exact real reader/configuration,
configured Ed25519 signer and independent identity/SPKI/configuration/policy pins,
original state enrollment/root/vector, actual consume-purpose historical custody owner, activation
planner/operation keys and canonical independently supplied activation expectations
and pending/authorization scope. The required exact journal configuration has
eight fields; source/configuration and actual historical bundle/delivery keys must
match, with a separate journal key. It verifies original enrollment, root/key
joins and current historical-custody bounds. The distinct
[v2 history purpose](oidc-session-activation-delivery-history-custody.md) binds the
actual consume request; completion-only v1 custody is rejected. Supplied policy
and signing pins still need independent cold root admission.

`prepare` accepts the typed consume request, original old token, six independent
delivery/subject IDs, primary roots/seven heads, original head query/observation
and the exact thirteen activation-completion originals. Inputs are captured before
callbacks. Actual state signature/pending/vector projection precedes read-only
acquisition. The real transition derives three effects and actual acquisition
returns five write frontiers. The signed-plan producer then independently replays
the original state, completed-activation provenance and indexed effects; neither
an acquisition result nor a claimed completion is accepted instead.

After genuine signing, the owner serializes the actual owned input graph into
the journal's closed sixteen-field document. It retains the original old token,
read/write evidence, four state originals and thirteen activation-completion
originals encrypted under the separate journal key. The signed plan/head expiry
narrows the original processing allowance before append. Only a durable exact
append permits return; expiry or publication uncertainty is not permission to
re-sign, regenerate, overwrite or execute again.

The public retained-verification signature is unchanged:

```python
verify_retained(*, envelope_bytes, expected_request, expected_scope,
    business_before_roots, authorization_before_roots, expected_counted_heads,
    expected_journal_digest, live_window, transport_deadline_ns, work)
```

It requires a known envelope, independent typed request/full scope,
primary roots/seven heads and the exact expected journal-ciphertext digest. It
owns those inputs, binds the genuine consume-history request and authenticates
the known planner signature and lifetime **before protected lookup**. Bound read
checks the ciphertext identity before decrypting. Restored request/scope, roots,
head expectations, state enrollment/vector and activation expectations/scope must
match the independent configuration and caller pins.

The consume-specific restoration helper rebuilds real `KernelContext`, query
records, counted heads and frontiers from the original bytes; it returns no
verified-result carrier. The owner then invokes actual full plan replay with
independently held keys and custody. This repeats genuine signatures, current
state, completed-activation provenance, possession and indexed effects. The
method never queries the database, signs a replacement, refreshes expired
authority or interprets missing retention as permission to regenerate.

Public verification and the [private consume exporter](../serverware/authority_oidc_session_activation_delivery_execution_export.py)
now share `_verify_retained_locked`, under the actual owner's nonblocking lock
and unchanged configuration. This private path returns the exact retained bytes
and same-call full replay only to the ongoing owner operation; no caller-supplied
successful carrier is admitted as authority. The exporter keeps that lock,
reads before sealing, and genuinely opens any first retained ciphertext to
compare it with those exact replayed originals. It returns ciphertext only.
The public method still returns `PreparedDeliveryPlan`, not this private result.

The same supplied work, original clock samples and inherited deadline cover the
whole composition. Historical custody can only narrow current processing bounds;
an old plan's expiry never becomes the processing clock. Exact class/PID/configuration
and nonblocking locks remain checked, and final serialization/plan-digest creation
must finish within the actual signed plan and head-observation expiry. Export
likewise retains the replay's original validity limit through lookup, sealing,
durable publication or exact-ciphertext reuse and return; storage cannot renew it.

`PreparedDeliveryPlan` contains only immutable `request_bytes`, `scope_bytes`,
`envelope_bytes`, `plan_digest` and `journal_digest`. No token, AES key,
proof-success capability or private original document is returned. Replay
returns the same token-free shape only after full admission and final lifetime
checks. `close()` closes the owned journal and drops same-process configuration
references; it does not close the separately owned history custodian or claim
memory erasure.

The registry's `plan_factory` now constructs this real owner rather than a stub;
its legacy `kernel_factory` remains absent. There is no optional stateless
fallback. The [cold configuration wrapper](oidc-session-activation-delivery-cold-planning.md)
authenticates root-original policy/resources, constructs actual history/reader/
journal/plan owners and preserves the original root lifetime around fixed calls.
The `.160` [OS delivery](oidc-session-activation-delivery-planner-delivery.md) and
[private service](oidc-session-activation-delivery-planner-service.md) connect
that wrapper to one bounded prepare or retained-replay exchange. It is not an
installed consume service. Purpose authorization/reservation, protected SQL,
original commit admission, one-use release, recovery and public/portal handoff
remain open. No tests, runtime, provisioning or deployment were performed.
