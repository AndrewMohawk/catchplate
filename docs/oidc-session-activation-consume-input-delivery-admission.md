# Consume-input staging admission

`oidc_session_activation_consume_input_delivery_admission` authenticates exact
issued consume-planner/history originals against separately provisioned issuer
policy and activation-planner originals. It is public-key-only source: no key
or resource read, process drop, listener, private replay or readiness claim.

```text
_verify_on_work(*, planner_bootstrap_bytes, history_custody_bytes,
    issuer_policy_bytes, activation_planner_bootstrap_bytes, root_public_key,
    live_window, transport_deadline_ns, work, _continuity=None)
```

The only inputs are original bytes, the independently held root and the actual
existing processing allowance. No verified material or expected graph can
replace originals. The private immutable `_DeliveryMaterial` output has:

```text
planner_bootstrap_bytes, history_custody_bytes, planner_material,
issuer_policy_material, planner_identity, history_identity,
live_window, deadline_ns, live
```

The material and its nested actual verifier outputs are same-call facts, not
an accepted authority carrier. `live()` returns the observed current epoch.
The identity fields are canonical ASCII71 bytes from the distinct staging
domains in the [fixed transport](oidc-session-activation-consume-input-delivery-transport.md).

## Independent original and resource joins

The receiver first genuinely admits the independent
[issuer policy](oidc-session-activation-consume-input-issuer-policy.md) and its
exact historically authenticated activation bootstrap. Historical admission
does not renew that old launch. It then invokes the actual live-purpose
consume-planner verifier, which admits the exact root-signed history original
and its nested historical planner; there is no historical fallback for the
newly issued pair.

The independent comparisons cover the complete static planner configuration,
generation/runtime cohort, dedicated key/identity, authentication/trust policy,
age/skew caps, database/read role, TLS/state endpoint, journal/export keys,
launch resource pins, history receiver/AES pins and query manifest. The nested
activation bootstrap and state-enrollment bytes must exactly equal the held
independent originals. Genuine state enrollment supplies database identity;
a DSN spelling does not. The policy's reservation sequence plus one and fence
must match the signed activation scope.

Both new intervals exactly equal the issuer's deterministic policy-derived
interval: policy issue time through the minimum of policy expiry and the
actual activation/source age cap. The known activation scope, including RP,
origin, original planner identity and delivery TTL, is independently joined.
The genuine planner verifier also binds the exact history bytes and the same
typed consume request in both originals.

## Deliberately narrower than request admission

The staging receiver does not receive the ephemeral raw16 request or old
session token. It therefore cannot independently re-derive the full consume
request, target-specific activation expectations, activation authorization
identity, pending-head ancestry or completed after-vector, nor prove original
old-token possession. Those remain authenticated **root-issued data**, not a
claim that this receiver reproduced the request-dependent derivation.

The [original request receiver](oidc-session-activation-consume-input-admission.md)
still authenticates and independently derives the returned pair under the
actual permission. The genuine consume worker still checks the actual request,
history and private/current-row semantics. Staging does not substitute for
either gate and cannot establish consume commit or session authority.

All four originals and a conservative bounded nested/comparison reservation
must fit 64 MiB before admission callbacks. The original work ledger, first
three clock samples and absolute deadline are retained. Policy and pair
expiry only narrow the original window. Optional `_continuity` exchanges
restrictive epoch/monotonic floors; it supplies no permission or allowance.
The returned guard retains the genuine policy and both current pair intervals.

The caller must separately observe and hold the exact authorized resources
before sending a staged ACK. Signed pins are not proof of provisioning,
directory contents, permanent drop or worker readiness. This implementation
is source-only, unbuilt and unexecuted.
