# Historical consume bridge and planner admission

Completion must distinguish three independently admitted roots: R0 authenticated
the old activation evidence, R1 signed the original consume bridge/planner, and
R2 authorizes the fresh completion role. They may differ. A received original
does not choose R1, and neither R0 nor R2 is a fallback for it.

The fresh completion outer must independently pin the R1 public key and exact
original bridge-policy interval. Only after authenticating that outer does its
owner pass those pins to these original-only helpers:

```text
issuer_policy._verify_historical_on_work(
    policy_bytes, activation_planner_bootstrap_bytes, root_public_key=R1,
    expected_policy_interval, live_window, transport_deadline_ns, work,
    _continuity=None)

delivery_planner_bootstrap._verify_bridge_historical_on_work(
    bootstrap_bytes, history_custody_bytes, root_public_key=R1,
    expected_policy_interval, live_window, transport_deadline_ns, work,
    _continuity=None)
```

All arguments are keyword-only. `expected_policy_interval` is an exact tuple
`(issuedAtEpochNs, expiresAtEpochNs)`, not a caller-selected replacement clock.
The bridge-policy module also exposes the first historical API. No helper accepts
a previously successful material in place of original bytes.

## Original evidence, actual processing

The issuer helper accepts only signed policy v2 and returns the distinct private
`_HistoricalIssuerPolicyMaterial`. It verifies the R1 signature and exact pinned
interval, then genuinely admits the old R0 planner and the embedded R1 planner,
their original state-enrollment signatures, complete state-payload compatibility,
generation, keys and resource separation. Supported source/cohort checks remain
unchanged. The original interval must be well formed and not future-issued under
the narrowed clock skew, but elapsed original expiry does not invalidate evidence.

Historical admission never installs that old expiry as a current launch deadline
and never uses the old issue time as a processing sample. The real supplied work,
clock origin and deadline survive; admitted age/skew limits can only tighten them.
The returned `live` guard checks this current processing lifetime, not whether the
historical issuer remains authorized to issue new consume inputs.

The planner helper accepts only original planner v3 plus planning history v7 under
R1. It verifies the signature and original launch containment within the exact
pinned policy interval, then joins that launch exactly to the genuinely derived
history interval (which may narrow policy expiry). It re-admits the original
history/policy through its separate historical API and repeats current-
at-that-time configuration, state, request, key and resource joins. It returns
`_HistoricalPlannerMaterial`, never a live constructor result. Its nested
`history_material.bridge_policy` is the distinct historical policy material:
completion retains its actual `live`, `live_window` and `deadline_ns` alongside
the fresh outer guard. `current_planner` denotes the R1 consume-evidence context;
`historical_root_public_key` remains R0. Neither denotes R2.

Before historical policy decoding, length-only conservative reservations cover
the signed/canonical policy, wrapped current planner, separate old planner and
fixed enrollment/vector inventory inside the existing 64 MiB ceiling. Planner
intake likewise reserves its original/bootstrap/history captures before decoding.
Nested decoders continue charging the same work object. Oversized combinations
fail closed; no additional allowance or total-process-heap bound is claimed.

## Fixed boundaries

Live policy/planner admission still requires live original launch expiry.
Legacy historical planner v2 remains a separate strict API; neither it nor a
schema hint selects the new bridge path. Fresh completion authority and its
purpose-bound resources must be admitted separately under R2, then actual plan,
pending, completion and response algorithms must verify the original controls.
These helpers do not execute SQL, reopen an attempt, renew delivery expiry, issue
new grants, release a token or prove a stored outcome exists.

This implementation is source-only: no build, test, interpreter, runtime, browser,
AWS or provisioning validation was performed.
