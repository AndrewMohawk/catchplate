# Supported successor replay families

This source-only correction separates registered planning programs from genuine
generic execution replay. It is unbuilt and unexecuted; no execution authority,
runtime result or production gate is claimed.

`authority_current_root_delta.OPERATIONS` covers the source planning registry,
including delivery-consumption planning. That broader inventory does not supply
an original-frame grammar or receiving-custody implementation. Equating it with
the smaller implemented replay inventory made the disjoint-family check reject
every operation after consume planning was registered.

[`authority_current_root_plan_replay.OPERATIONS`](../serverware/authority_current_root_plan_replay.py)
now derives only from its four actual disjoint replay families. `_frame_maxima`
checks that this union remains a subset of both the delta inventory and actual
source-program registry, rejects unsupported operations, and still invokes the
real source-contract check for the selected supported operation.

| Implemented family | Exact supported operations | Original frames |
| --- | --- | --- |
| Revocation | `webauthn.credential.revoke` | raw2 signed plan/context |
| Evidence | `webauthn.registration.evidence.admit`; `webauthn.trust.installation.admit` | raw3 signed plan/inputs/context |
| Transition | `webauthn.registration.finalize`; `webauthn.trust.stage`; `webauthn.trust.complete` | raw4 signed plan/proof/context originals |
| Activation | `oidc.session.activate` | raw2 signed plan/encrypted original bundle |

These are seven operations, not seven interchangeable verifiers. Each retains
its actual frame sizes, aggregate cap, independent expectations, original
signature/proof replay, effects and complete-root joins. Activation still needs
its real independently admitted receiving owner and original live allowance;
this change adds no historical fallback, plaintext key carriage or success
carrier input.

## Exact root delegation and connected consumers

The generic grant enrollment producer and verifier use the same sorted
`replay.OPERATIONS` list. Root delegation therefore names exactly these seven
operations, in canonical order, with no caller operation-list override. A list
that additionally names `oidc.session.activation-delivery.consume` is rejected.
Current-source enrollment admission still requires original root signatures,
database/generation/current-root identity and genuine distinct authorizer
key/policy joins; caller configuration remains a separate authorization binding.

The direct grant-production, grant-verification, computation and pending-plan
admission paths use `_originals` or `_frame_maxima`; protected packet SQL derives
its fixed frame maxima from the same supported inventory. They do not need a
second allowlist or a bypass. The family verifiers, grant fields, packet schemas,
SQL effects and processing lifetimes are unchanged.

`oidc.session.activation-delivery.consume` remains a real registered planning
program with its configured acquisition, signing and retention path. It is
deliberately absent from generic replay and root grant delegation until a real
original receiving replay/custody path is connected. New purpose authorization
or a planner signature alone cannot close that boundary. Consume issuance,
reservation, protected execution, recovery and exact committed token release
are not enabled by this inventory correction.
