# Finalization execution-grant production

[`authority_registration_finalization_grant_production.py`](../catchplate/authority_registration_finalization_grant_production.py)
composes original finalization authorization, genuine custody raw7 and a
complete before-vector with the existing real successor grant producer. It is
source-only, unbuilt and unexecuted. Its output is one original signed execution
grant, not a reservation, credential, successful SQL result or active session.

The private `_produce_on_configuration` accepts independently admitted
`payload`, `configuration_digest`, `generation`, `runtime_role_identities`,
exact raw7 `originals`, `before_vector_bytes`, `authorization_bytes`,
`authorization_enrollment_bytes`, `grant_enrollment_bytes`,
`current_root_enrollment_bytes`, actual `root_public_key` and
`authorizer_private_key`, plus the existing `live_window`, `work` and optional
`transport_deadline_ns`. No caller-selected authorization digest or successful
plan/admission carrier replaces those original bytes.

## Genuine pre-sign composition

1. Bound and retain the complete raw12 input inventory: raw7, before-vector,
   authorization and three enrollments. Individual source bounds and the
   existing 64 MiB aggregate apply before signature/clock callbacks.
2. Run [authorized plan admission](registration-finalization-plan-admission.md)
   on that same work/window. The distinct finalization caller is authenticated
   before genuine raw7 custody/history replay. Actual request and operation
   commitments match; the original plan interval lies inside its prior caller
   authorization.
3. Invoke the existing successor producer with the actual raw4, complete
   before-vector and independently configured planner/operation keys. Its
   genuine replay reconstructs the complete before/after effects and compares
   the exact authorized request/operation **before** the purpose-enrolled
   authorizer signs. A private same-call adapter retains the original clock
   bracket, narrowed deadline and last rollback observations; it cannot be
   supplied through this raw-original API.
4. Authenticate the resulting original grant control and join its operation,
   request, database/generation, enrollments and retained-record identity back
   to the already admitted originals. Final lifetime checks precede return.

The generated signature is not used to invent its own caller authority. The
original root/caller authorization was required before any plan replay or grant
signing. The actual generic producer performs dedicated key pairing/separation,
full-vector validation, claim reconstruction and same-call signed-output checks;
there is no custom crypto or hand-built grant payload in this wrapper.

## No renewal or execution claim

The fixed operation is `webauthn.registration.finalize`. Evidence-admission raw3,
grants and purposes are not accepted as substitutes. The original plan cannot
precede caller authorization, so callers must authorize before producing a new
plan rather than promote an older preparation. All actual replay/signature
work remains cumulative; exhausting it fails closed rather than obtaining a
replacement allowance. Original control/plan expiry and inherited deadlines
only narrow the supplied window; synchronous checks are not a hard watchdog.

This pure module itself owns no key service, transport or durable state. The
[dedicated cold authorizer](registration-finalization-authorizer.md) and
[public grant-preparation path](public-registration-finalization-grant.md) now
connect it to the actual purpose-key owner, bounded raw9 exchange, same-read
complete-vector acquisition and durable raw10/finalization association
referencing the existing evidence/signer association.
That source integration is unbuilt, unexecuted and unprovisioned. It adds no
one-use execution claim, currentness witness, reservation, SQL, completion or
automatic retry. The separate
[execution admission](registration-finalization-execution-admission.md) verifies
original grants for later consumers; neither helper executes credentials.
Atomic credential finalization/outcome handling and separate OIDC browser-session
activation still require their real downstream integration. Independent
provisioning and frozen production verification remain outstanding.
