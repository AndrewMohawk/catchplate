# Consume execution caller controls

This source-only foundation adds a distinct live post-plan caller purpose:
`authorize-oidc-session-activation-delivery-consume`, fixed to
`oidc.session.activation-delivery.consume`. It is not an execution grant,
public permission, SQL composition or token-release path. No source was built,
imported, tested or executed for this checkpoint.

## Original authority and exact controls

The dedicated caller enrollment is root-signed and genuinely joins the original
current-root enrollment and [consume-only grant enrollment](oidc-session-activation-delivery-execution-enrollment.md).
It binds configuration, database, generation, both enrollment identities, caller
identity/key/measurement, grant-authorizer audience and the independently supplied
consume-planner and operation-root key pins. Caller keys must be distinct from
root, current-root computation/completion/state, grant-authorizer and planner keys.
The generic activation/registration grant enrollment is not a fallback.

`authority_oidc_session_activation_delivery_execution_expectations._capture_on_work`
owns only closed data `{request, scope, journalDigest}`. It verifies the actual
typed consume request/operation commitments; it admits no keys, clocks, private
owners or successful replay carriers. The scope is the actual fourteen-field
consume planning scope. Capturing policy JSON does not authenticate that policy.

`authority_oidc_session_activation_delivery_execution_authorization` exposes
explicit `_produce_enrollment_on_work` / `_admit_enrollment_on_work` and live
`_produce_on_work` / `_verify_on_work`. The latter accept immutable raw2 originals
`(signed consume plan, encrypted consume-original bundle)`, independent expectations,
complete before-vector bytes, the three enrollment originals, root/configuration/
planner/operation pins and the supplied processing window, inherited deadline
and shared work. Private `_capture_on_work` / `_verify_held_on_work` compose the
same original verification, not an externally supplied successful result.

Before caller signing, the actual consume-plan schema/source commitments,
planner signature, request/operation identity, planner identity/configuration and
live original interval are checked. The signed controls bind that exact plan,
the purpose-separated framed raw2 identity, independent journal digest and the
digest of a genuinely decoded, source-validated complete before-vector. The
[bundle framing](oidc-session-activation-delivery-execution-bundle.md) is checked
without AES or plaintext; framing and the caller signature do not prove that
the ciphertext replays successfully or that its stored roots are authoritative.

## Time and remaining connection

The producer generates its own nonzero 32-byte random nonce and samples real
current issue time after known-plan authentication. The entire caller interval
must fit the original signed plan interval; it cannot backdate authorization or
renew the plan. Every graph is detached before hash/key/clock callbacks. Original
bytes have a combined 64 MiB ceiling; all work uses the same supplied ledger.
Current epoch/monotonic checks are sticky, and only narrower processing bounds
are allowed through final original readback and return. There is no historical
or expired-consume authorization mode.

The verifier returns private same-call identities and a current guard, not
executable effects or permission that another API may accept in place of
originals. First-exact encrypted export, independently admitted receiving custody
and full proof replay, actual consume grant production/cold service, reservation,
one-use SQL and completion/recovery remain open. Independent present-user
permission and caller-key delivery are still separate obligations. This partial
foundation does not close token-release detail row 11 or any production gate.
