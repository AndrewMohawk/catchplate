# Consume-only grant production

[`authority_oidc_session_activation_delivery_execution_grant_production._produce_on_work`](../catchplate/authority_oidc_session_activation_delivery_execution_grant_production.py)
produces original signed grant bytes only after genuine root/caller admission
and one full replay of the private consume originals. It accepts no arbitrary
payload, successful-verification carrier or signing callback.

```text
_produce_on_work(*, authorization_bytes, authorization_enrollment_bytes,
    current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
    configuration_digest, planner_public_key, operation_public_key,
    originals, expectations, before_vector_bytes, receiving_custody,
    live_window, transport_deadline_ns, private_key, work) -> bytes
```

The exact native private key is held and type-checked before shared capture can
invoke any callback. All public originals, keys, configuration, expectations and
the actual receiver are captured on the supplied work. Shared admission
authenticates the original dedicated [consume grant enrollment](oidc-session-activation-delivery-execution-enrollment.md),
current-root enrollment and [post-plan caller authorization](oidc-session-activation-delivery-execution-authorization.md).
Only that genuinely admitted enrollment supplies the authorizer public key;
the producer requires the actual private/public pair before replay or signing.

Shared replay calls the independently admitted
[receiving custodian](oidc-session-activation-delivery-execution-custody.md)
and its [original-proof replay](oidc-session-activation-delivery-execution-replay.md).
The known plan, exact encrypted raw2, journal identity, before-vector, expected
scope and derived effects/results must join. The producer never accepts those
facts as caller-supplied successful results and does not widen generic grants.

## Derive, sign and verify the same original

The payload is constructed only from the same-call admitted bindings and replay
claims. `issuedAtEpochNs` equals the authenticated original plan issue;
`expiresAtEpochNs` is the permitted replay ceiling, bounded by original plan,
caller, receiving/processing lifetime and the enrolled grant maximum age. The
original issue field does not pretend signing occurred at an earlier clock
sample: actual current guards must remain valid throughout production. No
clock opening, work allowance or original authority interval is renewed.

Before signing, the actual shared control and claim checks compare every fixed
binding and original interval. The dedicated wire contract signs with the real
enrolled key, then its signature verifier authenticates the exact output bytes.
The decoded payload must exactly equal the derived payload; control and claim
joins are repeated, retaining the actual original replay/custody/caller guard.
This suffix does not invoke the public full verifier or replay private proofs
a second time. Epoch and monotonic samples must not reverse, and expired output
cannot return after signing or signature verification.

The signed output plus all held admission originals, including the four original
receiving-custody documents, must fit the same aggregate 64 MiB limit enforced
by receiving verification. The per-grant bound and cumulative work charges also
remain in force.

Only bounded, canonical, token-free signed bytes return. No key, plaintext
private document, token or successful-proof carrier leaves this producer. A
separate receiver must independently admit originals and verify the grant;
the bytes alone are not a current execution permission. Cold grant key delivery
and service, reservation/pending admission, one-use consume SQL, durable
completion/recovery and committed-original token release remain separate work.
There is no automatic retry, historical renewal or public permission here.

Source-only implementation: no build, import execution, tests, runtime,
provisioning or installation was performed. This producer alone does not close
the full issuance integration or any production gate.
