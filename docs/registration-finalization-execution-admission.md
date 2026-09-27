# Original finalization execution admission

This source-only slice authenticates a distinct finalization-purpose caller
authorization and an actual successor grant against prepared finalization
originals. It returns only the unchanged raw7. It does not issue authorization
or a grant, reserve current roots, execute SQL, finalize a credential or activate
an OIDC session. No tests, imports, builds or runtime verification ran.

## Execution-order prerequisite

**Dedicated finalization authorization must precede production of the plan it
authorizes. Today's public preparation does not make retained raw7 eligible for
a later fresh execution authorization.** The current contracts require:

```text
authorization.issuedAtEpochNs <= plan.issuedAtEpochNs == grant.issuedAtEpochNs
```

The [grant producer](../serverware/authority_successor_execution_grant_production.py)
takes its issue time from `replayed.original_interval` and rejects a plan issued
before its bound request authorization. The
[grant shape](../serverware/authority_successor_execution_grant.py) separately
requires `issuedAtEpochNs == originalIssuedAtEpochNs`; full replay binds that
original time to the actual signed plan. This finalization admission also
rejects a grant issued before its caller authorization. An authorization newly
issued after the existing plan therefore cannot cover that plan. Neither
backdating authorization nor rewriting the retained plan/grant timestamp is a
continuation mechanism.

The future dedicated path must first authenticate the present caller and
finalization purpose, genuinely reconstruct the exact typed request/operation
from signer originals and bounded sibling observations, and issue its original
authorization. It must then produce a new live finalization plan bound to that
same request before grant/reservation/protected execution. Older preparation
remains retained history, not permission to start that sequence or automatically
replan. If the request or live preconditions have changed, the new path must
fail or require separate admission; it cannot relabel the old raw7.

## Fixed original authority

[`authority_registration_finalization_authorization._verify_on_work`](../serverware/authority_registration_finalization_authorization.py)
accepts only the original signed request and root-signed caller enrollment for
`authorize-registration-finalization` / `webauthn.registration.finalize`.
Their closed schemas are
`serverware.signedPolicyAuthorityRegistrationFinalizationAuthorization/v1` and
`serverware.signedPolicyAuthorityRegistrationFinalizationAuthorizationEnrollment/v1`;
each payload uses the corresponding schema without `signed` and with lowercase
`policyAuthority`. Signature domains and original-identity domains are distinct
from evidence-execution authorization.

The enrollment binds the caller public key/measurement, configuration,
database/generation, current-root and successor-grant enrollment identities,
authorizer audience, maximum age and skew. The request binds the same scope,
the exact caller enrollment/measurement, request/operation identities, nonzero
authorization identifier and original issue/expiry. Genuine root/current-root/
grant enrollment admission and caller separation from root, computation,
completion, state, authorizer, planner and evidence keys are mandatory.
Canonical originals and both signatures are actually verified. No bare
caller-chosen authorization digest is accepted as permission.

Evidence-admission enrollment or signatures confer no finalization purpose;
the root must explicitly admit the new delegation. The existing generic
successor-grant enrollment remains its independently root-admitted mechanism,
but the supplied grant must be for **finalization**, bind this exact new
authorization identity and replay the finalization plan. Existing
evidence-admission cold owners are not widened or reused as purpose authority.

## Raw7 and full grant replay

[`authority_registration_finalization_execution_admission._verify_on_configuration`](../serverware/authority_registration_finalization_execution_admission.py)
has keyword-only inputs:

```text
payload, configuration_digest, generation, runtime_role_identities,
originals, before_vector_bytes,
authorization_bytes, authorization_enrollment_bytes,
grant_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
root_public_key, live_window, work, transport_deadline_ns=None
```

`originals` is exact raw7: verifier custody intent, planner custody relay,
transition envelope, proof, inputs, context and separate historical expectations.
The transition raw4 is positions 2–5, not an evidence-admission raw3. The
independently admitted configuration selects actual finalization planner,
verifier and operation-key/policy pins. The real custody verifier authenticates
both controls and all body commitments, joins the separate history to those
pins and genuinely replays the transition. Custody remains retention-only, not
execution permission.

The actual successor-grant verifier additionally replays that raw4 against the
complete original before-vector. It derives the full after-vector and all grant
claims, rather than checking only signatures or vector hashes. The result must
match the new authorization's request/operation, database/generation and
enrollments, and the custody verifier's actual retained-record identity.

All source per-original and group bounds remain, with a complete 64 MiB cap
over raw7, before-vector, authorization, grant and three enrollments. Public
configuration graphs and immutable original references are held before native
callbacks. The authorization is capped at 64 KiB and its enrollment at 16 KiB.
All genuine replays share the supplied cumulative work; none supplies a fresh
allowance or accepts a prior successful-verification object.

## Live time and remaining execution path

This is live admission, not historical recovery. Original caller, custody,
plan and grant intervals must remain live through return. The grant interval
must fit the authorization interval without changing the original plan issue
time. A later caller authorization cannot silently retime an older prepared
plan. The existing processing window stays anchored to its original samples;
authorization/grant expiry, custody sub-windows and inherited transport deadline
only narrow its bound. Sticky epoch/monotonic checks reject reversal. Deadline
checks do not claim to interrupt a blocked native operation.

The existing source already has a real registered finalization transition,
full-vector grant/reserve primitives and protected successor issuer/executor
SQL. Its kernel inserts the credential, consumes the chosen challenge and
committed v2 evidence, invalidates exact OIDC sibling challenges when applicable,
and appends audit. It **does not activate the OIDC session**: that session is
read and validated, not mutated by this kernel.

Still required are dedicated caller enrollment/request issuance under actual
present-caller execution-purpose admission; its cold purpose/key owner;
original grant production and durable finalization association; independently
current predecessor/vector reservation and pending admission; and explicit
protected SQL dispatch/completion orchestration with its irreversible attempt
journal. Session activation remains a separate authenticated transition. The
[retained preparation facade](retained-registration-finalization.md) returns a
raw7 locator only, and the excluded legacy authority dispatcher is not an
execution fallback. Returning raw7 from this verifier is not an action token.

Deferred frozen coverage must include evidence/finalization purpose substitution,
altered root delegation or original commitments, mismatched authentic raw7/grant
pairs, complete-vector drift, key/generation mismatch, original interval escape,
expiry during replay, clock reversal and cumulative work exhaustion. No
production acceptance gate is closed by this source addition.
