# Historical activation state originals

This source-only component authenticates original head/state history. It is
unbuilt and unexecuted. It grants no present currentness, live lease, SQL,
completion, token-release or retry authority. Existing live verification and
signing APIs retain their behavior.

## Separate head verification

`authority_current_root_head._verify_historical_on_work` accepts original
observation/query/enrollment bytes, an independently held root public key and
the caller's real current `live_window`, `transport_deadline_ns` and `work`.
It returns only an owned ordinary observation payload.

The actual root signature enrolls the state key, database/generation scope,
initial vector, limits and measurement. The actual state signature joins the
canonical query digest, preserved 32-byte nonce, context, expected vector and
fixed activation operation. Original role, capacity, sequence/fence, pending
pair and true genesis-vector checks remain identical to the live path.

Observation issue/expiry must form a positive interval within both source and
enrolled `maxControlAgeNs`. Issue in the future beyond the enrolled state skew
is rejected using actual current epoch samples. Past expiry is permitted as
history; no verifier substitutes the original issue time for the processing
clock or invokes live admission at a fabricated historical instant.

The private `_verify_historical_with_enrollment_on_work` exposes the same-call
payload and genuinely verified enrollment only to the state join below. No API
accepts either successful result as an authority input.

## Original activation-plan join

`authority_oidc_session_activation_state._verify_historical_on_work` takes the
same original scope/assertion/token/vector/query/observation/enrollment/root
inputs as live state verification, replacing `now_epoch_ns` with the original
`historical_plan_interval=(issued, expires)` and the supplied current processing
window/deadline/work. Its caller must first verify the genuine signed plan;
the interval alone is not plan authentication.

The wrapper recomputes the exact subject/policy/input context and full-vector
identity, verifies the head originals and rejects either non-null pending
identity. It checks that:

- the original plan interval is positive, within original `maximumPlanAgeNs`
  and no later than the independently held original scope deadline;
- the original plan interval has a nonempty possible processing overlap with
  the head interval under **enrolled state skew** and original head age;
- plan expiry does not extend the signed head observation expiry;
- plan future issue respects original scope skew against the actual current
  clock; head future issue separately respects enrolled state skew.

The producer records `issuedAtEpochNs` from the original processing opening,
not the later signing instant; a valid head may be acquired after opening.
The overlap is therefore checked algebraically as
`max(planIssued, headIssued - enrolledSkew) < min(planExpires, headExpires, headIssued + maxControlAge + 1)`.
The `+ 1` represents the inclusive integer-nanosecond age bound; expiries are
exclusive. No computed endpoint becomes a clock sample or an asserted actual
signing time. The query schema has no timestamps: its exact original
nonce/query/context is joined through the state signature, not given an
invented issue or expiry.

Current processing uses the unchanged supplied opening bracket, cumulative
work and inherited monotonic deadline, with rollback/expiry checks through
return. Old scope, observation and plan deadlines are **not** used to reopen
or replace that current processing window, nor to require expired history to
be live again. Returned observations cannot authorize later work.

This supplies only the historical state portion of full private activation
plan replay. Generic activation historical-completion rejection stays in
place. Dedicated cold historical custody, complete historical semantic/proof
replay, completion signing/delivery and reconciliation remain separate
implementation boundaries; cross-generation authority resolution is not added.

## Historical caller authorization

`authority_oidc_session_activation_execution_authorization._verify_historical_on_work`
has the exact original-input signature of its live verifier. It independently
captures the signed plan/encrypted bundle pair, complete before-vector, caller,
grant and state enrollment originals, expected request/scope/journal identity,
configuration and actual keys before callbacks. It does not use the live
capture path, which would constrain processing to the old scope deadline.

Actual root-enrolled caller key, signature, canonical bytes, purpose, audience,
measurement and configuration/database/generation joins remain mandatory.
Known-plan signature admission, typed-request checks and genuine complete-vector
decoding derive the exact plan, raw-pair, request, operation and before-vector
commitments; the caller signature also joins the independent journal identity.
The original positive caller interval must fit its enrolled age and satisfy
`planIssued <= callerIssued < callerExpires <= planExpires`. Future caller issue
uses the actual current epoch and enrolled caller skew; past expiry is history,
never renewed execution authority.

The distinct private `_HistoricalAuthorization` contains same-call original
facts and a `live()` guard returning actual current epoch under the unchanged
processing window/work/deadline. It is not accepted as an input proof. Genuine
encrypted-original replay and original grant authentication remain separate
mandatory steps. This is current-source/configuration-cohort history only;
older source or cross-generation authority resolution is not supplied.
