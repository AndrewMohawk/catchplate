# Registration execution handoff admission

[`authority_registration_execution_handoff.py`](../serverware/authority_registration_execution_handoff.py)
provides private original-input helpers for control-plane SQL and
completion caller. It performs no network exchange, SQL, signing, storage or
automatic retry and creates no work allowance. The source is unbuilt and
unexecuted; no public caller or production acceptance gate is activated.

## Original scope before a send

`_admit_sql_on_configuration` takes the same keyword inputs as
[`authority_registration_execution_sql_admission._admit_on_configuration`](../serverware/authority_registration_execution_sql_admission.py):

- Grant raw10: caller authorization, signed planning request3, signed planning
  response4, complete before-vector and signed grant.
- Reservation raw3: original reserve request, snapshot and state acknowledgment.
- Independently admitted configuration/digest, generation, runtime identities,
  original caller/grant/current-root enrollments and actual root key.
- Independently current pending sequence/head/fence, original epoch and
  monotonic deadlines, and the caller's existing work ledger.

The genuine configured original exchange derives historical expectations and
planner/evidence keys. Bare submitted expectations, returned heads and prior
successful-verification objects cannot replace that admission. Caller-purpose
and grant controls must be live; a signed historical reserve acknowledgment
cannot admit itself as the current pending head.

After original control/history admission, the helper invokes the actual full
`authority_successor_execution_admission._admit_on_work`. This authenticates
the pending controls, genuinely replays the plan and joins the original grant
to the same-call computation. It does not merely check a received signature or
return a posted marker. The remote SQL owner must still perform its own genuine
admission; this preflight result is never sent as a replacement trust token.

The private `_AdmittedSqlHandoff` contains the original issuer arguments,
`live_window`, `deadline_ns`, retained `live` guard and genuine replay `marker`.
It returns no selected rows or executable mutations. A shorter reserve expiry
clips the existing opening bracket; nothing extends the caller/grant window or
inherited deadline. The owning caller must invoke the same guard around the
actual send, receive and subsequent response check.

## Unsigned SQL response checking

`_verify_sql_response_on_work(response_originals=..., expected_marker=..., work=...)`
accepts the [SQL service's exact raw4](registration-execution-sql-service.md#fixed-raw13-request-and-raw4-outcome)
and the marker from that same private preflight. It snapshots the marker before
native callbacks, checks the actual transport shape, and for `observed-commit`:

1. Joins the pending locator to the genuine marker's pending-decision digest.
2. Reuses the actual SQL owner's bounded, source-fixed marker parser and
   canonical check.
3. Requires canonical equality of the entire marker, not a selected-field match.

It returns only the unchanged raw4. An `uncertain` outcome raises the static
`RegistrationExecutionHandoffUncertainError`; it does not become a verified
commit, noncommit, receipt or retry permission.

This response is unsigned. Both IDs remain selectors; in particular, the packet
ID is not part of the marker and acquires no independent authenticity from the
comparison. The returned marker does not substitute for protected committed-state
readback, signed completion, independent currentness or credential finalization.
This private comparison is not a public API accepting caller-chosen markers.

## Explicitly live-only completion handoff

`_verify_live_completion_on_configuration` takes the same configuration,
grant raw10, reservation raw3 and independent pending/deadline/work inputs,
plus completion `response_originals`. The complete original inventory, including
the response and enrollments, remains within the shared 64 MiB ceiling before
native callbacks.

It performs actual configured exchange/caller/grant admission, then invokes
[`authority_registration_completion_response._verify_on_work`](registration-completion-response.md)
on the genuinely derived historical plan inputs and scope. That receiver performs
the heavy replay once and authenticates the original completion, state receipt
and observation. The live caller/grant guard is required both before and after.
Only the receiver's original bytes and authenticated content IDs are returned;
no result object is accepted at the incoming boundary.

This is **not historical completion recovery**. The original verifier-signed
planning request, planner-signed response, caller authorization and grant must
still satisfy their existing live gates. The adapter never disables expiry or
opens an unbounded replacement window to accept an old exchange.

The remaining historical integration gap is explicit:

- `authority_registration_execution_exchange._admit_on_configuration` invokes
  live planning request/response and history-admission helpers.
- `authority_registration_execution_authorization._verify_on_work` retains the
  original authorization expiry and rejects it after expiration.

Consequently, this caller adapter can reject a late completion even when the
lower-level [returned-original verifier](registration-completion-response.md)
can authenticate its historical signatures, or the separately admitted
[cold completion owner](registration-execution-completion-service.md) can recover
an unchanged retained original. Genuine historical admission of the original
planning exchange and caller authorization remains required for a later
control-plane recovery integration. A receipt, decoded context or live-only
success must not be relabeled as that missing authority.

## Remaining caller responsibilities and deferred verification

Present actor/purpose permission, actual transport peer/deadline ownership,
independent current pending authority, durable original retention and uncertain
outcome handling remain the caller's responsibilities. No execution or
completion endpoint, automatic retry, credential finalization or enrollment
activation is provided here.

After source freeze and prerequisite admission, planned coverage includes
genuine original preflight; wrong configuration/enrollment/pending/grant scope;
complete marker and canonical-wire mismatches; unsigned locator boundaries;
uncertain outcomes; shorter reserve expiry and clock rollback; caller-graph
mutation during callbacks; and late completion rejection without expiry renewal.
No tests, imports or runtime verification were performed for this source batch.
