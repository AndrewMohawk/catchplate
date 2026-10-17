# Finalization originals before protected SQL

The source-only [finalization SQL admission bridge](../catchplate/authority_registration_finalization_sql_admission.py)
authenticates retained finalization raw10 and reservation raw3 before supplying
original arguments to the actual `SuccessorExecutionIssuer`. It does not open
a database, issue a packet, sign, claim an attempt, execute SQL, complete a
credential or activate an OIDC browser session. Source remains unbuilt,
unexecuted and unprovisioned; no production gate is satisfied by this layer.

The private `_admit_on_configuration` requires:

- Independently admitted configuration, configuration digest, generation and
  runtime identities, root public key, and the three original current-root,
  successor-grant and dedicated **finalization caller** enrollments.
- Exact raw10: caller authorization, custody raw7, complete before-vector and
  original grant. Exact raw3: reserve request, computation snapshot and state
  acknowledgment. Every object/group and their combined 64 MiB bound is checked
  before native verification callbacks.
- Independently supplied **current** pending sequence, head digest and fence.
  These are required inputs, not copied from an acknowledgment, journal scan or
  other successful result. A root-signed expectation is still not a live witness.
- The caller's original `live_window`, inherited absolute
  `transport_deadline_ns`, and existing `work` allowance. No new processing
  window or allowance is created here.

## Genuine original joins

The actual [finalization execution admission](registration-finalization-execution-admission.md)
authenticates the original finalization authorization and custody controls,
complete transition proof and semantics, full before/after vectors and signed
execution grant. Actual configured planner/transition keys are used; no
evidence-admission purpose or caller-selected key is substituted.

The bridge verifies the computation-key signature on the original live reserve
and the state-key signature on the acknowledgment. The actual pending admission
helper joins those originals to the independently held sequence/head/fence,
database/generation, request ancestry and exact original interval; pending
capacity must leave room for completion. The reserve's request/operation and
grant identity must equal the same-call genuine replay and authorization.

It compares the complete canonical reserve vectors with the original raw10
before-vector and actual replayed effects, joins state-receipt vector digests,
reconstructs the exact computation snapshot, and checks its original bytes and
the reserve's signed snapshot digest. A valid signature alone, local association
or matching user ID is insufficient. Neither the plan, grant nor reserve can be
retimed or extended.

## Private continuation, not an authority token

The private `_AdmittedSqlInputs` contains `issue_arguments`, `live_window`,
`deadline_ns`, `live` and `marker_expectation`. Its arguments match the genuine
issuer's original-input API, excluding the separately supplied work/window/deadline. They retain raw4,
original reserve/snapshot/ack, original grant and enrollment, independently
configured keys and the unchanged expected pending pins. No public entrypoint
accepts this result as a successful verification carrier.

`marker_expectation` is the exact eighteen-field source marker derived by the
actual pending helper from this call's authenticated enrollment, reserve,
receipt and reconstructed snapshot. The [private SQL caller](control-plane-finalization-sql.md)
uses it only to compare a returned unsigned observation; it is neither an
accepted input proof nor independently signed completion.

`live()` returns a real checked epoch-nanosecond sample while retaining sticky
clock checks and original finalization/reserve freshness. The returned window
preserves its original opening samples and only narrows expiry/deadline. The
actual protected issuer must still perform its own genuine original pending,
plan and grant admission before custody; the executor separately owns the
irreversible attempt claim and actual protected SQL work.

This bridge grants no present-caller permission, cold process admission,
transport, latest-head observation, automatic retry or completion authority.
[Public reservation](public-registration-finalization-reservation.md) remains
only recorded reservation, not finalization SQL success. Separate current
authority, protected SQL, completion/outcome and browser-session gates remain.
