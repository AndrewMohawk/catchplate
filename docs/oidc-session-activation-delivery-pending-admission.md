# Independent consume pending admission

[`authority_oidc_session_activation_delivery_pending_admission.py`](../serverware/authority_oidc_session_activation_delivery_pending_admission.py)
checks a genuine reservation response against independently held current pending
pins. A signed ACK is not its own latest-head authority. This is a source-only
library prerequisite: unbuilt, unexecuted and unprovisioned. The cold pending
consumer is not connected in this batch, so token-release row 12 remains open
and in progress despite the connected reservation primitives.

The [independent SQL bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md)
now defines the root-held predecessor/current-pending pins, distinct receiving
purpose, fixed resource inventory and separate issuer/executor database scope.
It is not yet connected to an actual cold pending consumer or consume SQL
producer. The [reserver service](oidc-session-activation-delivery-execution-reserver-service.md)
only returns retained reservation originals; it does not select the SQL
receiver's expected pending head.

## Original-only API

`_admit_on_work` requires these keyword-only inputs:

```text
originals, expectations, before_vector_bytes, authorization_bytes, grant_bytes,
response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
current_root_enrollment_bytes, root_public_key, planner_public_key,
operation_public_key, configuration_digest, expected_predecessor_sequence,
expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
expected_pending_sequence, expected_pending_head_digest, expected_fence,
receiving_custody, live_window, transport_deadline_ns, work
```

`originals` is the immutable raw2 signed consume plan and encrypted execution
bundle; `expectations` remains closed public data `{request, scope, journalDigest}`.
`response_originals` is immutable raw3: original signed reserve, distinct consume
computation snapshot and actual signed state ACK. No plaintext token, successful
material/result, posted executable effects or callback verifier is accepted.

The actual `OidcSessionActivationDeliveryExecutionCustody.for_sql_issuer` owner
requires the separate root-signed receiving v3 / historical v5 purpose at fixed
UID/GID 65498. It cannot be a grant owner at 65500, reserve owner at 65499 or
planning owner at 65501. See [receiving custody](oidc-session-activation-delivery-execution-custody.md)
and [history purposes](oidc-session-activation-delivery-history-custody.md).
These are independently delivered keys matching the genuine sender's pins,
not permission to borrow another process's owner or ambient key access.

## What is actually checked

The fixed reservation verifier captures the caller graphs and all immutable
originals before cryptographic callbacks. Raw3, grant and the four receiving
originals share the existing 64 MiB aggregate and cumulative work; actual
per-frame caps still apply. It genuinely admits caller/root/grant controls,
authenticates the signed consume grant before private opening, replays the
original consume plan once, reconstructs exact vectors and snapshot, and verifies
the original reserve and ACK signatures and unchanged original lifetime.

The pending layer independently requires predecessor sequence plus one to equal
the expected pending sequence. The actual signed ACK digest must equal the
independently supplied pending head. Database, generation, enrollment, reserve
identity, predecessor head, fence, pending sequence and original issue/expiry
must all agree; the genuine state enrollment must leave capacity for completion.
None of these expected current values is copied from the returned ACK.

The same original processing window and positive inherited deadline remain
live through final return, narrowed by actual receiving/caller/grant/plan/reserve
limits. Expired consume plans are not admitted as history, and neither a stored
ACK nor a newly opened processing window renews execution authority.

Only unchanged raw3 is returned. There is no proof-carrying SQL suffix before a
real dedicated consumer exists. Generic consume dispatch remains rejected;
one-use SQL, commit evidence, durable completion/recovery, exact token release
and public permission remain separate, unfinished connections.
