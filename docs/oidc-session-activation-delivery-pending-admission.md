# Independent consume pending admission

[`authority_oidc_session_activation_delivery_pending_admission.py`](../serverware/authority_oidc_session_activation_delivery_pending_admission.py)
checks a genuine reservation response against independently held current pending
pins. A signed ACK is not its own latest-head authority. This is source-only,
unbuilt, unexecuted and unprovisioned. Its dedicated original-input continuation
now feeds actual protected [packet issuance](oidc-session-activation-delivery-execution-packet.md)
without a second proof replay; library outputs alone never close a cold-service
or production acceptance criterion.

The [independent SQL bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md)
now defines the root-held predecessor/current-pending pins, distinct receiving
purpose, fixed resource inventory and separate issuer/executor database scope.
The dedicated consume SQL path must use those independent pins, not returned
reservation data. The [reserver service](oidc-session-activation-delivery-execution-reserver-service.md)
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

The existing `_admit_on_work` still returns only unchanged raw3. The separately
named private `_admit_full_on_work` accepts exactly the same original inputs and
retains that invocation's genuine selected rows, three effects, complete vectors,
eighteen-field marker and original reserve interval. Its current guard also
retains the actual SQL-issuer receiving purpose. No entrypoint accepts this
candidate or guard as proof. The dedicated packet producer consumes this suffix
internally once; the protected issuer accepts only original-input arguments.

Generic consume grant/replay/preparation dispatch remains rejected. SQL custody
and a normal transaction observation are not signed completion, exact committed
token release, fresh public permission or portal handoff. Historical consume
completion and recovery admission remain separate, unfinished work.
