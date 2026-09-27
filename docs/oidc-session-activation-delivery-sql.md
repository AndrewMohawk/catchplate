# Protected consume SQL bridge

This source-only bridge connects independently admitted consume originals to
the actual protected issuer and IDs-only executor. It is not a token-release
endpoint. Source is unbuilt, unexecuted and unprovisioned; an unsigned observed
commit does not satisfy completion, currentness or any production gate.

`authority_oidc_session_activation_delivery_sql._execute_on_configuration`
takes the original caller authorization, consume plan/encrypted bundle, closed
expectations, before-vector, consume grant, reserve/snapshot/ACK and all three
original enrollments. It also requires independently held configuration,
database/generation, predecessor and current-pending sequence/head/fence,
the actual SQL-purpose receiving custodian, issuer/executor and the original
work/window/deadline. No successful admission result is accepted as an input.

The dedicated issuer entry performs genuine consume pending admission and
private replay once, encodes the resulting protected custody packet, and
publishes it through the actual issuer-role SQL path. The generic original
grant/replay dispatcher does not become an alternate consume entry. The bridge
does not replay the private originals a second time just to execute their
same-call custody IDs.

Only a genuine issuer return supplies the pending and packet digests handed to
`SuccessorExecutionExecutor.execute`. The actual executor durably claims its
catalog-bound attempt before opening SQL. Its protected transaction checks the
admitted roots, selected rows, effects and one-use conditions; the bridge checks
the exact returned marker against the marker derived by original admission.
Issuer and executor configurations, creator processes and the actual attempt
owner remain guarded. Equal query/catalog pins do not independently prove that
two TLS connections reach the same database.

One original processing allowance remains active through admission, publication,
execution and return. The issuer continuation preserves the original caller,
grant, plan, reserve and receiving-owner lifetime; the bridge additionally clips
its transport bound to the actual custody expiry. Its returned private
`_ExecutedSql(observation, live_window, deadline_ns, live)` is a same-call
continuation for the fixed service's send/cleanup checks, not an authority input.

Before a confirmed issuer return, a failure reports no guessed locator. After
that return, `DeliverySqlOutcomeError` retains the actual pending/packet
digests, including failures after a possible database commit. Once established,
it also carries the genuine same-call live guard, window and deadline; the cold
worker may send an uncertainty response only while that continuation remains
live. A missing or expired guard means no response packet, not a fresh response
allowance or an expiry extracted from unauthenticated input. Neither case
clears the durable attempt, regenerates a packet or retries SQL. Separate
authenticated completion/recovery must resolve uncertain outcomes; commit
observation alone does not authorize plaintext release or a browser session.
