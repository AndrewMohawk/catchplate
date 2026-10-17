# Historical finalization originals

This is source-only implementation, unbuilt and unexecuted. Historical admission
does not renew permission to finalize a credential or activate an OIDC session.

The private [historical exchange](../catchplate/authority_registration_finalization_history_exchange.py)
accepts independent configuration/generation/runtime identity, the three original
current-root/grant/finalization-caller enrollments, a pinned root key, and this
exact finalization raw10 inventory:

| Position | Original |
| --- | --- |
| 0 | Dedicated finalization caller authorization |
| 1–2 | Verifier custody intent and planner relay |
| 3–6 | Transition plan envelope, proof, inputs, evaluation context (raw4) |
| 7 | Separately committed historical expectations |
| 8 | Complete before-vector |
| 9 | Execution grant |

This is **not** the evidence-admission raw10 layout. Actual finalization
transition configuration supplies planner/verifier/operation keys and policy;
there is no evidence-purpose key fallback. The original dedicated caller
signature and root enrollment precede custody replay. The genuine verifier
intent signature authenticates every raw5 body commitment before historical
expectations are interpreted. The planner relay binds that exact intent.

Full transition proof and complete-vector replay derive the typed request,
effects, retained-plan identity and every execution-grant claim. Those claims
are compared with the authentic grant, authorization identity, database,
generation and enrollment scope. Original signed intervals remain bounded and
joined: the plan follows its caller authorization, controls fit the plan, and
the grant cannot extend those intervals. Future-issued originals are rejected
against real processing clock samples and the applicable skew bounds.

`_verify_on_configuration` returns private same-call observations: request and
operation digests, authorization digest, database/generation, owned expectations,
actual configured keys, original raw4, the replayed typed request and original
inputs. No entrypoint accepts this object as a successful-admission token.
Retained ownership must independently reconstruct the complete finalization
request from genuine signer originals and compare it, not trust local record
associations or user IDs alone.

The [completion history wrapper](../catchplate/authority_registration_finalization_completion_history.py)
additionally captures original reserve raw3, completion raw4 and independently
expected pending sequence/head/fence. It calls the actual
[finalization receiving verifier](../catchplate/authority_registration_finalization_completion_response.py),
which replays the original pending/plan/grant scope and authenticates completion
and state signatures. Its result contains original completion/state bytes and
their identities. An `uncertain` response is not authenticated completion.
The wire carries no packet identity; an independently admitted packet locator
must not be inferred from that result or an unsigned SQL outcome.

Both paths retain the caller's existing work, live processing window and
inherited absolute deadline. Aggregate original inventory is bounded to 64 MiB
before callbacks; individual and grouped source bounds still apply. Old expiry
is admitted only as history: no old issue time becomes the current clock, no
live verifier receives a fabricated clock, and no old execution window opens
again. The existing live authorization path is unchanged.

This slice covers only the same independently configured historical cohort.
Cross-generation/key authority resolution, present-caller ownership and fresh
recovery permission remain separate admissions. These modules perform no SQL,
signing, transport, storage, automatic retry or session activation and provide
no live external-head/currentness or production acceptance claim. See the
[cold completion contract](registration-finalization-completion-service.md)
for independently pinned history and pending-scope requirements.
