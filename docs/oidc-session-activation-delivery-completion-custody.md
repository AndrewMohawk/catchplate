# Consume completion historical key custody

This source-only layer admits a distinct private completion purpose for
`oidc.session.activation-delivery.consume`. It does not relabel the consume SQL
receiver, reopen an expired consume plan, execute SQL, sign a completion, or
release a token. Cold key/FD delivery, service construction, state-peer routing
and response admission remain separate integration work. Nothing here is built,
executed, installed or production-verified.

## Fixed purpose and originals

The new [bootstrap](../serverware/oidc_session_activation_delivery_completion_custody_bootstrap.py)
uses `serverware.signedOidcSessionActivationDeliveryCompletionCustody/v1` and the
matching `serverware.oidcSessionActivationDeliveryCompletionCustody/v1` payload.
Its fixed consumer role is `consume-completion-history`, process mode
`oidc-session-activation-delivery-completion`, and UID/GID **65497** with empty
supplementary groups. Admission rejects collisions with independently configured
generic runtime role IDs. A narrow source/ops lookup found no existing use before
this purpose was assigned; that is not host account provisioning.

Four immutable originals are required, not incoming admitted material:

| Original | Authority at completion time |
| --- | --- |
| Fresh completion custody envelope | Actual independent root signature and current bounded receiving purpose |
| Original consume planner bootstrap v2 | Historical signed configuration, planner, policy, request, vector, enrollment and resource data |
| Original consume-planning activation-history v2 | Historical planning purpose and exact predecessor activation bootstrap/request binding |
| Separate activation-history v6 | Fresh root-signed historical activation custody for the same completion process, request and receiver identity |

The outer envelope retains closed `{byteCount, bytesDigest}` descriptors for the
three detached originals and canonical consume request, avoiding duplicated
base64 payloads. It joins configuration/generation/runtime closure, independent
receiver identity, consume export key digest and historical bundle/delivery key
digests. All three AES purposes and both original journal-key pins must be
distinct. Both history originals must identify the exact same original
activation bootstrap; requests must match byte-for-byte.

The outer limit is 16 KiB, consume planner 4 MiB, each activation-history original
8 MiB, and the existing cumulative original limit remains 64 MiB. Original
signatures, canonical bytes and typed request commitments are genuinely checked.
No bootstrap or successful result object can replace those bytes.

## Separate historical and current lifetimes

`oidc_session_activation_delivery_planner_bootstrap._verify_historical_on_work`
and activation-history `_verify_historical_consume_on_work` authenticate original
v2 data under the supplied actual current processing window. They return distinct
`_HistoricalPlannerMaterial` and `_HistoricalPlanningMaterial` results, reject
future-issued originals, and preserve signed original intervals. Their real
processing samples are not proof that old launches remain live.

Only the fresh completion envelope and separate v6 history grant enter current
launch freshness checks. The completion interval must fit the fresh v6 interval;
it need not fit either expired planning interval. The genuine replayed consume
plan must fit both authenticated original planning intervals algebraically.
Current processing is never clipped to an expired plan deadline, sampled at an
old issue time, or renewed after a callback.

All original source/configuration/key cohort checks remain strict. This is not
H05 cross-cohort historical resolution. Existing live bootstrap verifiers retain
their current expiry behavior. The live consume planning/receiving gate accepts
only v2–v5; historical consume replay requires v6. A broader predecessor-activation
provenance gate admits v6 only for replaying that original activation, not for new
consume execution.

## Actual private owner

[`OidcSessionActivationDeliveryCompletionCustody`](../serverware/authority_oidc_session_activation_delivery_completion_custody.py)
requires the four originals, independent root and receiver identity, actual
consume execution-bundle/historical-bundle/delivery AES keys, and the original
`work`, `live_window` and `transport_deadline_ns`. It genuinely constructs the
separate v6 historical owner; no caller-supplied nested owner is accepted.

The exact class seals configuration identity, PID, fixed UID/GID/mode, a
nonblocking ownership lock, original root bytes and sticky clock observations.
Every protected use reauthenticates the root originals and actual key digests.
Keys never appear in its public results. Closing the owner also closes its owned
nested history custody.

Its source-fixed methods are:

- `require_completion_on_work`: exact-purpose check, not fresh I/O authority.
- `bind_context_on_work`: compare independently supplied root and original
  current-root enrollment; no receipt supplies those expectations.
- `processing_bounds_on_work`: reauthenticate and return only a narrower current
  window/deadline, preserving the original opening and cumulative work.
- `check_on_work`: return a same-call current epoch guard for protected I/O.
- `verify_exchange_on_work`: accept only original caller/grant/enrollment/raw2
  bytes and independent request/scope/vector/configuration/key expectations;
  invoke the [historical exchange](oidc-session-activation-delivery-history-exchange.md)
  exactly once and strengthen its returned current guard.

The exchange method independently joins the root-admitted before-vector, typed
consume request, planner identity/key, policy and subject. It supplies private
keys and actual v6 custody internally to
[historical consume replay](oidc-session-activation-delivery-execution-history.md).
Its ordinary `_HistoricalExchange` output remains a same-call diagnostic result,
never an accepted proof DTO, executable effect carrier or authority to repeat SQL.
Returned guards reacquire the owner lock and retain both fresh role bounds
through later protected reads/signing. No FD inventory or cold-launch contract
is defined by this library slice.
