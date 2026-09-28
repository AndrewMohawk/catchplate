# Same-call consume planning and retained export

[`control_plane_oidc_session_activation_consume_planning.py`](../serverware/control_plane_oidc_session_activation_consume_planning.py)
connects an actually acknowledged activation completion to the isolated
consume planner's prepare and exact retained-export paths. It is source-only,
unbuilt, unexecuted and unprovisioned. No consume authorization/grant, reserve,
SQL execution, token opening, public route or active-session cookie is added.
The whole activation step 22 and release handoff remain incomplete;
production acceptance remains 0/6 verified.

## A continuation, not a resumed permission

The actual live permission context provides:

```text
prepare_consume(*, planner_bootstrap_bytes, history_custody_bytes)
    -> (prepared_raw6, exported_raw7)
```

The parent `_prepare_oidc_session_activation_consume` facade supplies only
those two immutable originals to its current actual permission slot. There is
no supplied work, window, deadline, callback, completion result or restored
context. The same parent/PID/thread and held locks must still be active after
its genuine `dispatch_completion(...)` call acknowledged the exact originals.
Only that source-fixed call seals the completion raw4, original activation
before-vector and actual dispatcher guards. An uncertain completion, escaped
context or journal loader cannot manufacture this state. The consume latch is
spent before new root admission; any failure revokes the context.

Existing one-shot dispatch facades exit their contexts before returning, so
their returned tuples cannot later be supplied here. A separately authorized
private orchestration must use the still-active context; this module installs
no public route or asynchronous context-resumption mechanism.

## Stable cold policy, post-activation root originals

Explicit execution configuration `/v4` pins the fixed consume planner endpoint
and its distinct public key/SPKI and measurement. It does not pretend to know
the future consume request. The actual
[root-original helper](control-plane-oidc-session-activation-execution-bootstrap.md#explicit-consume-planner-endpoint-profile)
authenticates the separately supplied planner and consume-history originals
under the same cumulative allowance, joining actual parent configuration,
generation, runtime identity, activation planner/state originals and the
configured consume signer. No AES/history key or extra descriptor is delivered
to the UID/GID 65532 control plane. The private planner remains UID/GID 65501.

The following cannot generally be pinned in the parent's pre-activation cold
bootstrap: the random new-token commitment and deterministic delivery target,
exact post-permission activation request/scope/journal identity, nonce-bound
caller authorization digest, signed reservation ACK head/fence and resulting
complete vector. The new per-request originals must independently bind those
actual values. Root issuance and matching cold-service provisioning are
external prerequisites, not implemented automation or evidence of runtime
readiness. They must be arranged while this original finite allowance remains
valid; this API cannot wait indefinitely, reopen a window or revive old
execution permission.

## Genuine original joins before prepare

All new immutable originals, actual key/owner references and mutable parent
and target graphs are held before native/root callbacks. The caller joins the
root-admitted activation expectations and pending scope to the sealed raw8,
actual authorization identity, independently scoped reserve/ACK and full
post-activation vector. The history's original activation planner bootstrap
must be byte-identical to the parent's held original. The typed consume
arguments must match the actual
activation subject, challenge, assertion and old/new-token commitments. The
delivery ID uses the existing deterministic activation recipe, not a response
field. The actual request cookie must still supply the same original 64-byte
old token and match its authenticated commitment.

The original dispatcher guards remain active. Root planner/history intervals
and their real opening brackets additionally survive through context exit;
the actual narrowed clock/skew check stays last and retains the newer floors.
Only expiry/policy narrowing is permitted. The old token is sent solely to the
fixed private planner, whose genuine private transition rechecks possession
and current state. It is never added to the control-plane journal.

## Durable claim, prepare, verify, export

The separate token-free consume-planning claim binds the retained finalization
target, actual activation-authorization identity and source. It precedes the
first prepare socket. The stage appends use the same cumulative work, with
bounded I/O precharged before stable native callbacks. Recovered records are
read-only and cannot resume an exchange or authorize another attempt.

The [bounded planner transport](oidc-session-activation-delivery-planner-transport.md)
uses a distinct raw16 prepare profile: purpose, old token, exact activation
original tuple13, and the caller's already-held epoch ceiling. The service can
only shorten its existing window to that ceiling. The old raw15 profile stays
strict. One original deadline and actual owner guard cover every native chunk
and normal close; aggregate response caps tighten before allocation.

Prepare and export each contact a finite, one-exchange service. Independently
provisioned, root-admitted workers must serve both exchanges using the shared
retained state before the original deadline expires. This source does not
relaunch or provision either worker, and the second exchange does not renew
the caller's allowance.

| Durable response | Exact original inventory |
| --- | --- |
| Prepared raw6 | Status, canonical consume request, canonical scope, signed plan, plan digest, journal digest |
| Exported raw7 | Status, same request/scope/plan, encrypted execution bundle, same plan/journal digests |

Each raw response is retained before status or semantic interpretation. Before
export, the prepared request must equal the independently root-admitted typed
original; scope/policy/subject must match independent root expectations, with
only a shorter deadline allowed. The real public-plan signature helper checks
the configured signer, exact request/configuration/identity and live interval.
The genuine plan identity must match its returned digest. Thus the exact plan
is both durable and authenticated before it can select retained export.

The journal digest is an exact held locator, not a signature or replay proof.
The export request supplies only that retained identity, the verified original
plan and its unchanged scope deadline. The actual private service replays its
known originals before export. After raw7 retention, request, scope, plan and
both identities must be byte-identical to raw6. Public framing checks the
distinct ciphertext format; only the genuine private receiving purpose can
open it and establish semantic or AEAD admission. No successful result object
is accepted as downstream authority. Missing/uncertain responses, changed
originals or close failures are terminal; no retry, token regeneration or
automatic recovery is introduced.
