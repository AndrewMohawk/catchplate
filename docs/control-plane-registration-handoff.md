# Retained registration SQL and completion handoff

The private control-plane continuation now connects retained registration
originals to the actual cold SQL and completion transports. This is **source
implementation only: unbuilt and unexecuted**. Existing
public reserve routes still reserve only; they additionally retain the exact
authenticated reserve request, snapshot and acknowledgment under the prepared
grant. No credential is finalized and no session is activated here.

## Separate explicit actions

[`control_plane_registration_handoff`](../serverware/control_plane_registration_handoff.py)
provides two private application entrypoints:

| Action | Result and boundary |
| --- | --- |
| `execute_retained_registration(local_digest, *, expected_user_id, expected_session_id)` | `(local_digest, SQL raw4)` after ownership replay, one durable local dispatch claim, live original replay, one fixed transport exchange and marker equality. The SQL response remains unsigned. |
| `request_retained_registration_completion(local_digest, *, expected_user_id, expected_session_id)` | `(local_digest, completion raw4)` after ownership replay, live original authorization and genuine returned-original verification. It does not finalize a credential. |

The [explicit public handlers](public-registration-handoff.md) authenticate the **present caller**, ownership of
the registration, current session/roles, CSRF and separate permission for the
requested action before calling either entrypoint. Possessing a local ID,
preparation permission, reserve approval or an old successful result is not
that authorization. The private methods repeat genuine ownership replay against
the authenticated user/session scalars before side effects; they accept no
successful subject object as permission. Portal controls remain separate work.

Only the actual cold enrollment and custody owners are accepted. The explicit
[nested-v3 bootstrap](control-plane-registration-execution-handoff-bootstrap.md)
supplies fixed endpoints, original enrollments, an independently expected pending
sequence/head/fence and a separately pinned completion packet ID. V1 remains
grant-only and v2 remains reserve-only. There is no environment or key fallback,
new signer authority, response-derived checkpoint or automatic profile upgrade.

The cold pins describe one intended operation, not a self-advancing workflow.
The independent provisioning authority must supply the corresponding packet
and pending scope. Their root signature authenticates claims; it does not prove
that those claims remain current at action time. This batch provisions nothing.

## SQL ordering and uncertainty

```text
present actor, ownership and execution-purpose permission
    -> actual retained signer/grant association + reservation originals
    -> live caller/control admission + genuine complete pending/grant replay
    -> durable local SQL-dispatch claim
    -> one raw13 request to the independently configured SQL service
    -> retain the exact unsigned raw4 observation, including uncertainty
    -> check observed marker against this call's genuine replay marker
```

The [real SQL service](registration-execution-sql-service.md) independently
admits its own cold scope and records its protected executor attempt before
database work. The caller's local claim supplements, not replaces, that
boundary. It is published and fsynced before send, rejects every repeat and is
never cleared after failure. A lost response, uncertain issuance or expired
window cannot authorize another SQL send.

The returned SQL marker must equal the canonical full marker from the same-call
genuine preflight; the pending locator must match that marker. The packet ID is
an **unsigned selector**, not packet authority or a completion receipt. The
completion caller never promotes it into its expected packet pin.

One work allowance and the original action deadline cover loading, replay,
claiming, transport and response admission. Nested guards can only narrow those
bounds, including any shorter original grant/reserve expiry. Late storage can
retain opaque originals but cannot renew execution authority. A retained SQL
response may fail subsequent admission; storage does not label it verified.

`RegistrationHandoffOutcomeError` carries a canonical submitted local selector
and a fixed message, never raw originals or a claim of remote nonexecution.
The selector alone does not prove retention succeeded. Cancellation propagates.
Neither this error nor an absent outcome provides automatic retry permission.

## Live completion, not historical caller recovery

Completion requires the actual preparation/reservation and local dispatch claim,
but does not require a SQL response: SQL can commit before its response is lost.
The small request uses only the independent cold packet pin. The service's own
protected readback/replay and retained-original recovery remain authoritative
for what it signs; an unsigned local outcome cannot replace those checks.

Before contacting the service, the caller authenticates its original live
planning exchange, caller authorization and grant controls. After the response,
the [handoff verifier](registration-execution-handoff-admission.md) genuinely
replays original plan/reserve/grant scope and verifies completion/state originals
against the independent pending scope. It joins the full marker/vector and
canonical observation; it does not claim that the completion wire authenticates
a packet locator or establishes a fresh current head.

Only successfully authenticated completion raw4 is appended by this caller.
An uncertain completion response creates no verified completion record. Existing
completion originals are reread and genuinely reverified without another socket
request; no stored success bit is trusted. The lower-level opaque journal can
retain other carriers, so it independently grants no assurance.

The caller path deliberately still requires **unexpired original caller and
grant controls**. The separate service can recover historical originals, but
the existing caller exchange has no historical authorization-admission seam.
End-to-end historical recovery therefore remains required implementation; this
live path must not be relabeled as recovery or weaken expiry checks to simulate
it. There is no automatic request retry, SQL retry or re-signing workflow.

## Retention and remaining work

The [outcome journal](control-plane-registration-outcomes.md) retains fixed
bounded records under the actual preparation association and preserves the
original source token. It does not advance any independent checkpoint. Quota,
fsync failure, interruption and hostile-host rollback remain explicit limits.
Conflicting first responses cannot overwrite records; future recovery needs a
separate bounded reconciliation design if an opaque uncertain completion record
was retained by another caller.

Public purpose/ownership admission and bounded status are now wired in source.
Still required: historical caller recovery, reconciliation, complete portal workflows, genuine
associated-original replay for credential finalization, action-time currentness
and atomic one-use authority, deployment/provisioning and all production gates.

After prerequisites and source freeze, consolidated verification must cover
disabled/older profiles, altered pins and retained originals, cross-registration
selectors, exact owner continuity, repeated dispatch across restart, failure
before/after claim/send/storage, uncertain SQL with genuine completion, invalid
marker/signature/scope, shorter grant/reserve expiry, completion replay without
transport, clock reversal and unchanged public reserve-only behavior. No tests,
imports, builds or runtime verification ran for this source batch.
