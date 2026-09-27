# Dedicated activation completion and recovery

This `.155` checkpoint is **source-only, unbuilt and unexecuted**. It connects
historical custody, original pending admission, actual protected readers,
completion signing and durable original delivery in private library source.
It is not an installed cold service, public action or completed session flow.
F08.4e.6 remains in progress; no counted step or production gate closes.

## Independent authority and actual originals

The [historical custody bootstrap](oidc-session-activation-history-custody-bootstrap.md)
authenticates a distinct fresh `completion-history` receiving purpose. The
[process-bound owner](oidc-session-activation-history-custody.md) holds the
independently pinned bundle/delivery AES keys and genuine original planner
policy, vector and state enrollment. The three live receiving roles are
unchanged; a live owner cannot be relabelled as historical custody.

The caller independently supplies exact packet identity, configuration,
caller authorization identity, root/planner/operation keys, enrollment originals
and database/generation/pending sequence/head/fence. Neither retained bytes nor
an ACK chooses these expected values. The real configured custody/commit
readers and durable delivery owner are required; an opener, candidate,
successful observation or signing callback is not accepted instead.

## First completion

[`authority_oidc_session_activation_completion_recovery`](../serverware/authority_oidc_session_activation_completion_recovery.py)
holds the actual completion delivery owner's recovery lock across lookup,
protected packet retrieval, production, retention and exchange. Before I/O it
reauthenticates historical custody and narrows the supplied processing window
to that role's fresh launch ceiling without changing its opening samples.
Enrolled completion policy can only narrow the same window further.

When there is no retained completion,
[`authority_oidc_session_activation_completion`](../serverware/authority_oidc_session_activation_completion.py)
authenticates the original packet identity and matches its enrollments to the
independent originals. It checks the actual completion private/public-key pair
against the root-authenticated state enrollment. The genuine
[historical pending adapter](oidc-session-activation-completion-admission.md)
then verifies the original caller, grant, encrypted plan, reserve, snapshot and
ACK, rederiving the full vectors, immutable marker and effects identity.
Stored packet claims must match those actual same-call facts.

The fixed commit reader uses a real read-only connection and returns only after
normal cursor/connection closure. Its observed marker and complete vector must
equal the genuine historical result before any completion is signed. The
completion control binds the exact observation bytes, operation, pending scope,
fence, snapshot, result and before/after vector commitments. Its interval is the
current processing bracket, never an extension of the expired execution grant.

| Stage | Durable or authority boundary |
| --- | --- |
| Original replay | Proves original semantics; grants no new execution permission. |
| Protected commit read | Observes the exact committed marker and roots; no SQL mutation. |
| Completion signing | Uses the actually enrolled completion key and real-current guards. |
| Enqueue | Retains the first exact completion before any transmission. |
| State delivery | Retains the exact authenticated acknowledgment before successful return. |

The bounded call retains the same work allowance throughout. Fresh outer
custody and actual-current guards surround key operations, reader phases,
signing, journal work and transport. Reader/transport bounds and signed-control
expiry cannot outlive the independently admitted fresh historical role. These
checks are not a hard watchdog for arbitrary native calls.

## Retained-original recovery

A retained completion is authenticated and joined to the independently pinned
packet and pending scope. This branch trusts the genuine original enrolled
completion assertion, not a new caller-supplied replay result. It does not sign
again, reopen the original grant, re-run the SQL executor or clear an attempt.

A fresh nonce-bound state lookup has three outcomes:

- **Acknowledged:** recover and durably retain only the exact original state
  acknowledgment, then return it unchanged.
- **Pending, not recorded:** only the unchanged retained completion may be
  delivered, at most once in this call. A late or lost result preserves it.
- **Changed or contradictory state:** fail unresolved; do not replace the
  completion or infer that the database transaction did not commit.

An expired never-accepted original cannot be replaced. The state owner still
enforces its acceptance policy. Returned receipts are historical completion
evidence, not a current session lease, token release or fresh user permission.

## Still required before this step closes

The source composition needs dedicated cold completion signing-key/FD delivery,
independently admitted custody/commit-reader DB/TLS configurations, journal
checkpoint and actual service launch/transport. The state service must separately
admit the activation completion/lookup peer and genuine operation under an
explicit signed profile. Response framing and receiving verification must join
the exact originals without presenting an unsigned outcome as completion.

The generic activation completion APIs intentionally still reject. Current
source/configuration/key-cohort checks remain strict; H05 cross-version
historical authority is not implemented by this change. Trusted-host key
ownership and matching query/catalog pins do not establish hostile-host
custody, database identity, rollback resistance or off-host currentness.
Protected token release, public permission/recovery and portal confirmation are
separate open steps. Source totals remain **18/26 landed, 1 in progress, 7 other
open**, with **34/46 parent checkpoints** and **0/6 production gates**.

No build, test, import, parser, formatter, provisioning or runtime command was run.
