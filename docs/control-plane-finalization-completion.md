# Private retained finalization completion and recovery

This source-only integration connects retained finalization originals to the
[dedicated completion service](registration-finalization-completion-service.md).
It is unbuilt, unexecuted and unprovisioned. It never invokes or retries SQL,
clears an attempt, renews old execution authority or activates an OIDC session.
Public completion/recovery permissions and portal controls are not wired here.

## Explicit cold scope and original ownership

The [nested v4 caller profile](control-plane-registration-finalization-custody.md#opt-in-completion-caller-configuration)
independently pins the completion endpoint, requested custody-packet digest and
original authorization digest. Existing independently admitted configuration,
generation, transition keys, enrollment originals and pending sequence/head/fence
remain mandatory. Older profiles stay disabled; there is no new key or FD.

`completionPacketDigest` selects the request; unsigned SQL packet locators
cannot supply it. The returned raw4 contains no packet ID, so receiving
verification makes no independent packet-identity claim. The actual historical
authorization identity must match `completionAuthorizationDigest`.

The [subject inspector](../serverware/control_plane_registration_finalization_completion_subject.py)
exposes `inspect_retained_finalization_completion_subject(local_digest)`.
Its result is ordinary owned data with exactly `localDigest`, `userId`,
`challengeId`, `sessionId`, `mode`, `requestDigest` and `operationId`—not a proof
token or present-caller permission. The locator alone establishes no ownership.

Actual [historical replay](registration-finalization-history.md) authenticates the complete finalization plan/grant and
its associated signer/evidence-completion originals. The finalization request
is regenerated from the genuine signer exchange and proven sibling challenge
IDs, then joined to the original authorization and plan. Historical signatures
can remain verifiable after their action interval expires; they cannot revive
that interval. Only the independently configured source/configuration/key cohort
is supported. Cross-generation historical authority remains separate H05 work.

## Private initial request and explicit recovery

The [completion facade](../serverware/control_plane_registration_finalization_completion.py) provides two distinct calls:

- `request_retained_registration_finalization_completion(local_digest, *, expected_user_id, expected_session_id)`
- `recover_retained_registration_finalization_completion(local_digest, *, expected_user_id, expected_session_id)`

Both return `(same_local_digest, authenticated_raw4)`. Ordinary failure is
`RetainedFinalizationCompletionOutcomeError`, carrying only `local_digest` and
a static message—not a remote result, currentness or retry assertion.

The expected user/session scalars must come from genuine present authentication,
not posted identities or an earlier successful-inspection dictionary. The facade
repeats retained ownership under the actual cold owner lock. One current work
budget and original live window cover that call; nested admission and transport
may narrow its deadline but cannot reopen or extend it.

Before a completion exchange, actual original pending/grant admission joins the
complete plan, reserve/snapshot/state acknowledgment and independent pending
pins. One bounded exchange uses the fixed endpoint and independently pinned
packet selector. The [original-only receiver](registration-finalization-completion-response.md)
authenticates the completion and state signatures, complete marker/full-vector
joins and canonical embedded observation. No incoming success object bypasses
those steps, and the completion path never calls a protected SQL executor.

## Immutable outcomes and reconciliation

The [journal](../serverware/control_plane_custody_journal.py)/[client](../serverware/control_plane_custody_client.py) expose `append_registration_finalization_completion_outcome`
and `append_registration_finalization_completion_reconciliation`, each taking
`(finalization_digest, originals)` and returning only a local content digest.
`load_registration_finalization_outcomes` returns opaque associated originals.
Both appends require the complete finalization/evidence/signer chain, retained
reservation and irreversible SQL claim; a SQL outcome may be absent. Storage
shape checks and a content digest do not authenticate a completion.

The first bounded returned raw4 is retained **before** semantic or final lifetime
acceptance. This preserves uncertainty or a late response instead of disguising
it as no request sent. A retained acknowledgment is genuinely reverified before
reuse; its stored status or a previous successful call cannot authorize reuse.

Only explicit recovery can fetch again after an uncertain completion response.
A subsequently authenticated acknowledgment is retained in a separate immutable
reconciliation slot. The first uncertainty is never overwritten, the SQL claim
is never released, and neither record authorizes another SQL dispatch. Exact
repeated originals may be idempotently retained; different originals cannot
silently replace an existing record. Missing bytes, local publication failure
or an absent response establish neither remote nonexecution nor retry permission.

The source codec distinguishes `completion-outcome` and `completion-reconciled`
without changing existing SQL claim/outcome bytes. The latter is an association
with authenticated recovery originals, not a mutable “latest result” receipt.
Local retention is not an off-host witness or rollback-resistant currentness.

## Remaining public and release boundaries

This batch adds no HTTP endpoint or portal action. Separate current ownership,
purpose-specific complete/recover permission and post-SQL pending-session handling
remain necessary. That session branch must account for the credential already
inserted by SQL rather than reuse the pre-execution empty-history branch.
Separate authenticated OIDC activation remains F08.

The next public implementation will keep the pre-SQL empty-history rule intact.
Its new completion-only subject contract must additionally bind the credential
ID regenerated from these originals. A fresh pending cookie, CSRF and current
roles precede permission: genuinely empty history with the target absent may
use fresh bootstrap; exactly the one matching live target requires fresh
target-key, action-bound WebAuthn plus configured two-person approval, not
bootstrap. Extra, foreign or revoked history is denied. Pending-purpose options
must derive the action and payload binding server-side because the existing
operator options endpoint requires an active session. Recheck session, roles
and credential identity after permission, allowing only the expected counter
update. This is the next design decision, **not an implemented public bypass**;
the current private inspector still returns seven fields.

Authenticated historical completion is not a live latest-head lease, packet
provenance proof, browser-session activation or production acceptance. Independent
authority/provisioning and frozen end-to-end verification remain required;
no execution result or passing test is claimed by this guide.
