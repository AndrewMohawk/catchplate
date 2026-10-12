# Private retained finalization completion and recovery

This source-only integration connects retained finalization originals to the
[dedicated completion service](registration-finalization-completion-service.md).
It is unbuilt, unexecuted and unprovisioned. It never invokes or retries SQL,
clears an attempt, renews old execution authority or activates an OIDC session.
Separate [public completion/recovery permissions](public-registration-finalization-completion.md)
and explicit [portal controls](portal-registration-handoff.md) now call this
private path; they do not make historical ownership itself present permission.

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
Its result is ordinary owned data with exactly eight fields: `localDigest`,
`userId`, `challengeId`, `sessionId`, `mode`, `requestDigest`, `operationId` and
`credentialId`—not a proof token or present-caller permission. The credential ID
comes from the fully regenerated, authenticated finalization request, not the
locator or an unsigned SQL response. The locator alone establishes no ownership.

Actual [historical replay](registration-finalization-history.md) authenticates the complete finalization plan/grant and
its associated signer/evidence-completion originals. The finalization request
is regenerated from the genuine signer exchange and proven sibling challenge
IDs, then joined to the original authorization and plan. Historical signatures
can remain verifiable after their action interval expires; they cannot revive
that interval. Only the independently configured source/configuration/key cohort
is supported. Cross-generation historical authority remains separate H05 work.

## Combined historical preallocation

The subject inspector now obtains preparation, reservation, finalization
outcomes and associated registration outcomes through one direct metered
`load_registration_finalization_completion_history` call. It does not wrap that
charging reader in a stable native callback or independently load four large
record families before checking their combined size. The journal's
[selected-history reader](control-plane-registration-finalization-completion-history.md)
preflights the admitted metadata for all selected encoded bodies before body one,
then reads and decodes each body once under the original work and guard.

Before calling it, the subject subtracts these source-defined reservations from
the existing 64 MiB byte-accounting allowance:

- Eight 4 MiB cold-parent representation footprints, covering already-held
  original/configuration representations without traversing private key objects.
- Four times the actual lengths of the six independently configured enrollment
  originals, each checked against its existing format cap.
- Two 4 MiB regenerated typed-request representations and two 8 KiB runtime
  capture allowances for the genuine replay path.
- The exact nonnegative additive held-byte count supplied by the earlier caller.
  The recovery path carries its actual bounded request/body/payload/policy/pins,
  old-token and independently configured history representations into this count.

The remaining allowance is tightened to `3 * (remaining // 8)` for the reader.
Its own preflight requires three times the actual selected encoded sizes plus
16 KiB of bounded header/locator bookkeeping. This leaves five additional
selected-byte footprints for replay, capture and canonical representations.
An insufficient allowance refuses before historical body allocation; neither
reader nor replay receives a fresh work budget or clock window.

The final exact original-byte sum remains and includes the additive retained
bytes. All preparation/source/type checks and genuine historical signature,
full-vector, signer-regeneration, pending/grant and current-owner checks remain.
These are conservative source-defined byte representations, not a claimed bound
on the entire Python heap. Cumulative computation is still metered on the same
actual validation work. This source change is not execution evidence.

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

## Public integration and remaining release boundaries

The [public routes and contract](public-registration-finalization-completion.md)
now expose independent complete and recover purposes, with fresh present
permission before this facade repeats genuine ownership. The new binding adds
the authenticated credential ID without widening the older generic seven-field
handoff schema. Success projects only the facade's authenticated result: it
acknowledges finalization, not session activation or currentness.

The implemented [pending permission helper](finalization-pending-permission.md)
keeps the pre-SQL empty-history rule intact. A fresh pending cookie, explicit
CSRF and current roles precede permission: genuinely empty history with the
target absent requires fresh bootstrap; exactly the one matching live target
requires fresh target-key completion possession, not bootstrap. Extra, foreign
or revoked history is denied. Dedicated completion options derive the action and
payload binding server-side. One nonce belongs to the actual enrollment owner,
is clipped to its original context, and is spent before signature verification;
it cannot be reissued on that owner or recovered after owner loss. Session,
roles and the complete credential row are rechecked after permission. Stored
counters, bookkeeping, challenges and approvals do not change, preserving the
exact pending metadata vector.

If the complete or recover action requires two-person approval, both public
branches instead return HTTP 503 with fixed error
`registration_finalization_completion_two_person_unavailable` before options,
assertion consumption, bootstrap or dispatch. Ordinary approval writes would
invalidate the committed after-vector required by the independent completion
reader. A future integrated authorization protocol is required; the current
refusal is intentional and has no guard-bypass or local-transaction workaround.

Two explicit [portal controls](portal-registration-handoff.md) connect those
actions without automatic chaining or retry. There is no implemented 428
two-person approval negotiation or continuation for completion/recovery. F08 separate authenticated
OIDC activation is next; no completion route activates the pending session.

Authenticated historical completion is not a live latest-head lease, packet
provenance proof, browser-session activation or production acceptance. Independent
authority/provisioning and frozen end-to-end verification remain required;
no execution result or passing test is claimed by this guide.
