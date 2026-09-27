# Public retained-registration execution and completion

These explicit API actions connect the [retained-original handoff](control-plane-registration-handoff.md)
to present caller authorization. They are **source-only, unbuilt and unexecuted**;
they require independently provisioned nested-v3 cold owners. Registering routes
in source does not deploy them or establish production acceptance.

## Four separate POST actions

| Route | Present caller | Purpose |
| --- | --- | --- |
| `/api/webauthn/register/execute-retained` | Current authenticated admin/approver | `execute-registration-evidence` |
| `/api/auth/session/webauthn/register/execute-retained` | Current pending OIDC session, first credential only | `execute-registration-evidence` |
| `/api/webauthn/register/complete-retained` | Current authenticated admin/approver | `complete-registration-evidence` |
| `/api/auth/session/webauthn/register/complete-retained` | Current pending OIDC session, first credential only | `complete-registration-evidence` |

The closed request contains `purpose`, canonical `localDigest`, and optional
`bootstrapToken` and `mfa`. The [HTTP contract](registration-handoff-http-contract.md)
defines exact nested bounds and public response fields. No browser-selected
user, session, roots, expected hashes, packet ID, endpoint or raw authority
original is accepted. Request framing requires one exact Content-Length and
`application/json`, no transfer/content encoding or query string, an exact body
length and at most 64 KiB. Duplicate JSON members and oversized/deep structures
are rejected before the handler.

## Ownership is replayed, not inferred from an ID

The actual cold owner must enable SQL/completion before permission is spent.
The [subject inspector](registration-handoff-subject.md) loads the real retained
signer/grant association, genuinely replays the signer originals and verifies
the original grant/planning exchange. The grant's signed request commitment
must match that same signer's reconstructed request; a local association between
unrelated valid exchanges cannot supply ownership.

The derived user must equal the current authenticated actor. Operator actions
require a non-session registration; pending actions require the exact current
pending-session ID. The handoff repeats this genuine inspection on its existing
work/deadline immediately before SQL claim or completion send/reuse, comparing
explicit current-caller scalars. No successful subject dictionary is passed
into execution as a permission token.

```text
strict request + current caller/session
    -> actual cold owner + replayed registration ownership
    -> separate action-bound bootstrap or WebAuthn/two-person permission
    -> current caller/session and credential-history branch rechecked
    -> same-owner original replay and ownership rechecked
    -> one-use SQL dispatch OR authenticated completion-original handoff
```

## Present-purpose permission

The two new actions are `webauthn.registration.execution.execute` and
`webauthn.registration.execution.complete`. Preparation/reserve approvals and
old enrollment authorization do not replace either permission.

With existing credential history, operator actions reject bootstrap tokens and
require a fresh, directly verified mutation assertion plus configured two-person
approval. The binding includes source-selected action/purpose, actual local ID,
replayed user/challenge/session/mode and signed request/operation identities.
Missing assertion returns **412** with the exact action, resource and payload
digest. An assertion may already be consumed before **428** approval negotiation;
continuing requires a fresh assertion, not automatic replay. Production startup
requires both new actions in its two-person configuration when the actual
nested-v3 owner is enabled.

Empty history requires a fresh presentation of the configured bootstrap token
even in development; its configured length must be at least 32 characters.
MFA cannot substitute in that branch. Pending-session actions reject **any**
credential history, including revoked credentials, and require cookie CSRF even
if unrelated authorization headers are present. They reload the uncached session,
roles, expiry and history before dispatch. Operator actions repeat real request
authentication/current roles and use uncached OIDC-session admission when relevant.

These checks do not create an independent action-time witness or atomic global
role-revocation boundary; those production requirements remain unchanged.

## Outcomes never imply credential finalization

Success is **202** with a bounded no-store projection, no raw originals or keys:

- Execute: `status: observed-commit`, `observationAuthenticated: false`. The
  unsigned service marker was compared with genuine same-call replay; it is
  not a signed completion or a credential-finalization result.
- Complete: `status: completion-acknowledged`, `observationAuthenticated: true`
  only after the actual facade authenticates original completion/state
  signatures and scope and durably retains them.

Both retain `registrationCompleted: false`, `currentnessEstablished: false`
and `automaticRetryAllowed: false`. SQL evidence admission is not credential
finalization, and completion does not activate a pending session.

Internal failures return fixed **503** uncertainty with `remoteState: unknown`;
no raw exception text or claimed nonexecution is exposed. A local selector is
included only after this handler has authenticated its retained ownership.
Existing bounded 4xx negotiation remains available with generic retry hints
removed. Responses are no-store. Cancellation propagates; lost responses never
release a dispatch claim or authorize SQL retry.

## Still incomplete

Both public actions still require live original signer/caller/grant controls.
[Historical completion admission](registration-completion-history.md) now
composes genuine historical planning request/response, full plan/history replay,
caller/grant and completion-original verification in source. It does not relax
these routes or renew execution permission. Separate
[public historical completion recovery](public-registration-recovery.md) is now
implemented in source, with genuine historical ownership replay, fresh
recovery-purpose permission and bounded reconciliation/transport/storage. These
original execute/complete actions remain live-only; recovery never retries SQL.

Separate credential finalization, complete portal UX, independent currentness,
provisioning, frozen verification and full production acceptance remain open.
No service/key/role configuration, database mutation or runtime activation was
performed while authoring this source.

Planned consolidated verification includes strict framing and duplicate keys;
cross-user/session and mismatched authentic signer/grant pairs; disabled/older
profiles; bootstrap and hardware-MFA branches; approval consumption; concurrent
role/session/history changes; same-owner continuity; failures around dispatch
claim/send/retention; uncertain SQL with later completion; immutable result
replay; and no accidental finalization or automatic retry. None ran in this batch.
