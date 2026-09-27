# Retained registration handoff HTTP contract

This source-only contract separates execution of registration evidence from
completion recovery. Neither action finalizes a credential or establishes a
latest current head. The [pure helper](../serverware/control_plane_registration_handoff_http.py)
owns bounded shapes and public projections, not HTTP handlers, actor/session
authentication, database access or cryptographic verification. The current
source is unbuilt and unexecuted.

## Fixed routes and request bodies

The handler integration selects one of four POST routes:

| Route | Required purpose | Fresh action binding |
| --- | --- | --- |
| `/api/webauthn/register/execute-retained` | `execute-registration-evidence` | `webauthn.registration.execution.execute` |
| `/api/auth/session/webauthn/register/execute-retained` | `execute-registration-evidence` | `webauthn.registration.execution.execute` |
| `/api/webauthn/register/complete-retained` | `complete-registration-evidence` | `webauthn.registration.execution.complete` |
| `/api/auth/session/webauthn/register/complete-retained` | `complete-registration-evidence` | `webauthn.registration.execution.complete` |

`parse_request(raw_bytes, *, completion)` accepts exactly required `purpose`
and `localDigest`, plus optional `bootstrapToken` and `mfa`. The handler selects
the boolean mode; the body cannot select another action. `localDigest` must be
canonical lowercase `sha256:` text identifying the retained preparation, not
a SQL packet ID or an action token.

- `bootstrapToken`: string at most 1024 characters, or null.
- `mfa`: null or a closed object allowing only `assertion` and `approvalId`.
  `assertion` is null or an ordinary JSON object; `approvalId` is null or a
  string of 1–4096 characters. Empty MFA objects are only shapes, not authority.

These optional shapes match the existing reservation request contract. No
actor, keys, expected roots, packet selector, caller identity, result status or
caller-chosen action fields are accepted. Authority-evidence wrapper fields do
not substitute for an actual fresh mutation assertion. The handler owns the
current actor/session, CSRF, credential-history, bootstrap, assertion and
two-person admission gates.

The original body is at most 64 KiB. The existing strict JSON parser rejects
duplicates, invalid UTF-8, BOMs, floats and non-finite numbers, with limits of
depth 16, 64 keys per object, 512 total keys, 128 items per array, 4096 total
nodes, 64 KiB per string and signed-63-bit-magnitude integers. The result is a
new owned dictionary, including owned nested assertion data. HTTP middleware
must separately enforce the fixed route, no query, `application/json`, exact
Content-Length and no alternate transfer/content encoding.

## Genuine subject and new action binding

`request_binding(subject, *, completion)` consumes only the same-call result of
the genuine `inspect_retained_registration_subject` path. Its exact seven
fields are `localDigest`, `userId`, `challengeId`, `sessionId`, `mode`,
`requestDigest` and `operationId`. The local, request and operation digests are
canonical lowercase SHA256; user/challenge/session identifiers are nonempty
UTF-8 text at most 4096 bytes.
The session identifier is nonnull only for `oidc-session-first-enrollment`;
the other fixed modes are `bootstrap-token`, `development-bootstrap` and
`existing-webauthn`, with null session identifiers.

The projection returns a fresh dictionary adding schema
`serverware.webAuthnRegistrationHandoffIntent/v1` and the source-selected purpose
and action to those seven fields. This is the ordinary request input for the
existing canonical MFA/approval payload hash, not a successful replay token.
Shape validation does not authenticate a supplied subject dictionary. The
handler must obtain it from full original signer/grant/planning/authorization
inspection, bind the actual current caller and repeat required current-state
checks. A retained `development-bootstrap` mode is historical context, never a
development bypass for the new action. No raw originals or authorization secrets
are exposed in this projection.

## Public success and uncertainty

`accepted(local_digest, raw4, *, completion=False)` checks only the fixed
transport carrier and canonical local ID. It must be called **only after the
actual private facade succeeds**, not on caller-supplied or merely retained
response bytes.

The SQL projection has schema
`serverware.webAuthnRegistrationExecutionHandoff/v1`, status `observed-commit`
and `observationAuthenticated:false`. It deliberately labels an unsigned SQL
observation, not signed completion. The completion projection has schema
`serverware.webAuthnRegistrationCompletion/v1`, status `completion-acknowledged`
and `observationAuthenticated:true`. That true field depends on the actual
facade's genuine original-response verification; this pure helper performs no
authentication and cannot establish it from an `acknowledged` byte label.

Both projections contain the fixed purpose, local preparation ID,
`registrationCompleted:false`, `currentnessEstablished:false` and
`automaticRetryAllowed:false`. They expose no raw originals, SQL packet ID,
MFA assertion or bootstrap token. They never claim `executionStarted:false`:
SQL may actually have run.

`unavailable(local_digest=None, *, completion=False)` provides fixed errors
`registration_execution_unavailable` or `registration_completion_unavailable`,
the same false completion/currentness/retry flags and `remoteState:unknown`.
An optional local ID is included only when the caller actually supplies a
canonical ID. Invalid IDs fail closed. Handlers use HTTP 503 for uncertain
outcomes and return no internal exception text, keys, paths or response bodies.
This does not assert nonexecution, noncommit or absence of a retained claim.

Handlers retain the existing HTTP 412/428 negotiation bindings for action,
resource and payload digest, while removing any generic `retry` hint and setting
`automaticRetryAllowed:false`. A consumed assertion may need fresh independent
presentation after approval negotiation. No success, negotiation response or
uncertain failure authorizes automatic resubmission. Responses are noncacheable.

## Remaining evidence boundary

The local [outcome store](control-plane-registration-outcomes.md) burns a durable
SQL-dispatch claim before the real caller sends and never releases it. Its
records are original bytes, not verification or latest-state tokens. Genuine
returned-original admission, independently current checkpoints, purpose-bound
handler authorization and separate credential finalization cannot be inferred
from these HTTP projections. First-response completion retention does not
silently upgrade an earlier uncertain response; future reconciliation remains
separate work.

Planned frozen coverage includes closed fields/mode, duplicate/size/depth and
MFA-shape rejection; actor/subject/action binding; genuine facade-only projection;
unsigned SQL labeling; uncertainty redaction and no automatic retry. No tests,
imports or runtime verification have been run for this source batch.
