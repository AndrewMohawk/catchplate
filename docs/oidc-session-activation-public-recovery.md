# Public activation recovery: actor and evidence boundary

Recovery is a separate user action, not another activation attempt. This source
slice adds bounded recovery options and a private, live authorization context.
It does **not** add a public recovery-dispatch endpoint, recover a token or close
activation step 23. Source remains unbuilt, unexecuted and unprovisioned.

## Why the activation permission cannot be reused

Protected activation may replace the pending token before the browser receives
its new cookie. The old cookie then no longer authenticates the current session.
Normal OIDC login also creates a different session and replaces that cookie;
neither behavior proves permission over the original activation target.

The recovery path instead combines three distinct checks:

1. Genuine replay of retained finalization originals and its acknowledgment
   selects the original user, session and sole credential.
2. A root-enrolled historical release-intent signature joins that target to
   possession of the old cookie and the still-live original delivery interval.
   This is narrowly scoped target evidence, not full release authorization.
3. A fresh recovery-specific WebAuthn assertion authenticates that exact key,
   with current credential trust, target-session state, authoritative roles and
   configured independent approval checked under a live context.

The old cookie is never a current-identity lookup or a substitute for the fresh
assertion. No additional token cookie, re-login workflow or plaintext token
journal is introduced. A lost old cookie is not repaired by this path.

```mermaid
flowchart LR
  R[Bounded request and old cookie] --> E[Original target and possession checks]
  E --> O[Fresh recovery options]
  O --> W[New target-key assertion]
  W --> A[Current roles, trust and approval]
  A --> P[Live private actor context]
  P -. separate unfinished integration .-> D[Fresh recovery authority and dispatch]
  D -.-> C[Verified original token and guarded cookie delivery]
```

## Public options; no permission-success endpoint

`POST /api/auth/session/activation/recovery/options` accepts only the closed
[recovery request contract](../serverware/oidc_session_activation_recovery_http_contract.py):
the fixed schema and purpose plus `localDigest`, within 64 KiB. Options reject
MFA fields; the private authorization carrier may carry a fresh assertion and
approval identifier. Neither carrier accepts a user, session, credential,
clock, grant, proof, outcome or token from JSON.

The actual request must pass exact configured-origin and cookie-CSRF checks.
The options response is a genuine action-bound WebAuthn challenge, not evidence
of an authorized recovery or an active session. The private authorization
context independently repeats original admission before consuming the fresh
assertion. It does not accept a previous options result as permission.

The fresh assertion binds the retained target and exact original-association
and old-token digests. The activation-authorization digest selected from local
claim metadata is only an association locator: including it in the assertion
does not authenticate the old execution or turn that metadata into a grant.

Current RBAC must have an active authoritative binding; no development-role
fallback or unrelated bearer/admin identity selects this flow. When two-person
approval is globally enabled, an uncovered recovery action is a configuration
refusal, not a silent approval bypass. The default action list and requester
role classification explicitly include recovery.

## Narrow, read-only retained-original selection

The source-owned selector uses the journal's existing exact-target consume
index. It reads only the activation claim, consume claim and retained release
intent, with actual bounded metadata-sized charges before file reads and
normal-close identity checks. It does not load the large prepared ciphertext,
proof setup, private packet or entire activation/consume inventory.

Expected absence is unavailable evidence, not corruption and not permission to
resend. Changed identities, malformed records or inconsistent retained metadata
still fail closed. The selected record objects are ordinary original evidence;
the historical inspector replays and verifies the actual authoritative inputs.

Original work, processing bounds and clock floors remain joined through actor
admission and its guarded lifetime. A busy startup owner is refused immediately,
without waiting, retrying or opening a later allowance. Actual startup/trust
locks stay held during the private authorization context; its scope is
invalidated on exit. No old activation permission is reopened and no old intent
interval is renewed.

## Remaining recovery work

This slice requires a retained release intent. Failures before that stage still
need a distinct original-bound completion/recovery path; they are not treated
as safe activation retries. Full recovery also needs fresh independently issued
recovery-profile authority, exact retained outcome/storage admission, the finite
private recovery exchange, genuine response verification and a final current-
auth/cookie boundary. A once-checked actor or intent result cannot replace any
of those checks.

No protected activation or consume SQL is repeated here. WebAuthn challenge
issuance and assertion-counter updates remain their normal authentication
effects. Missing, partial or uncertain evidence preserves the existing cookie
and never grants automatic retry. Portal integration, provisioning and all
production acceptance gates remain separate work.
