# Enrolled OAuth activation portal

This is source integration for the new-credential ceremony in
[controlled activation](oauth-controlled-activation.md), following
[enrolled consent](oauth-enrolled-consent-portal.md). It is not a tested pilot,
browser verification, provider proof or production acceptance.

## Operator journey

1. The requester selects **Review enrolled account** from the pending list, or
   enters the exact pending credential ID and selects **Inspect exact account**.
   A fresh cookie check and SELECT-only activation-original read supply the
   account, provider subject, application, client, scopes and exact binding hashes.
2. After checking the review, the requester explicitly asks for approval with a
   fresh passkey. A definite HTTP 428 carrying the exact approval continuation
   means **approval requested**, never credential activated. The UI does not
   follow the response's `retry` field automatically.
3. A different operator with the literal `credential_owner` role selects Approve
   in the queue. The UI reads the current account original, compares all four
   binding strings, presents the complete account/scope review for confirmation,
   obtains a new purpose-bound passkey assertion and approves once. Notes,
   including whitespace-only notes, are refused rather than silently discarded.
4. The requester refreshes the queue, explicitly selects that matching approved
   record and activates with another fresh passkey. The backend atomically
   consumes the approval and publishes the credential. The UI accepts only the
   exact active version-one credential and consumed approval response.

After a reload, the pending ID plus the actual matching queue record allows
selection without restoring browser-stored assertions or a generic mutation.
Missing queue data is not evidence that a previous request failed. An uncertain
submission must be investigated through retained server state, not retried by
reloading. Approval queues are observations; each new operation obtains current
backend authorization and rechecks actual originals.

## Profile and authority boundaries

The consent module's shared, per-response `enrolledOAuthProfile` is the only UI
selector. Only the independently selected cold backend chooses the enrolled
profile. An unavailable selector refuses actions; an HTTP error never switches
to development. The legacy development flow remains explicitly separate.

The enrolled UI requires a secure, top-level page, an active OIDC cookie and the
literal `credential_owner` role for both people. An admin role alone does not
qualify. Entered bearer credentials block the ceremony; the UI does not silently
clear them. Fresh cookie checks bracket options, WebAuthn and final response
handling. Same-origin POSTs obtain CSRF originals immediately before dispatch.

Only the four string fields in `oauthActivationOriginal/v1.request` are echoed:
pending credential ID, pending-row SHA-256, enrollment SHA-256 and payload
digest. Numeric metadata and review data are display-only; they are not signed
inputs, currentness evidence or permission. In particular, a JavaScript numeric
projection of an i64 generation is never echoed or used to choose authority.
The reviewed account/subject/scopes and binding hashes are rendered as text.
No credential plaintext is requested or returned.

Each ceremony has one nonrenewing 120-second UI budget, clipped to observed
pending, challenge and approval expiry. Each HTTP exchange is capped at 30
seconds within that budget. The server independently applies its own genuine
enrollment/currentness/deadline checks; UI clocks and locks confer no authority.
Responses are bounded, duplicate-key-rejecting JSON; exact action shapes and
WebAuthn challenge/origin/credential associations are checked before submission.
Hardware provenance and signature verification remain server responsibilities.

Before final dispatch, a page-local lock is consumed. Context changes abort
in-flight work; submitted but unconfirmed outcomes block further mutations for
that pending account and actor in this page. A later cookie-check failure does
not erase a definite acknowledgment or turn it into permission to repeat.
Selection changes do not clear locks. No session/local storage holds assertions,
continuations or authority. Browser-memory clearing is not a key-erasure claim.

Setup, reconnect, denial, cancellation and revocation are not silently routed
through legacy helpers in the enrolled flow. Each requires its own controlled
lifecycle operation. The separate revocation work path is not a browser retry
button or a claim that an accepted HTTP response proves provider revocation.

## Deferred verification

After source integration and artifact preparation, the consolidated verification
must exercise both real operators, actual trusted passkeys, expiry/context
changes, malformed and oversized responses, non-null notes, distinct-account
selection, lost final replies, approved-record selection after reload, exact
credential publication and explicit development/enrolled/unavailable routing.
No browser, parser, build, runtime or provider execution has been performed for
this source batch.
