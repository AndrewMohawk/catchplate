# Explicit activation and recovery approval continuation

The `.218` portal uses fresh server-issued options and real WebAuthn assertions
for each action. A required second-person approval can interrupt that call
before protected execution. Previously, activation/recovery HTTP handlers
discarded the approval locator while returning their fixed failure bodies.

The actual application two-person gate now raises a private HTTP-exception
subclass when it creates or retrieves an approval request. Ordinary consumers
still see the existing HTTP 428 detail. Only activation/recovery handlers
recognize that exact source exception and project a bounded public response;
generic 428 errors, private-service replies and ordinary uncertainty cannot
create this continuation. Activation additionally requires its pre-dispatch
flag to remain false. The recovery actor's approval gate precedes the protected
continuation and its durable effect claims.

The public HTTP 428 object contains only `detail`, with nine fields:

- `schema: catchplate.oidcSessionActivationApprovalRequired/v1`
- `error: control_plane_approval_required`
- `approvalId`, `action`, `resourceId`, `payloadDigest`
- `dispatchState: approval-required`
- `automaticRetryAllowed: false`
- `freshAuthorizationRequired: true`

Action is one of the two source-fixed activation/recovery actions. Approval and
resource identifiers are bounded printable ASCII; the payload digest is exact
lowercase SHA-256 framing. The serialized response is capped at 16 KiB, uses
no-store/no-cache/nosniff headers and has no cookie, token, private original,
exception message or generic retry instruction. It conveys negotiation data,
not permission, and makes no claim about earlier execution or current sessions.

The portal keeps the original attempt marked as submitted. A matching typed
approval response may create one in-memory, explicitly selected continuation
bound to that exact action, locator, actor context and server payload. After
independent approval, the requester must explicitly continue with new options
and new assertions. The options must still match the held binding. Context
changes discard that continuation; generic errors never clear the attempt or
authorize repeating SQL. No assertion or approval state is persisted by the
portal, and no automatic approval polling or resubmission is introduced.

Source only: these joins have not been built or runtime-tested. Server-side
approval consumption, independent approver requirements and actual execution
guards remain authoritative; the browser's negotiation state substitutes for
none of them.
