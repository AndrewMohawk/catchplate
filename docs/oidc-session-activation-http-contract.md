# Explicit activation HTTP data contract

Source only, unbuilt and unexecuted. This module defines bounded request data
and conservative failure data for a future explicit activation POST. It adds
no route, middleware, options endpoint, WebAuthn ceremony, authority issuer,
cookie operation or successful activation response. The existing
`/api/auth/session/activation/permission/options` contract remains unchanged.

## Closed request

The future body is an immutable JSON object of at most 256 KiB, with exactly:

| Field | Required data |
| --- | --- |
| `schema` | `serverware.oidcSessionActivationHttpRequest/v1` |
| `purpose` | `dispatch-oidc-session-activation` |
| `localDigest` | Existing canonical retained-finalization `sha256:` locator |
| `mfa` | Object requiring a nonempty `assertion` object; optional `approvalId` text of 1–4,096 characters |
| `planning` | Exactly `assertion` (object) and `challengeId` (text of 1–1,024 characters) |

The existing strict JSON decoder rejects duplicate fields, non-object roots,
floating-point/non-finite numbers, invalid text and trailing material. Fixed
limits are depth 16, 64 keys per object, 512 total keys, 128 items per array and
4,096 total nodes. Unknown outer, MFA or planning fields are rejected. Assertion
contents remain bounded ordinary WebAuthn data for the actual verifiers, not
an authenticated identity or a new successful-result carrier.

`parse_request(raw_bytes)` returns a newly owned ordinary dictionary and checks
the projected byte bounds. `request_originals(raw_bytes)` instead returns:

1. Canonical permission bytes containing the existing
   `authorize-oidc-session-activation` purpose, the exact locator and `mfa`,
   bounded to the existing 64 KiB permission limit and checked with its actual
   `parse_request(..., options=False)` interface.
2. Canonical planning-assertion JSON bytes, bounded to the actual 128 KiB
   activation assertion limit.
3. The exact planning challenge ID required by the real planner caller.

Both APIs consume immutable body bytes, not an incoming parsed or admitted
object. Canonicalization changes the outer JSON representation only: encoded
authenticator data, signature and client-data originals are not decoded or
regenerated. The permission and planning assertions remain separate inputs.
No byte-equality test establishes separate ceremonies: the real permission
verifier and planner must authenticate their own challenges and target.

The fixed permission action remains
`webauthn.oidc-session.activation.authorize`. Its fresh assertion may CAS-update
the credential counter, so genuine permission must precede planning on the
same live context. Optional `approvalId` is merely a carrier; actual configured
two-person approval policy decides whether it is required and authentic.

The body accepts no posted actor/session/credential target, root material,
grant, proof, server bootstrap, private key, token, deadline or permission DTO.
The browser's locator and challenge ID are not independently trusted pins.
The actual request, pending cookie, CSRF, retained subject, sole credential,
roles and approval all require genuine admission. Request-scoped consume,
proof-worker and release authority still require a separately authorized
bounded acquisition path inside the original work/window; browser input does
not supply or manufacture it.

## Failure data and route preconditions

The two output-only helpers return exactly `schema`, `purpose`, `localDigest`,
`status`, `dispatchState`, `sessionState` and `automaticRetryAllowed`.
The schema is `serverware.oidcSessionActivationHttpFailure/v1`, purpose is the
fixed dispatch purpose, locator is a canonical digest or `null`, session state
is always `unknown`, and automatic retry is always `false`.

| Helper | Status / dispatch state | Handler prerequisite |
| --- | --- | --- |
| `rejected_before_dispatch(local_digest=None)` | `rejected-before-dispatch` / `not-dispatched` | Source-controlled knowledge that this invocation did not attempt activation dispatch |
| `outcome_unknown(local_digest=None)` | `outcome-unknown` / `unknown` | Dispatch was attempted, or whether it happened cannot be established |

These are ordinary data factories, not attestations of which path ran. The
handler must never infer pre-dispatch rejection from a timeout, missing reply,
retained claim or downstream exception. Pre-dispatch rejection says nothing
about a permission assertion's counter update or any earlier invocation.
Neither helper accepts an arbitrary success flag, selects HTTP status codes,
sets a cookie or claims `activationExecuted: false` after uncertain effects.

There is deliberately no success helper. A future route may replace the pending
cookie only after genuine token verification and a fresh exact current-session,
credential and identity check. Unknown outcomes preserve the pending cookie,
authorize no resend and prove neither commit nor nonexecution. Public routing,
cookie/current-auth integration, separately authorized recovery and portal work
remain open; this data contract closes none of those boundaries.
