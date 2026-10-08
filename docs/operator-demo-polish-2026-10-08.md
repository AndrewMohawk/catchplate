# Operator demo polish — 2026-10-08

This change refines method support and client-token expiry in the separate
operator demo, based on `18873483`. Focused verification has passed; deployment
and live-service verification remain pending.

## Changes

- New connection input rejects `HEAD`. The demo requires bounded JSON response
  bodies; bodyless-response support is not implemented.
- The client command generator supports `OPTIONS` for an explicitly allowed
  connection. It still uses the bounded JSON policy; this does not add generic
  OPTIONS forwarding or change the allowed destination, path, or methods.
- Connection metadata reports `client_status` separately from policy activation:
  `expired` takes precedence, `ready` requires an unexpired token and matching
  loaded policy, and `pending` means the unexpired client's policy is not loaded.
  A loaded policy alone does not make an expired client usable.
- The page schedules a one-shot expiry timer, clears a held token when it expires,
  and disables the affected client actions. Expiry changes the displayed client
  state without renewing the token or changing policy activation.

This patch adds no token renewal or revocation workflow and changes no signed
policy format or Rust enforcement. Response-header compatibility remains deferred;
any future support must preserve the strict exact-value predicate contract.

## Verification

| Check | Status | Evidence / boundary |
| --- | --- | --- |
| API rejects new `HEAD` input; supported methods retain their scope | Passed, isolated backend | `HEAD` and mixed-`HEAD` requests return HTTP 422 without creating a connection; signed `OPTIONS` policy persists and reopens |
| `OPTIONS` client generation preserves the bounded JSON contract | Passed, isolated frontend | Pure generator checks; no live OPTIONS request claimed |
| `client_status` distinguishes ready, pending and expired, with expiry first | Passed, real persisted state with controlled clock/loaded hash | Nine boundary cases repeated after restart, without renewal or state writes |
| Open-page expiry clears the held token and disables client actions | Passed, intercepted browser fixtures | Rendered timer and interaction checks; live relay still pending |
| Existing credential, CA, request and audit workflow still works | Pending | Real API/browser relay verification |
| Exact reviewed source is deployed and verified | Pending | Deployment revision and retained runtime results |

Backend verification passed **20 tests**: six profile tests in 13.558 seconds,
thirteen persistence tests in 180.366 seconds, and one local HTTP runtime test in
23.243 seconds. The network-isolated, read-only container exited 0 and was removed.
These checks use real SQLite persistence, signed/schema-validated policy and a
real local HTTP server. The expiry matrix controls only the clock and observed
loaded-policy hash; it is not a live Rust policy-load or proxy test.

Frontend verification passed **29 checks**: seven pure generator checks and
twenty-two rendered Chromium groups using intercepted API fixtures. Five offline
asset tests also passed. Those browser responses are fixtures, not deployed API,
CA, credential-injection or audit evidence. Syntax and whitespace checks passed.

The tested store SHA-256 is
`18cf4735aded2dda65ea2bb4c609df41b623cabe6bdc6e6a8f42941564744062`.
Backend tests ran sequentially in image
`sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01`
with one CPU, 1 GiB memory, 64 PIDs, no network, read-only source and a disposable
256 MiB scratch tmpfs. No Rust build, renewal, live request or deployment ran in
these checks. Earlier operator-demo acceptance does not verify this patch.

## Remaining scope

The existing deployment is configured only for `https://demo-upstream:8443`.
Provider selection and a real-provider request remain open, along with WAN proxy
DNS/cutover, human SSO/workstation verification, native/hardware custody and the
full production acceptance gates. This polish does not close those requirements.
