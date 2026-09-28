# Same-context consume completion controls

`control_plane_oidc_session_activation_consume_completion.py` connects the
actual live permission context's retained consume SQL attempt to one isolated
consume-completion exchange. It returns original bytes, not a token, current
session, private replay result or reusable permission. This is source-only
implementation; it is not evidence of a built, executed or provisioned flow.

## Entry and original ownership

`permission.complete_consume()` takes no arguments. It is available only after
that same actual context's [consume dispatch](control-plane-oidc-session-activation-consume-dispatch.md)
has retained its SQL raw4 response. The method spends a separate one-use latch
before callbacks. It cannot accept a posted SQL result, original tuple, work
ledger, deadline, context carrier or recovered journal record.

The context retains the admitted consume SQL raw8 in its original order:
caller authorization, signed plan, encrypted bundle, typed expectations,
execution grant, reserve request, computation snapshot and reserve ACK. Its
independently held complete before-vector and actual current/narrow guards
remain attached. Original activation completion, consume preparation/export,
old-cookie possession, caller-key/FD identity, parent custody and same PID/thread
are still required. No private history or AES key enters UID 65532.

Nested [consume execution configuration v3](control-plane-oidc-session-activation-consume-execution-bootstrap.md)
adds only the fixed completion endpoint. Earlier v1/v2 configurations cannot
use this continuation. It adds no key, descriptor or guessed future packet pin.
Explicit v4 selects a separate release-hint response profile; v3 remains raw4.

## One original-bound exchange

The caller independently re-admits the original consume caller authorization,
public signed grant, reserve, consume-specific snapshot and state ACK. It joins
the complete before/after vectors, actual original frame identities, root
enrollments, configured predecessor/fence and same typed consume target. The
expected commit marker is derived from these genuine signed public controls;
no fabricated private replay carrier is created or accepted.

The [distinct dispatch transport](oidc-session-activation-delivery-completion-dispatch-transport.md)
sends raw2 `(b"complete-oidc-session-activation-delivery", caller_authorization)`
under `SWODCM02`. Explicit root-signed service launch v2 admits peer 65532 and
byte-compares that authorization with its independently held original before
using its own root-pinned packet and actual private completion machinery.
The old private selector profile and peer 65497 remain distinct and strict.
An unsigned SQL packet locator is never selected or promoted into authority.

That v2 service profile returns only raw4:

- `(b"acknowledged", completion_request_digest, signed_complete, state_ACK)`; or
- `(b"uncertain", b"", b"", b"")`.

The explicit v4 caller / launch-v3 worker instead exchange the separately
versioned [`SWODCM03`/`SWODCR02` profile](oidc-session-activation-release-hints.md).
Its response is raw6: this same raw4 plus
packet-digest bytes and a bounded canonical release-hint descriptor. The latter
holds an effects digest, encrypted delivery envelope and original dates, never
a plaintext token or new authority. The caller retains raw4 first, then these
two opaque hint originals, before interpreting either. `complete_consume()`
still returns raw4; hints are sealed only inside the same actual context for
[release-intent production](control-plane-oidc-session-activation-release-intent.md).
Legacy profiles and public completion-verification claims are unchanged.

Shape validation is followed by metered first-exact
[completion-outcome retention](control-plane-oidc-session-activation-consume-records.md)
before status, identity or signature interpretation. This ninth token-free
record stays under the original live consume claim and activation-authorization
identity; it contains no old/new token, cookie or assertion. The local retention
digest is checked but is not completion authority.

For an acknowledged response, the receiver genuinely verifies the complete
request and state ACK against the root enrollment and exact reserve successor.
It checks the returned complete-request identity, fixed consume operation,
every marker join, canonical signed observation and complete after-vector.
These are authenticated public controls. The separate
[completion custodian](oidc-session-activation-delivery-completion-custody.md)
still performs private historical replay and actual commit readback; this caller
does not independently repeat or claim that proof.

## Lifetime and uncertainty

The same cumulative work and original epoch/monotonic bracket survive all
admission, socket I/O, normal close, retention and return. Actual current guards
remain mandatory around native chunks. Original root lifetimes, sticky clock
floors and narrowed skew policy persist. Grant, reserve and complete expiry and
issued-plus-maximum-age bounds only shorten that allowance; no historical
interval is renewed. The final context check retains these narrower limits.
Whole-held originals plus bounded request/response headers and maximum response
are reserved under the existing 64 MiB ceiling before network dispatch.

A normally returned uncertain SQL raw4 can lead to this one completion request;
only the actual completion service can resolve its own packet. A missing SQL
response or thrown failure has already revoked the context and cannot enter.
The completion raw4 is sealed as an observation, not presumed success. Failure
is terminal, retained bytes survive, and there is no SQL retry, automatic
completion retry, relaunch or recovery permission. An uncertain response is not
proof of noncommit, latest state, token release or delivery.

Matching root-admitted per-request service material and a finite one-exchange
worker must already be independently provisioned within the original deadline.
This source neither provisions nor restarts it. Public activation routing,
token release, caller handoff and production acceptance are not supplied by
this continuation.
