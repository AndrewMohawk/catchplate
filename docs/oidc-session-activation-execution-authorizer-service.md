# Activation execution authorizer service

This is a source-only, dedicated grant service for `oidc.session.activate`.
It joins the actual [role bootstrap](oidc-session-activation-execution-authorizer-bootstrap.md),
[receiving custody](oidc-session-activation-execution-custody.md) and genuine
[post-plan execution authorization](oidc-session-activation-execution-authorization.md).
It does not reserve state, issue SQL custody, execute mutations, complete expired
history, release an active token or activate a browser session.

## Cold ownership

`oidc_session_activation_execution_authorizer_startup.py` exposes
`initialize_from_environment()`, `require_started()` and `close()`.
The actual singleton's `serve_once()` returns false on an idle wait or true after
its sole completed exchange. Every accepted connection spends the launch,
including peer rejection, malformed input and uncertain delivery. Failures do
not restart the singleton or authorize a retry.

The process is fixed to mode `oidc-session-activation-execution-authorizer`,
UID/GID `65506`, no supplementary groups and the exact eight-variable child
environment. The listener accepts only peer UID/GID `65532`; clients authenticate
the root-created listener as `0:0`. The socket is fixed at
`/run/catchplate/oidc-session-activation-execution/authorizer.sock`.

The seven inherited descriptors are root `198`, role bootstrap `199`, listener
`200`, receiving-custody original `201`, bundle key `202`, delivery-custody key
`203` and dedicated grant-signing key `204`. Genuine root admission precedes
private-key loading. The actual custody owner receives the independently
role-admitted receiver identity, both separately pinned raw32 encryption keys
and the unchanged receiving original. The signer must match the actual enrolled
authorizer public key. No journal key, caller signing key or successful input
carrier substitutes for this admission.

PID, process identity, environment, sealed originals, listener/path identities,
descriptor inventory and actual custody configuration remain checked. Closing
drops held key references and closes the custody owner, duplicate listener and
all seven adopted inherited descriptors. Accepted sockets close on success,
ordinary failure and cancellation. Host-local custody is not measured hardware
or protection against a hostile root.

## Fixed original exchange

`authority_oidc_session_activation_execution_authorizer_transport.py` uses
`SWOAGQ01` requests and `SWOAGR01` responses, with u64 big-endian lengths.
The exact request raw4 is:

1. Original signed activation execution authorization, at most 64 KiB.
2. Original signed activation plan, at most 16 KiB.
3. Original encrypted execution bundle, under the actual bundle framing cap.
4. Canonical closed expectation JSON containing only `request`, `scope` and
   `journalDigest`, at most 2 MiB.

The response is raw1: the original signed execution grant, at most 64 KiB.
It contains no plaintext private journal, tokens, encryption keys or error text.
Framing performs no JSON, signature or permission admission. Lengths are checked
before body allocation; reserving the maximum response plus both headers keeps
the entire exchange within 64 MiB. Per-frame caps do not enlarge cumulative
work or the later protected-packet cap. Both directions require exact EOF;
the client half-closes its request and never retries automatically.

`_socket_request(endpoint, *, originals, deadline_ns)` requires the original
inherited bound and the source-fixed endpoint with integer timeout 1–30 seconds.
It returns unverified original grant bytes; receiving callers must genuinely
verify them. No uncertainty response is fabricated: a failed or partial exchange
is not proof that no grant was signed, and provides no retry permission.

## One original request lifetime

One work allowance and clock bracket open before peer or frame intake. Canonical
expectation capture may only narrow that bracket to the supplied scope's
deadline/age/skew. Those data are not authority: the original role and receiving
bootstraps are reauthenticated, then the dedicated producer verifies actual
caller authorization and performs genuine raw2 replay before signing.
Configuration, keys, enrollments and the complete before-vector come from
root-admitted originals, not the request's expectation graph.

The same work, opening samples and inherited bound cover replay, signing and
send. Sticky clock checks reject rollback; the actual returned grant's unchanged
expiry additionally clips transmission and final return. Nothing backdates the
post-plan authorization or renews plan, state observation, launch or grant time.

This grant-role wiring does not supply the separate reserver/state-peer and
SQL-role services, durable one-use execution, historical completion, protected
token release or public/portal permission flows. No keys, accounts, sockets or
services were provisioned. The source is unbuilt and unexecuted; no test or
production-readiness result is claimed.
