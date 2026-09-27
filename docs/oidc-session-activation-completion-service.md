# Cold activation completion service

The `.156` source connects the dedicated cold completion worker, protected
readers, durable completion recovery and state acknowledgment. It is **source-only,
unbuilt, unexecuted and uninstalled**; source integration is not production
acceptance or evidence that these resources have been provisioned.

## Admission and ownership

[`oidc_session_activation_completion_startup.py`](../serverware/oidc_session_activation_completion_startup.py)
exports `initialize_from_environment()`, `require_started()` and `close()`.
Only genuine initialization creates its private owner; `serve_once()` returns
`False` while idle and `True` after its one accepted exchange. An accepted
connection is terminal even when malformed, unauthorized or uncertain. The
runner does not renew the launch or automatically retry.

The fixed process is `oidc-session-activation-completion`, UID/GID **65503**,
with request peer **65532** and an exact literal environment. Its seven inherited
descriptors are:

| FD | Resource |
| --- | --- |
| 198 | Root public key |
| 199 | Signed completion bootstrap with embedded historical custody |
| 200 | `/run/serverware/oidc-session-activation/completion.sock` listener |
| 201 | Enrolled completion signing key |
| 202 | `/var/lib/serverware/oidc-session-activation-completions` journal |
| 203 | Independently pinned bundle AES key |
| 204 | Independently pinned delivery AES key |

The [delivery layer](oidc-session-activation-completion-delivery.md) authenticates
the root-signed launch before private resources are opened. Startup repeats
[bootstrap admission](oidc-session-activation-completion-bootstrap.md), checks
the sealed originals and signed listener/journal identities, and constructs the
actual historical custody owner, completion journal/delivery owner, successor
custody recovery reader, commit reader and current-root client. The two read-only
database owners consume their independent TLS, role, query and catalog pins.
No request can choose a database, key, pending head or historical context.

Continuity checks retain PID, process/environment, sealed descriptors, listener,
journal, TLS identities and actual owner configurations. The descriptor inventory
also accounts for the owned listener/journal duplicates and accepted connection.
Failure cleanup closes allocated owned resources; inherited descriptors remain
borrowed until process exit. `close()` invalidates the owner and rejects closure
while a connection is active.

## Current processing, historical originals

One startup work allowance and original clock window cover admission, key/TLS
checks and completion-journal recovery. TLS hashes and declared bytes are charged
before the actual fixed-file check. Journal replay receives that same allowance;
it does not create a fresh budget per retained record. Older delivery callers
which omit the optional inherited allowance retain their existing behavior.

Each request opens one current work/window **before peer, frame or body reads**.
Its initial age is bounded by launch timeout, caller policy and original planner
policy. Historical-role and completion-policy checks can only narrow the same
opening samples and inherited deadline. Fresh role/custody admission remains
mandatory around protected work; expired planner or execution intervals are
historical facts, never substituted clocks or renewed execution permission.
These checks are not a hard watchdog for arbitrary native calls.

## Durable recovery and wire result

The fixed transport uses `SWOACM01` / `SWOACR01`. Its raw2 request is the literal
purpose `recover-oidc-session-activation-completion` plus the canonical packet
digest. The digest must equal the independent cold pin. Lengths and aggregate
bounds precede body allocation; one inherited deadline covers peer checking,
framing, half-close and exact EOF. Socket framing alone is not semantic proof.

The actual [recovery composition](oidc-session-activation-completion-recovery.md)
holds the durable owner's recovery lock. A first completion genuinely replays
the original encrypted plan/caller/grant/reservation, independently admits pending
scope, and compares the protected committed marker and complete vector before
signing. The first exact completion is retained before state transmission; its
authenticated ACK is retained before successful return. A retained completion is
reused unchanged, with explicit state lookup/reconciliation rather than a new
signature or renewed expiry. The [v6 state peer](current-root-activation-completion-peer.md)
is a separate required admission.

The response is immutable raw4:

| Outcome | Fields |
| --- | --- |
| Acknowledged | `acknowledged`, completion-request digest, original signed completion, original ACK |
| Uncertain | `uncertain`, empty, empty, empty |

The acknowledged identity is joined to the actual retained completion and
recovery result; it is not the packet locator echoed as proof. Recoverable
exceptions disclose no internal error text. Signing, publication or acceptance
may already be durable after uncertainty or a lost response. The separate
receiving verifier authenticates originals under independently held historical
custody; unsigned framing is never accepted as completion authority.

This worker performs no SQL mutation or retry, releases no token, establishes no
current browser session and exposes no public HTTP acceptance. Generic activation
completion remains rejected; this is a distinct historical purpose. Same-source
cohort checks remain, with H05 cross-version history still separate. Trusted-host
local admission is not off-host currentness, rollback resistance or hardware
custody. Protected token release, public actions and portal confirmation remain
separate work. No runtime or provisioning verification was performed.
