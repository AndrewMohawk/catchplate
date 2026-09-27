# Finite private release service

The source-fixed service connects the actual
[release startup](oidc-session-activation-release-startup.md) to one private
request and its success-only response. Source is unbuilt and unexecuted; this
does not provision or demonstrate a running service, network delivery, current
authentication or production readiness.

## Original resource and lifetime ownership

`oidc_session_activation_release_runner._run_with_resources(resource_owner)`
consumes the exact real resource owner produced by root delivery. It calls
`startup.start_from_resources` once, without another intake, privilege drop,
execution boundary, work ledger or clock opening. The fixed process remains
UID/GID 65502 in the same PID. Standalone runner starts fail closed.

Startup retains the five delivered descriptors, actual journal duplicate and,
after admission, one accepted socket. `accept_on_work()` waits under the original
root-admitted allowance and owns that nonblocking close-on-exec socket. The
service and transport never close or detach it. One accepted request is terminal,
including malformed input, peer rejection, disconnect or timeout; there is no
retry loop or second operation.

## Fixed dispatch

`oidc_session_activation_release_service.serve_once(started)` requires the exact
actual startup owner. Its root-selected profile determines the permitted frames:

| Profile | Immutable request originals | Actual operation |
| --- | --- | --- |
| `live-release` | Fixed live purpose, proof, proof enrollment, intent, intent enrollment, old token, encrypted delivery envelope | `open_committed_on_work` |
| `recovery` | Fixed recovery purpose, the same six originals, then the exact retained outcome record | `recover_on_work` |

No request supplies keys, root policy, expected release scope, a success object
or a new allowance. Startup's actual owners authenticate these originals and
the independent root pins. The service does not repeat admission or historical
replay. Transport framing is not authority.

The service computes the framed identity of the exact request and sends only
`(request_identity, actual_token_bytes)`. Its transport guard invokes the actual
startup `processing_context()` throughout I/O, enforcing the same work object,
unchanged opening bracket and only-narrowing lifetime. Any intent/proof expiry
admitted by the actual operation constrains sending. Successful transmission is
followed by startup-owned connection close and another current guard.

## Failure and completion boundary

There is no error or uncertain-response frame after failed admission or a
poisoned owner. Failure closes the actual startup and resources without deleting
or replacing durable outcomes. A partial send or absent response does not prove
absence, authorize another opening or grant an automatic retry.

The runner returns only status: zero requires the sole success send and
established cleanup; any operation, signal or cleanup failure returns nonzero
with a fixed secret-free diagnostic. No token, socket or owner escapes through
the runner result. Successful local sending is not independently authenticated
receipt or a single-egress acknowledgment. Independent response verification,
authorized caller handoff and later public/portal permission remain separate
requirements. No SQL, history key, signing key, provisioning or production
acceptance is added by this service.
