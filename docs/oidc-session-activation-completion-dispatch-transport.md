# Activation completion dispatch transport

This source-only profile connects a caller's original signed activation
authorization to the separately configured completion service. It does not
derive completion authority from an unsigned SQL response or give the caller
private historical keys.

`authority_oidc_session_activation_completion_dispatch_transport.py` fixes:

| Item | Original-byte contract |
| --- | --- |
| Endpoint | `/run/serverware/oidc-session-activation/completion.sock`; expected root listener peer `0:0`. |
| Request | `SWOACM02`; raw2 is `complete-oidc-session-activation` and the exact signed caller authorization original, 2 bytes to 64 KiB. |
| Acknowledged response | `SWOACR01`; raw4 is `acknowledged`, completion-request digest, original signed complete control (up to 256 KiB), original state ACK (up to 16 KiB). |
| Uncertain response | `SWOACR01`; `uncertain` followed by three empty frames. |

The explicit root-admitted launch selects this profile before receiving. Its
actual service must compare the received authorization bytes to the genuinely
admitted root-held authorization original and then use only its independently
root-pinned packet locator. A request cannot select the profile, supply a new
packet pin or upgrade an unsigned SQL observation into authority. The transport
does not parse or verify the authorization signature. The service remains
UID/GID 65503 with request peer 65532; caller-side root-listener checking does
not substitute for service-side request-peer admission.

The older `SWOACM01` packet-selector profile is unchanged and does not accept
this purpose or inventory. There is no magic fallback or profile sniffing. Both
profiles reuse only the same byte-only raw4 response grammar; response framing
is not a completion verifier or an authenticated packet echo.

## Guarded caller and bounded service framing

The caller API is:

```text
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current)
```

It returns unverified raw4. The shared private caller transport chooses this
exact module as one of five literal source-fixed profiles. It retains the same
actual current guard, sticky epoch observations, cumulative work and inherited
monotonic deadline around allocation, connect, peer checking, each bounded
chunk, half-close, exact EOF and one owned close. The local timeout only
tightens the inherited bound. Response allocations are precharged before body
allocation. No clock window, work allowance, resend or close retry is created.
See the [guarded caller contract](oidc-session-activation-caller-transports.md).

The service helpers `_recv_request(connection, *, deadline_ns)` and
`_send_response(connection, originals, *, deadline_ns)` keep exact frame
lengths, the whole-exchange source ceiling, half-close and EOF. All request body
lengths are checked before allocating either body. Endpoint and response helper
reuse is source-fixed; no externally supplied codec or proof result is accepted.

Durable first-exact retention and genuine receiving admission belong to the
actual caller/service composition, not this codec. In particular, the existing
full response verifier still requires its actual privileged historical custody;
this transport does not make that owner available to UID 65532. Uncertainty or
an interrupted response provides no retry permission or absence proof.

Source is unbuilt, unexecuted and unprovisioned. This profile alone does not close
public activation dispatch, connect consume/release, issue a browser cookie or
establish production readiness.
