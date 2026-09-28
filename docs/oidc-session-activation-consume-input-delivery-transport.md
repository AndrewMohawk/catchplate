# Exact consume-input staging transport

`authority_oidc_session_activation_consume_input_delivery_transport` carries
only an issued planner/history pair and an identity-only staged ACK. It never
admits signatures, reads keys/resources, creates a worker or transfers the
ephemeral old-token request.

The fixed root listener is
`/run/serverware/oidc-session-activation/consume-bootstrap.sock`. The server
checks issuer UID/GID `65495:65495` before request bytes. The issuer checks the
root-created listener peer `0:0`; its independently signed endpoint supplies
an exact integer timeout of 1–30 seconds, which only tightens the original
deadline.

| Frame | Exact original inventory |
| --- | --- |
| Request `SWOCDQ01` | `stage-oidc-session-activation-consume-inputs`, planner bootstrap, history custody |
| Response `SWOCDR01` | `staged`, planner identity ASCII71, history identity ASCII71 |

Each header is 32 bytes: magic8 followed by three unsigned big-endian lengths.
Planner originals are 2 bytes through 4 MiB; history originals are 2 bytes
through 8 MiB. The ACK
is exactly 6 + 71 + 71 bytes. Every declared length and the whole raw3 are
checked before body allocation; exact EOF rejects trailing bytes.

```text
_recv_request(connection, *, deadline_ns, work, current,
    maximum_original_bytes=None)
_send_response(connection, originals, *, deadline_ns, work, current)
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
    channel)
_pair_identities_on_work(planner_original, history_original, *, deadline_ns,
    work, current)
```

The optional receive ceiling is an exact integer from 4 bytes through 12 MiB, limiting
the **sum of planner and history bodies**, not their purpose/header. Root
delivery must compute its remaining whole-call capacity from independently
held originals and decoding/resource reservations and supply that tightening
ceiling. The fixed exchange also fits the source 64 MiB aggregate bound.
All body storage is precharged before any body is allocated.

The identity helper frames each exact original through the existing metered
framing primitive in two new, distinct domains:

```text
serverware.oidcSessionActivationConsumeInputDeliveryPlannerBootstrapIdentity/v1
serverware.oidcSessionActivationConsumeInputDeliveryHistoryCustodyIdentity/v1
```

These are not raw SHA-256 wrapper digests or interchangeable identities. The
same helper supplies admission output and exact outgoing ACK comparison.
Neither an identity nor a well-formed ACK independently admits authority.

The socket client requires the actual consume issuer's private
`_DeliveryChannel`, not an incoming socket/descriptor exception or a generic
caller profile. That genuine owner creates, registers, authenticates and
closes its one outgoing socket. The transport guards allocation, connect,
peer checks, bounded chunks, EOF and normal close with the original work and
current guard. It returns only after both ACK identities match and the owned
channel closes normally. Failure or uncertain close is terminal, without
retry, fallback, detach or a fresh allowance.

Root delivery must perform genuine
[independent staging admission](oidc-session-activation-consume-input-delivery-admission.md)
and hold the exact authorized resources before constructing the ACK. `staged`
does not mean permanent privilege drop, worker readiness, private replay,
commit, token delivery or current authentication. No staging receipt may
substitute for the actual request receiver or consume worker checks. This is
source-only implementation, unbuilt and unexecuted.
