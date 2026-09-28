# Recovery server-original staging transport

`authority_oidc_session_activation_release_recovery_delivery_transport.py`
defines one fixed public-caller → root-receiver exchange. It relays an original
already admitted and durably retained by the actual recovery acquisition
context. Framing is not recovery authority, private-store evidence, worker
readiness or token delivery. Existing LIVE staging and its private issuer peer
remain unchanged.

The only endpoint is
`/run/serverware/oidc-session-activation-token-release/recovery-bootstrap.sock`,
with root server peer `0:0`, public caller peer `65532:65532`, and an exact integer
timeout from 1 through 30 seconds that only tightens the original deadline.
The root-created staging pathname is `0:65532`, mode `0660`. The caller selects
the timeout from its genuinely admitted policy's release launch, not a browser
field or response-created endpoint.

| Direction | Magic | Exact immutable frames |
| --- | --- | --- |
| Request | `SWORDQ01` | `(b"stage-oidc-session-activation-release-recovery-bootstrap", serverBootstrap)`; bootstrap 2 bytes through the actual server's 16 MiB cap |
| Response | `SWORDR01` | `(b"staged", bootstrapIdentityASCII71)`; exact status6 and canonical digest71 |

Each header is 24 bytes: eight-byte magic and two unsigned eight-byte lengths.
The bootstrap identity uses the actual client
`SERVER_BOOTSTRAP_IDENTITY_DOMAIN` and original-byte digest helper; it is not a
hash of a re-encoded payload or a peer-provided success object. No old token,
proof, outcome record, key, resource path or caller-selected clock is sent.

The receiver APIs are `_recv_request(connection, *, deadline_ns, work, current,
maximum_bootstrap_bytes=None)` and `_send_response(connection, originals, *,
deadline_ns, work, current)`. They preserve the receiver's socket ownership.
The receive cap may only narrow 2..16 MiB and is checked against every announced
length before either body allocation. Peer identity is checked before bytes;
guarded chunks, all-body precharges and exact EOF retain the actual original
work/current/absolute deadline. There is no error/status alternative, retry or
socket replacement.

The private `_socket_request_on_work(endpoint, *, originals, deadline_ns, work,
current)` uses only literal profile 16 of the existing caller engine. The engine
owns one socket from creation through exactly one normal close, checks the root
peer before request bytes, admits the exact response lengths before allocation,
and refuses trailing bytes. The helper computes the outgoing bootstrap identity
itself and compares the received ACK after that owned close. Existing fifteen
profiles, endpoints and optional response-cap behavior are unchanged; no generic
profile or callback can be supplied as authority.

`_bootstrap_identity_on_work(original, *, deadline_ns, work, current)` is also
available to the genuine receiver. The root receiver may send `staged` only
after independently admitting the original and binding/sealing the actual
required resources. This ACK says neither that permanent privilege drop or
checkpoint-one store recovery succeeded, nor that the finite worker is ready.
The caller and root receiver retain separate original ledgers; neither learns
an allowance from the other process.

The [actor-owned context](control-plane-oidc-session-activation-recovery-acquisition.md)
adds a one-shot staging latch and full held-original/buffer reservation before
contact. Its existing durable policy-keyed attempt already makes uncertainty
non-resumable under the same authority. The optional public Compose override
mounts only the two preprovisioned acquisition/staging sockets read-only, with
`create_host_path: false`; it neither creates a worker nor installs keys/resources.

Protected recovery exchange, actual store observation and guarded public cookie
delivery remain separate work. Source only: unbuilt, unexecuted and unprovisioned.
