# Guest inspector router consumer

This source connects the [fixed inspector child](response-v2-guest-inspector.md)
to the actual response-custody accept, before-dispatch and before-response
consumers. It does not launch the cohort or establish a working guest image.
The host path still uses the original opaque kernel PeerMeasurement; guest
responses can never be deserialized into that type.

## Actual private handoff

For the custody-router role, the existing exact guestListener profile now
requires an attached private inspector owner before its service thread, transaction listener or readiness
publication. There is no additional unsigned profile selector and no host
fallback. Only signed guest custody-router startup admits the complete fixed
descriptor set:

| Router FD | Original |
| --- | --- |
| 6 | Root-prepared, bound-not-listening guest transaction socket |
| 7 | Original sealed listener consistency handoff |
| 8 | Actual private inspector router channel |
| 9 | Actual clone3-owned inspector child PIDFD |
| 10 | Same sealed worker bootstrap used on the worker's FD 5 |

CLI additions are --guest-inspector-fd 8, --guest-inspector-pidfd 9 and
--guest-inspector-bootstrap-fd 10 alongside --guest-listener-fd 6 and
--guest-listener-handoff-fd 7. All five are mandatory, distinct kernel objects
and CLOEXEC before any generation/TEE verifier child. Actual signed
guest-delivery loading and listener-owner attachment precede inspector attach.
The source-owned cohort factory, not a caller-supplied PID or successful DTO,
must duplicate these only from the actual one-use
GuestInspectorRouterEndpoint owner.

The parent validates the worker's initialized frame on FD 3 using actual final
64990 SCM_CREDENTIALS and SCM_PIDFD against its owned child before exporting the
endpoint. That frame is not forwarded as inspector-origin evidence. The router
uses its own first and every actual FD 4 response. Socketpair SO_PEERCRED may
still describe root creation; it is never accepted as final inspector identity.

The router consumes the original sealed bootstrap, compares its exact
configuration/delivery hashes to its actual retained signed Delivery, and keeps
that same private Arc through cloned consumers. It checks actual boot and
retained originals, child PIDFD process identity and unchanged absolute gate
lifetime throughout. The bootstrap is consistency data, not new authority.

## Real measurement consumers

Before reading any gate frame, accept authentication passes the actual accepted
socket and its kernel connection PIDFD. The worker reply is accepted only after
actual final inspector UID/GID 64990 and SCM_PIDFD match the inherited child
original. The result must have the exact closed request echo and six measurement
fields. Any returned SCM_RIGHTS object is closed and rejected.

The router derives the process binding from actual target socket/PIDFD kernel
metadata and compares the worker result to it. Independent configured
executable, cgroup and security-label pins still decide whether the connection
is authenticated. A private Guest observation owner retains that measurement
and real process identity; the Host owner remains the original opaque core
measurement with unchanged algorithms.

Every actual inbound control frame is hashed and inspected before parsing or
dispatch. Every outbound control frame is inspected before send, including
response-data results. Requests carry the actual received packet PIDFD,
locally retained zero-based packet index and authenticated session hash only
after hello has actually established it. Before hello the session is null;
unauthenticated fields never manufacture local context.

The serialized private channel has one strictly increasing sequence, separate
from packet indices. Its lock, poll, send, receive, target recheck and inspector
recheck all consume one pre-receive absolute allowance capped by the original
gate lifetime. The response-data guest branch does not reset its operation
start after parsing. No uncertain request is resent. Any identity, context,
deadline, ancillary, measurement or channel mismatch poisons and shuts down the
shared private endpoint; no restart/rejoin/fallback is provided.

These are actual bounded kernel observations, not an assertion that a process
can never subsequently change, provider authorship, a response release grant
or a new root of trust. The measured parent executable/child ownership and
real cohort FD distribution remain indispensable. Actual provisioning,
builds, kernel/LSM behavior, guest startup and end-to-end acceptance have not
been executed by this source-only integration.
