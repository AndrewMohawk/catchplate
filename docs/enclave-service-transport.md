# Native control-plane service transport

Status: source-only, unbuilt and unexecuted. The native preparation path now
composes the existing control-plane HTTP clients with fixed-authority transport,
and a callable parent relay owns bounded serving and cleanup. This is not an
activated native startup, daemon installation or independent admission of
configuration, keys, endpoints or enclave identity.

## Exact service inventory

The [gate](../data-plane/decision-gate-rs/src/main.rs) retains the existing URLs
and application protocols. Five configured URL fields form one shared service
table; credential leases retain their separate exact-origin client.

| Configured URL field | Existing request path | Actual consumer |
| --- | --- | --- |
| Policy trust-root attestation | `GET /attestation`, with generated nonce query | `fetch_attested_policy_trust_root` |
| Audit | `POST /api/data-plane/audit` | `post_audit_batch` |
| Grant consumption | `POST /api/data-plane/grants/consume` | `consume_shared_grant` |
| Rate-limit consumption | `POST /api/data-plane/rate-limits/consume` | `enforce_shared_rate_limit` |
| Release-authorization base | `POST /api/data-plane/release-authorizations/{reserve,dispatch,complete}` | `post_release_authorization_http` |
| Credential lease, separate client | `POST /api/data-plane/credential-leases` | `fetch_scoped_credential_lease` |

There is no additional policy-download endpoint in this path: `load_snapshot`
reads the local policy bundle and obtains its trust root through the attestation
source. `refresh_policy_snapshot` uses that same source. Policy-shadow generation
installation calls `load_shadow_snapshot_pair` with
`state.policy_trust_root_source`, not a separately constructed HTTP client.

## Retained multi-authority routing

[NativeUpstreamRelaysV1::service_proxy](../data-plane/decision-gate-rs/src/native_upstream_relays_v1.rs)
takes 1..32 configured HTTPS URLs. Each origin must resolve to exactly one
existing static host/literal-`SocketAddr` assignment; missing or ambiguous
assignments deny preparation. The owner deduplicates the resulting authority
table and retains its tunnel. A later call cannot replace that table or renew
the original process/boottime lifetime. The broker continues to use
`broker_proxy` separately.

[LoopbackTlsTunnelV1::open_routes](../data-plane/decision-gate-rs/src/enclave_loopback_tunnel_v1.rs)
accepts 1..32 unique, fixed authority-to-parent-port entries. It retains the
single-authority adapter's authenticated `127.0.0.1` CONNECT protocol, fresh
local Basic token, four workers, queue of 16, bounded shutdown inventory and
joined cleanup. CONNECT and Host must name the same exact configured authority;
only the retained table selects a parent port. Unknown authorities fail instead
of selecting a new destination. No destination or local authentication header
is forwarded over vsock.

Native preparation installs an HTTPS-only proxy on **all** HTTPS requests from
the shared client, rather than an optional per-host proxy callback that could
fall back to direct networking. The existing builder disables ambient proxies
and redirects and retains its control-plane CA configuration and TLS peer
information. Reqwest still performs actual TLS and hostname verification inside
the intended enclave boundary. HTTP is rejected on these prepared clients.

`prepare_native_tls_gate_state` requires an unused attested trust source and
joins the actual initial policy hash to the retained runtime identity. It
installs the two-second shared `audit_client` and five-second trust client on
the same service proxy. Both disable idle per-host connection pooling so idle
TLS sessions cannot occupy all four shared bridge workers; fresh connections
cost additional handshakes, with no runtime throughput claim. Provider and
broker pooling is otherwise unchanged. `NativeControlPlaneTransport` retains
the trust client and relay owner through source cloning, including refresh and shadow use; the
native trust branch does not recreate the legacy direct client. The separate
credential-broker client retains its three-second bound and fixed assignment.

Shared service requests check the actual retained native lifetime before each
attempt and after bounded response-body acquisition, clipping request timeouts
to the remaining original bound. Trust fetch similarly checks each attempt,
the acquired body and the return boundary. Existing retries do not create a new
native lifetime. Service settlement is not relabeled as a new policy operation.

Origin routing is **not** path or service-role authorization. Existing canonical
URL checks, service tokens, request scopes, attestation/nonces, signed-response
checks where required, and policy/application decisions remain in force. The
bridge neither manufactures a verified response nor supplies missing trust-root
or configuration provenance.

## Bounded parent serving owner

[serve_parent_relay_v1](../data-plane/decision-gate-rs/src/enclave_parent_relay_v1.rs)
consumes an already-created `VsockListenerV1`, one separately configured literal
`SocketAddr`, an expected enclave CID, worker/queue limits and an absolute
deadline. Its exact signature is
`serve_parent_relay_v1(listener, target, expected_peer_cid, worker_count, queue_capacity, deadline)`.
It validates the target before accepting, requires a concrete enclave CID
greater than 3 matching the actual listener scope, and clips to the listener's
original deadline. Each accepted connection is rejoined to that fixed scope.

The owner permits 1..16 workers and a queue of 1..64. Queued and running streams
retain shutdown handles; capacity rejection closes the newly accepted stream.
Scoped workers receive one immutable target and the real shared cancellation
flag. Exit cancels sessions, drops queued work and joins every worker. There is
no detached worker, on-wire target command, DNS lookup or alternate destination
retry. An already-running TCP connect may delay joining by its remaining
three-second connect bound plus kernel/scheduling delay; this is not a hard
watchdog or proof of remote destruction.

The shared pump retains the [outbound transport](enclave-outbound-transport.md)
policy: opaque TLS bytes, two 16 KiB buffers, nonblocking I/O, requested idle
waits at most 5 ms, and original-deadline/cancellation checks. First EOF stops
new reads in both directions, drains only already-buffered bytes, then attempts
full shutdown. Neither EOF nor successful forwarding authorizes an application
result. When composed with the actual HTTPS client, the relay carries TLS
ciphertext rather than decrypted application data. The pump itself does not
encrypt or validate arbitrary caller-supplied bytes.

## Still outside this source integration

The normal `main` policy loader and environment-driven startup remain legacy;
the separate [native bootstrap](enclave-bootstrap.md) now installs retained
transport before actually loading and compiling bounded original policy bytes
into fresh state. It does not retroactively admit legacy state or supply
independent bootstrap authority. No new CLI/environment mode, parent daemon/systemd
unit, listener provisioning or complete native bootstrap is activated here.
Proof/observation custody transports and the complete admitted enclave lifecycle
remain separate work.

Static endpoint/CID/port assignments and actual parent connected-peer checks
are transport configuration, not independently attested network-location
evidence. A hostile parent may route differently; hostname TLS authentication
does not prove the parent route or claimed remote IP. Independent configuration,
CA/release/policy admission, protected service credentials, key-release and
rollback controls, session revocation, deployment and frozen runtime
verification remain required. See the [runtime identity guide](enclave-runtime-identity.md)
for the remaining full-enclave and KMS boundaries.
