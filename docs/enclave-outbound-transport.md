# Native outbound TLS transport

Status: source-only, unbuilt and unexecuted. This is a fixed-route transport
composition, not enclave deployment, production activation or independent
admission of the supplied endpoints, policy or trust roots. The later
[service transport integration](enclave-service-transport.md) adds a bounded
parent serving owner, not a provisioned listener daemon.

## Preserve the real TLS endpoint

Reqwest remains the HTTPS/TLS client. In an admitted native deployment it must
run inside the enclave and retain genuine upstream certificate and hostname
verification. The local bridge adapts its CONNECT transport; it does not replace
Reqwest TLS with a caller-supplied success result or move TLS termination to the
parent.

```text
enclave Reqwest TLS client
    -> authenticated 127.0.0.1 CONNECT bridge, exact configured authority
    -> opaque stream over vsock to parent CID 3 and fixed port
    -> parent TCP connection to its independently configured SocketAddr
    -> upstream TLS peer
```

The local CONNECT exchange is consumed inside the enclave. Its fresh local
Basic-authentication token and exact authority are bridge access constraints,
not upstream credentials or attestation. They are not forwarded to the parent.
The parent receives no target-selection header, hostname-resolution request or
credential-injection command. Its fixed assignment must be independently joined
to the enclave's configured authority and parent port. TLS still authenticates
the remote peer; a CID or TCP address does not do that.

The [local owner](../data-plane/decision-gate-rs/src/enclave_loopback_tunnel_v1.rs),
`LoopbackTlsTunnelV1::open(authority, relay_port, deadline)`, binds only an
ephemeral `127.0.0.1` port. Its configuration exposes that address and a fresh
password derived from 32 random bytes for Basic username `serverware-relay`. It accepts only
localhost peers and exact configured CONNECT/Host authority, bounded to 512
ASCII bytes; request heads are capped at 8 KiB. Four workers, a queue of 16 and
an active shutdown inventory of at most 21 bound the connection count. The
owner's Drop cancels active work and joins its server/workers; `verify_live`
checks that the original serving scope remains available. The password is
local access custody, not an upstream bearer credential or hardware proof.

## Fixed assignments and retained owners

[NativeUpstreamRelaysV1](../data-plane/decision-gate-rs/src/native_upstream_relays_v1.rs)
accepts 1..32 static `NativeRelayAssignmentV1 { host, endpoint, parent_port }`
entries and one original deadline. `endpoint` is a literal `SocketAddr`;
`proxy_for(host, endpoint)` requires that exact pair. A parent port may be
shared only by assignments naming the same literal endpoint. There is no
assignment mutation or deadline-renewal API, and creator-PID drift fails.

Tunnels are created lazily and retained by the route owner, rather than dropped
after returning a Reqwest proxy setting. `broker_proxy(url)` requires HTTPS
and exactly one configured endpoint matching the broker's host/port; it rejects
missing or ambiguous assignments. These ordinary configuration records do not
authenticate endpoint provenance or make an externally resolved IP trustworthy.

`resolved_addresses(host, port)` returns only the nonempty, sorted, deduplicated
IP inventory from those exact static assignments, with the same process and
deadline checks. It does not query ambient DNS or accept a caller-selected
replacement address. Independent admission of that inventory remains necessary.

The [gate integration](../data-plane/decision-gate-rs/src/main.rs) retains this
owner in `GateState` under the prepared native lifetime. Preparation rejects
preexisting relay state or a populated legacy upstream-client cache. Provider
preparation passes **all** configured addresses for that origin through the
unchanged signed route-address policy, then uses the same deterministic selected socket for
`proxy_for`. Native clients bypass the legacy cache and retain the existing
Reqwest TLS/root configuration with HTTPS-only proxying. Native policy/time
scope is checked before and after the dispatch barrier, and the request timeout
is clipped to the remaining original bound.

When a credential-broker URL is configured, preparation builds its HTTPS proxy
client from the same existing control-plane root-trust builder and the unique
fixed broker assignment. The [service transport integration](enclave-service-transport.md)
also routes the shared control-plane and trust clients; neither integration
activates native startup or independently admits those roots. Both providers and broker
keep TLS processing and plaintext request construction at the original client.

The static assignment and parent-side connected-peer check are transport
configuration, **not** independently attested remote-IP evidence. A hostile
parent can choose a different network route. Successful upstream TLS
authenticates the hostname under the admitted certificate policy; it does not
prove the parent's physical route, remote network location or claimed IP.

## Bounded relay and cleanup

The shared [relay](../data-plane/decision-gate-rs/src/enclave_tls_relay_io_v1.rs)
uses two fixed 16 KiB buffers, nonblocking data I/O and the minimum of the
caller's bound and the retained vsock stream's original boottime deadline.
Cancellation and deadline checks surround relay iterations, with requested
idle waits of at most 5 ms. It performs no TLS parsing or termination and makes
no application-completion claim from successful byte forwarding.

On the first EOF it stops reading both directions, drains only bytes already
buffered under the same deadline, and attempts full shutdown of both streams.
Errors, cancellation and expiry discard pending buffers and attempt both
shutdowns. Callers must discard the streams even if cleanup reports an error;
shutdown attempts are not proof of confirmed remote termination.

`relay_fixed_upstream_v1(stream, target, deadline)` owns one already-admitted
parent-side vsock connection. It connects only the separately supplied literal
`SocketAddr`, caps that connect attempt at three seconds within the original
deadline, and joins the actual connected peer address. It has no DNS, redirect,
listener or on-wire target-selection interface. Address-shape validation does
not authorize a destination; private or loopback assignments still require
independent admission. Early failure retains cleanup responsibility.

Nonblocking loops, bounded connect attempts and joined worker cleanup are not
hard scheduler/syscall watchdogs. They do not establish that every operation
or remote effect has stopped at the exact deadline. Scope expiry and active
session cancellation remain real owner responsibilities, not digest claims.

## Remaining production work

The parent daemon must admit the enclave CID and independently fixed port-to-TCP
assignments; no arbitrary forwarding service is activated here. Static endpoint
and address provenance, independently admitted inventory updates, lifecycle
provisioning and end-to-end runtime verification remain necessary. Native
provider/broker routing does not use ambient DNS; this is not blanket admission
of other resolver paths. Shared control-plane/audit/trust client routing and a
bounded parent serving owner are now composed in the
[service transport source](enclave-service-transport.md); admitted native
bootstrap and proof transports are not supplied by these adapters.

The complete gate's policy, credential acquisition, decryption/injection,
upstream TLS, response checks and proof authority must still execute within the
independently admitted enclave boundary. See the
[native runtime identity guide](enclave-runtime-identity.md) for key custody,
quote-verification and activation limitations. No build, test, network probe or
hardware evidence was produced by this source work.
