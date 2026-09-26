# Fixed-endpoint native parent ingress

Status: source-only, unbuilt and unexecuted.
[`serverware-native-parent-ingress`](../data-plane/decision-gate-rs/src/bin/serverware-native-parent-ingress.rs)
accepts TCP connections on one configured address and forwards opaque bytes
to one fixed enclave CID/port. It supplies the inbound half of the native
transport path, not TLS termination, client authentication, Nitro attestation
or a provisioned production service.

```text
actual client TLS connection
    -> fixed parent TCP listener
    -> opaque bytes to fixed enclave CID/port
    -> enclave TLS 1.3 server and mandatory client-certificate verification
```

This is distinct from the [outbound parent relay](native-parent-relay.md), which
accepts enclave vsock connections and connects to a fixed upstream TCP endpoint.
Neither bridge selects a destination from TLS, HTTP or another on-wire command.

## Exact CLI and original configuration

The CLI shape is below. Paths and pins are placeholders, not an admitted launch:

```text
serverware-native-parent-ingress \
  --configuration /approved/parent-ingress.json \
  --configuration-sha256 sha256:<exact-configuration-original-digest>
```

Both options are required exactly once; unknown, duplicate or missing arguments
fail. No environment/default address, forwarded target or arbitrary proxy mode
is selected. The [closed configuration](../data-plane/decision-gate-rs/src/native_parent_ingress_cli/config.rs)
has exactly seven fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `serverware.nativeParentIngressConfiguration/v1`. |
| `listenAddress` | One concrete unicast `SocketAddr`, not a wildcard address; TCP port greater than 1,023. |
| `enclaveCid` | Fixed destination CID greater than 3 and not `u32::MAX`. |
| `enclavePort` | Fixed enclave vsock port greater than 1,023 and not `u32::MAX`. |
| `workers` | 1–16 scoped workers. |
| `queueCapacity` | 1–64 queued TCP connections. |
| `deadlineBoottimeNs` | Original absolute deadline in the parent's `CLOCK_BOOTTIME` domain. |

The original is a nonempty regular file of at most 16 KiB, read through the
[shared retained-original loader](../data-plane/decision-gate-rs/src/native_startup_config/originals.rs).
It requires exact canonical absolute paths, component-by-component no-follow
opens, actual byte/hash/metadata consistency and fresh held-file/name checks
before binding and before serving. It does not reload configuration after
shutdown or permit live endpoint changes. Public ingress configuration contains
no service credentials or TLS private keys; the native gate's separate private
configuration-file mode requirement does not apply here. Pins identify local
original bytes, not independently admitted configuration or immutable storage.

Use one process for each fixed TCP-listener/enclave-endpoint assignment. CID,
port and address shape checks do not authorize that inventory. The separately
configured [enclave listener](native-startup-config.md) still requires its fixed
parent peer scope and genuine mTLS. Parent and enclave boottime clocks are
different domains: equal numeric deadlines do not establish equal expiry times.
Each side retains its own original local bound without renewal.

## What the bridge does not authenticate

The parent holds no TLS private key and does not parse TLS, HTTP or a PROXY
protocol preface to decide where traffic goes. It injects no HTTP forwarding
header or original-client-IP claim. The original TCP peer address is not
forwarded or authenticated to the enclave by this bridge. Enclave authorization
must use its independently verified client identity and existing application
gates, not a parent-provided source address.
The gate's [`GateSocket::client_ip`](../data-plane/decision-gate-rs/src/main.rs)
returns `None` for vsock: CIDR rules see absence, not a manufactured parent or
loopback IP. This bridge adds no PROXY preface or `X-Forwarded-For` injection to
change that boundary.

With the actual client/enclave TLS endpoints, the bridge carries TLS ciphertext
and leaves client-certificate verification inside the enclave. The pump does
not itself encrypt or validate arbitrary bytes. Ordinary handshake metadata
can remain visible to the parent, and a hostile parent can drop, delay or alter
traffic. Kernel CID/address joins are routing observations, not evidence of
hardware admission or trusted client identity.

## Bounded ownership and cancellation

The actual [`serve_parent_ingress_v1` cohort](../data-plane/decision-gate-rs/src/enclave_parent_ingress_v1.rs)
consumes the listener and checks its configured address. It bounds worker and
queue counts, retains shutdown custody for queued/active TCP and connected vsock
sessions, and uses one fixed enclave endpoint. The vsock connect attempt is
capped at three seconds within the original parent-local deadline; accepted
connections do not create fresh lifetimes. The shared pump retains
two 16 KiB buffers, nonblocking data I/O and requested idle waits at most 5 ms.
On first EOF it stops new reads in both directions, drains only already-buffered
bytes, then attempts full shutdown. Error, expiry or cancellation discards
pending buffers and attempts TCP/vsock shutdown; neither is a remote-destruction
or application-completion receipt.

The CLI reuses the owned SIGTERM/SIGINT `signalfd` monitor: signals are blocked
before worker creation, consumed by one joined polling thread, and request
cooperative cancellation. Relay workers join before the monitor is dropped;
the creator's original mask/actions are then restored best-effort, and pending
signals can take their original action. There is no asynchronous Rust signal
handler or detached cleanup worker.
Cancellation/expiry returns an unsuccessful exit with a fixed diagnostic;
configuration originals and panic payloads are not printed by the entrypoint.

Connection, filesystem and kernel/scheduling delays can postpone return.
Original-deadline checks and cooperative cleanup are not a hard syscall
watchdog. A separately responsible owner must retain hard-stop/reaping custody
where required. Cancellation cannot prove that every remote effect has stopped.

## Static packaging and review-required service input

[Dockerfile.production](../data-plane/decision-gate-rs/Dockerfile.production)
builds the autobin in its existing digest-pinned Rust 1.88 / Alpine 3.22 offline
stage, using pinned Cargo/vendor/musl inputs and `cargo --frozen`. The recipe
checks no ELF interpreter, no dynamic `NEEDED` entries and a size at most 64 MiB.
It adds no dependency or download. `native-parent-ingress-artifact` exports
`/serverware-native-parent-ingress`; the final image installs the static-stage
binary root-owned, mode 0555, at
`/usr/local/libexec/serverware-native-parent-ingress`. The image's decision-gate
`ENTRYPOINT` remains unchanged. The ordinary glibc output is not this export.

The [service template](../ops/systemd/serverware-native-parent-ingress.service.in)
is review-required, unrendered and uninstalled. It names a separately precreated
unprivileged `serverware-native-ingress` account/group and the fixed binary;
only literal `@CONFIGURATION_PATH@` and `@CONFIGURATION_SHA256@` are substituted.
It has no install section, renderer or `Restart` loop. TERM requests joined
cancellation, followed by ten-second control-group KILL escalation; this is not
a hard kernel watchdog or proof that blocked tasks terminated. No account,
cloud permission, firewall rule, listener or parent host is provisioned here.

Independent binary/configuration/host/assignment admission, protected service
provisioning and full enclave/client mTLS deployment remain required. This slice
supplies no KMS release, Nitro evidence, signed inventory or production-readiness
claim. No build, traffic test, signal/expiry exercise or deployment was performed;
consolidated frozen artifact and end-to-end failure validation remain pending.
