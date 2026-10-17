# Fixed-target native parent relay

Status: source-only, unbuilt and unexecuted.
[`catchplate-native-parent-relay`](../data-plane/decision-gate-rs/src/bin/catchplate-native-parent-relay.rs)
provides a parent-side CLI for the existing bounded relay owner. It forwards
opaque bytes to one configured literal TCP endpoint; it does not terminate TLS,
obtain credentials, verify Nitro evidence or provision an admitted service.
The separate [parent ingress bridge](native-parent-ingress.md) handles the
opposite direction: fixed TCP listener to fixed enclave CID/port, without TLS
termination or authenticated original-client-IP forwarding.

## Exact CLI and configuration

The command shape is below. Paths and pins are placeholders, not a ready or
independently approved deployment:

```text
catchplate-native-parent-relay \
  --configuration /approved/parent-relay.json \
  --configuration-sha256 sha256:<exact-configuration-original-digest>
```

Both options are required exactly once; unknown, duplicate or missing arguments
fail. Configuration is explicit, with no environment/default destination or
target learned from a connection. The original file's SHA-256 pin establishes
local byte identity, not independent authorization of its inventory.

The [closed configuration](../data-plane/decision-gate-rs/src/native_parent_relay_cli/config.rs)
object contains:

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `catchplate.nativeParentRelayConfiguration/v1`. |
| `listenPort` | Fixed parent vsock port greater than 1,023 and not `u32::MAX`. |
| `expectedEnclaveCid` | One concrete expected enclave CID greater than 3, not `u32::MAX`; checked against the actual peer/listener scope. |
| `target` | One literal `SocketAddr`, including TCP port; no hostname, DNS, redirect or on-wire target override. |
| `workers` | 1–16 scoped workers. |
| `queueCapacity` | 1–64 queued connections. |
| `deadlineBoottimeNs` | Original absolute deadline in the **parent's** `CLOCK_BOOTTIME` domain. |

The original configuration is nonempty and at most 16 KiB. The CLI reuses the
[retained original reader](../data-plane/decision-gate-rs/src/native_startup_config/originals.rs):
exact canonical absolute path, component-by-component no-follow opens, regular
file admission, actual SHA-256/size/metadata checks and a final held-file/name
recheck before binding and again before serving, not after shutdown or as a
live reload. This relay configuration contains no credentials or private keys and
does not use the native gate's separate private-file-mode requirement. The
reader does not make mutable storage immutable or authenticate its supplied pin.

Use one process for each distinct fixed parent-port/target assignment. The
enclave's [relay inventory](enclave-outbound-transport.md) must independently
agree about the port and literal endpoint. Multiple origins can share a port
only where that inventory already permits the same literal endpoint. There is
no process-local arbitrary-destination proxy or live assignment update API.

The parent's absolute deadline is not numerically comparable to an enclave's
boottime deadline: they belong to different clock domains. Each side retains
and enforces its own original local bound. Supplying equal integers does not
establish equal expiry times or independent trusted-time evidence.

## Actual transport and termination scope

The existing [parent serving owner](../data-plane/decision-gate-rs/src/enclave_parent_relay_v1.rs)
retains the real listener, fixed target and expected peer CID. The
[shared relay](../data-plane/decision-gate-rs/src/enclave_tls_relay_io_v1.rs)
connects only that literal TCP address, clips the connect attempt to at most
three seconds within the remaining original bound, and joins the actual
connected-peer address. It accepts no hostname, CONNECT header, destination
selection or credential-injection command as routing authority. The enclave's
local CONNECT exchange is consumed before vsock; ordinary TLS handshake metadata
can still be visible to the parent.

When composed with the actual enclave HTTPS client, this path carries TLS
ciphertext and leaves certificate/hostname verification inside the enclave.
The pump itself neither encrypts nor validates arbitrary caller bytes. Kernel
peer CID checks and connected-address equality are routing checks, not
attestation, service-role authorization or independently attested network
location. A hostile parent can route differently; TLS does not prove its route.

Two 16 KiB buffers and nonblocking data operations bound the pump's buffering;
idle waits request at most 5 ms. On first EOF, it stops new reads in both
directions, drains only bytes already buffered, then attempts full shutdown.
Cancellation, error or expiry discards pending buffers and attempts shutdown.
Neither EOF nor successful forwarding proves application completion or remote
destruction.

SIGTERM and SIGINT are blocked before worker creation and consumed through
`signalfd` by one owned polling thread, not an asynchronous signal handler.
This additional monitor temporarily installs default dispositions, including
when a signal was inherited as ignored, and polls with a 100 ms timeout. After
relay workers have joined, its owner stops/joins the monitor and attempts to
restore the creator's original mask/actions; pending signals can then take
their original action. Received signals or monitor errors request cooperative
stop. Serving stops accepting, closes owned queued/active vsock sessions and
joins its scoped workers; there is no
detached cleanup thread. An already-running TCP connect and blocking kernel,
filesystem or scheduling work can delay return. The three-second connect cap,
deadline checks and joined cleanup are not a hard watchdog; an external owner
must retain hard-stop/reaping responsibility where required.
Cancellation/expiry exits unsuccessfully with a fixed diagnostic; returned
errors and unwinding diagnostics do not print configuration originals.

## Static artifact, not deployment

[Dockerfile.production](../data-plane/decision-gate-rs/Dockerfile.production)
adds this autobin to the existing digest-pinned Rust 1.88 / Alpine 3.22 offline
build, using the existing pinned Cargo/vendor/musl inputs and `cargo --frozen`.
The recipe checks for no ELF interpreter, no dynamic `NEEDED` entries and a
size of at most 64 MiB. It adds no dependencies or downloads.

The scratch target `native-parent-relay-artifact` exports
`/catchplate-native-parent-relay`. The final image installs the static-stage
binary at `/usr/local/libexec/catchplate-native-parent-relay`, root-owned with
mode 0555. Its decision-gate `ENTRYPOINT` is unchanged: installation does not
automatically run a parent relay or place that process on a Nitro parent host.
The ordinary glibc build output is not this static export.

The repository also supplies a review-required
[systemd service template](../ops/systemd/catchplate-native-parent-relay.service.in)
for one assignment. It uses the fixed libexec binary and a separately
precreated unprivileged `catchplate-native-relay` account/group; its only
substitutions are literal `@CONFIGURATION_PATH@` and `@CONFIGURATION_SHA256@`.
It has `Restart=no`, no install section or renderer, and TERM followed by a
ten-second control-group KILL escalation. That escalation is not a hard kernel
watchdog or proof of termination. Independently admit and review the binary,
configuration, account, host, assignment and literal-safe substitutions before
installation. The template is not copied into the image, installed or enabled
by this source change.

No build, static-artifact verification, traffic exercise, signal/shutdown test
or deployment was performed for this source slice. Independent executable and
configuration admission, assigned enclave CID/port inventory, parent-host
service provisioning and consolidated runtime/failure validation remain
required. This CLI supplies no KMS Recipient release, Nitro attestation,
credential authority or complete native production deployment. See
[service transport](enclave-service-transport.md) and
[native startup configuration](native-startup-config.md) for the separate
enclave-side composition and its unchanged admission boundaries.
