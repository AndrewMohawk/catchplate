# Native workload local CONNECT sidecar

`serverware-workload-sidecar` is the standalone multi-connection local adapter
for applications whose HTTPS proxy clients cannot present the workload's mTLS
identity to Serverware directly. It is separate from the existing
[one-CONNECT bootstrap adapter](native-application-proxy.md). It does not
bootstrap an application, issue certificates, create a network namespace,
install a CA, change egress rules or declare a native pilot ready.

```mermaid
flowchart LR
    A[Application] -->|Local token, loopback CONNECT| S[Workload sidecar]
    S -->|Workload mTLS, fresh attested session| G[Serverware native gate]
    G -->|Policy-authorized credential use| P[Upstream provider]
```

## Independently provisioned cold inputs

The exact fourteen-field
[sidecar configuration](../schemas/native-workload-sidecar.v1.schema.json)
contains the workload ID, loopback port, local-token digest, exact destination
allowlist, real workload network-namespace device/inode/boot and UID/GID,
original issue/expiry interval, connection/byte bounds and five-field upstream
scope. Supply its exact independent SHA256 pin. The original must be an
existing owner-only file; the installed unprivileged service must be able to
read it and the separately protected workload private-key original.

Upstream pins name already provisioned workload certificate/chain and private
key, a fixed non-loopback literal gate address and principal, and the exact
[nativeProxyIngress/v4 service original](../schemas/native-proxy-ingress.v4.schema.json).
That original pins existing startup evidence, independent startup expectations,
nonce-free session scope, Nitro trust roots, workload issuer, expected principal
and identity-policy commitment. Neither the service nor its installer generates
keys, approves pins, retrieves replacement originals or uses supplied local
identity headers as native authority. Existing native workload issuance and
`serverware-enrollment --admit-native-workload-certificate` remain separate
provisioning steps, not actions performed at service startup.

An independent provisioner supplies a nonzero 32-random-byte local token,
encoded as exactly 43 unpadded base64url ASCII characters. `localTokenSha256`
hashes **those 43 ASCII bytes**, not the decoded bytes. Deliver the token only
to the intended workload; do not put it in this configuration, a service unit,
logs or shell history. Conventional proxy clients use the workload ID as Basic
username and that exact token text as password, with the semantic proxy URL
`http://WORKLOAD_ID:TOKEN@127.0.0.1:PORT`. Provision that setting through the
application's protected configuration. Proxy environment support and secret
exposure vary by client; do not infer correct use from setting a variable.

## Local and upstream connection boundaries

The service starts unprivileged in a **preexisting, explicitly admitted workload
network namespace**, retains its real namespace descriptor and checks its
boot/device/inode and exact UID/GID. It binds only `127.0.0.1`, never all host
interfaces. It does not select a default host namespace or create one. The
token is bound by the unchanged cold original to this workload, namespace and
absolute expiry; it is not an OS-level proof of which process knows the token.
The operator must protect token delivery and separately enforce application
egress so the proxy cannot be bypassed. Namespace membership alone is not an
egress-policy installation receipt or hostile-host isolation.

Before any native contact, the local parser requires one HTTP/1.0 or HTTP/1.1
CONNECT, at most 8192 bytes and 64 lines, one canonical Basic authorization,
and an exact allowlisted canonical DNS:port. Host must agree and is required
for HTTP/1.1. Only bounded User-Agent, Connection and Proxy-Connection are
otherwise accepted; duplicate fields, bodies/framing, upgrades, folded headers
and unknown fields fail closed. The reader stops at the header terminator,
without taking bytes from the inner TLS stream. Authentication uses a
fixed-length constant-time digest comparison. The entire header and decoded
credential temporaries are wiped. Only the authenticated destination leaves
the parser: local Proxy-Authorization and other supplied headers are never
forwarded. There is no direct-provider fallback.

The explicit v4 service source genuinely verifies fresh startup once under the
existing startup freshness checks, then retains the exact initial leaf, CA and
immutable source scope. Every new upstream TLS connection obtains a fresh
existing native PrincipalSession challenge/proof and verifies the actual
selected workload chain and principal before sending its independently
constructed CONNECT. It does not reuse or reset a one-shot admission. Legacy
v1-v3 remain unchanged and do not accept v4. This service is not a relaxation of
their repeated-startup freshness checks or a five-minute daemon advertised as
a long-lived service.

The original cold interval is at most 24 hours and must also fit actual native
certificate/PKI/source limits; an overlong scope is refused. Each connection is
at most 120 seconds and is also clipped by the service's original absolute limit; wall, boot and monotonic
checks never renew it. Configuration bounds allow 1..16 concurrent connections,
1..5000 ms for a local header and 4096..1073741824 tunnel bytes independently
per direction, with two fixed 16 KiB relay buffers. Reaching either directional
cap closes the connection without probing past it or declaring provider success. Fresh proof does
not renew a certificate or the service. Native trust retains its existing
no-CRL boundary: no live revocation, witness, automatic renewal or automatic
retry claim is made. A fresh independently provisioned cold start is required
after expiry or a poisoned service scope.

## Fixed artifact and offline unit preparation

The existing pinned offline static-musl owner builds the dedicated
`native-workload-sidecar-artifact` target in
`data-plane/decision-gate-rs/Dockerfile.production`. It preserves the frozen
Cargo inputs and checks that the binary has no interpreter or dynamic-needed
entries and is at most 64 MiB. The existing production artifact builder accepts
this exact target, with the same source/dependency and build-network checks.
Its export contains only:

- `usr/local/libexec/serverware-workload-sidecar` (0555);
- `usr/share/serverware/install_workload_sidecar_unit.py` (0444);
- `usr/share/serverware/native-workload-sidecar.v1.schema.json` (0444).

This workload-side artifact is not copied into the native claimant closure or
advertised as an enclave service. Artifact construction is not installation,
enrollment or successful traffic evidence. No Cargo or dependency additions are
needed for it.

After independently installing the fixed binary and provisioning the cold
files and existing namespace, the Linux amd64 offline helper can emit one
service unit:

```text
python3 -I -B /usr/share/serverware/install_workload_sidecar_unit.py \
  --configuration /absolute/workload/sidecar.json \
  --configuration-sha256 sha256:INDEPENDENT_CONFIG_DIGEST \
  --network-namespace /run/netns/EXISTING_WORKLOAD_NAMESPACE \
  --output /absolute/new-owner-only-output/serverware-workload-sidecar.service
```

The output directory must already exist, be caller-owned mode 0700, and the
named output must not exist. Configuration is a single-link 0400/0600 regular
file owned by the exact nonroot service UID. The helper verifies its pin and
live original boot/time interval, the namespace's actual nsfs/network type and
matching device/inode, retains/rechecks the original descriptors during output,
and writes/fsyncs/readbacks an exclusive 0600 unit. Paths must be absolute,
no-symlink and contain only ASCII letters, digits, `/`, `.`, `_`, `-`, without
empty/dot/traversal components; systemd expansions and ambiguous whitespace are
not accepted. The Rust service remains the full configuration/upstream
validator. This unit preparation is not a readiness test.

The unit has literal numeric User/Group, the explicit `NetworkNamespacePath`,
and fixed `ExecStart` containing only `--configuration` and
`--configuration-sha256`. It uses `NoNewPrivileges`, empty capabilities,
`Restart=no`, control-group cleanup and a 120-second stop timeout before forced
termination. It has no Install section. The helper only emits the file: no
install/start/enable/systemd call, no namespace creation, no credential copying,
no network call. Retain any partial output on error rather than overwriting or
treating it as installed. A privileged operator must separately install and
explicitly start the unit in the already approved environment; runtime rechecks
the real namespace and all original bounds.

On SIGINT/TERM the server stops accepts and closes retained local socket clones;
already active upstream phases remain within their original <=120-second
connection deadlines, not a renewed shutdown allowance or a reconnect.
The <=120-second connection/network bound is not a hard bound on filesystem
operations: original-file acquisition/readback can block in the kernel. Use an
external process/cgroup watchdog and operator-owned terminal cleanup. The unit's
stop timeout requests forced termination, but does not prove a task blocked in
uninterruptible I/O has exited. Do not restart over an unknown surviving owner.

Broad acceptance, actual client compatibility, negative controls, deployment,
egress enforcement and native request evidence remain separate work. Source or
artifact availability does not satisfy those gates.
