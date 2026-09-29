# Native ordinary-application CONNECT adapter

This is a source-only integration slice, not a tested pilot or completion of
N04/N05/N06. The explicit `nativeBootstrapClient/v9` cold path connects one
ordinary immutable-image application to the actual native proxy using one
bounded HTTP CONNECT tunnel. Existing v1–v8 profiles retain their contracts;
an incoming newer grant or manifest cannot select the new path.

## Separate authorities and originals

V9 requires nonnull genuine CA installation plus egress, attachment, execution
and `applicationProxy` input children. The application inputs are three pinned
originals: `ingressConfiguration`, `targetCertificate`, `targetPrivateKey`.
Their paths and pins are distinct, and both target identity artifacts must
differ from both bootstrap caller identity artifacts. The bootstrap caller
certificate is never the target TLS client identity.

The exact canonical ASCII `applicationProxy` object in execution manifest v3
has nine fields: profile `native-target-mtls-one-connect-v1`, listenerPort,
destination, maximumTunnelBytes, proxyEndpoint, ingressConfigurationSha256,
targetCertificateSha256, targetPrivateKeySha256 and targetPrincipalId.
Start authorization v4 signs its exact hash as `applicationProxySha256`.
Egress authorization v5 separately signs the same hash and listener port and
requires `manual-dual-stack-loopback-proxy-v1`. The unchanged launch-manifest v2
pins this actual execution-manifest original, not an old host placeholder.

The start owner joins all these originals before the irreversible creation
and start claims. Listener creation cannot proceed on an old start/egress
grant. Python producers require explicit `APPLICATION_PROFILE` or
`APPLICATION_WORKLOAD_PROFILE`; old default entrypoints refuse these versions.
Schema validation, copied hashes, capture dictionaries and lookup results do
not create permission.

## Actual child and connection

After the genuine claimed clone creates its new network namespace, the
syscall-only trampoline raises only its own `lo`, creates a nonblocking
127.0.0.1 TCP listener at the signed port (1024–65535), and transfers its actual
descriptor over the inherited private seqpacket before dropping privileges.
The privileged listener is closed in the child and never survives into the
ELF descriptor whitelist. The parent checks socket kind, protocol, listening
state, exact address/port, held identity and actual socket namespace against
the same child's retained nsfs owner. Old children send no listener and keep
loopback down; they cannot be promoted.

The two additional fixed nft output rules admit only TCP
127.0.0.1 → 127.0.0.1 with source or destination equal to that port, after the
existing fragment drops. They are included in the same one-shot transaction,
ACK custody and exact expression readback. No blanket loopback accept, host
firewall change, generic host route, NAT, DNS or external return exception is
added. Attachment preflight and final readback admit only the source-fixed
loopback addresses/routes under the genuine v5 owner. The Linux v6.12
[IPv4 loopback address constructor](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/devinet.c),
[IPv4 local/broadcast route constructor](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/fib_frontend.c)
and [IPv6 loopback constructor](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv6/addrconf.c)
define that bounded normalization. These are observations, not delete or
repair permissions.

Before releasing the blocked executable, the parent opens one literal
upstream endpoint using its retained launcher-host namespace. This is the
explicitly authorized adapter channel, not evidence that an application
opened a direct veth connection. The native ingress-v3 owner replays pinned
startup/scope/issuer originals, retains the selected target mTLS certificate,
and performs fresh same-connection role-3/principal preflight. The actual
target SPKI, target principal, native CA DER and endpoint must match the
genuine bootstrap/egress parents. The same connection sends exactly one
CONNECT for the signed canonical DNS authority. No bootstrap credential,
application-provided authentication header, arbitrary TLS configuration,
resumption, alternate endpoint or ordinary-verifier fallback is substituted.

Only after upstream CONNECT 200, actual network readiness and the independent
guardian checks can the first executable be released and positively observed
at its EXEC stop. The parent accepts one local CONNECT, requiring the exact
signed authority and Host. Optional bounded User-Agent and
Proxy-Connection: keep-alive are accepted but not forwarded. Other headers,
including Proxy-Authorization, fail closed. The local 200 is not emitted
before actual upstream success. Opaque inner TLS bytes are relayed; provider
credentials remain in the native proxy's existing per-request lease/injection
path, never in application environment, image, descriptors or relay capture.

## Application and lifetime boundary

The image has the existing real immutable single-CA PEM association, not a
writable trust installation. Signed `SSL_CERT_FILE` selects that file and
signed `HTTPS_PROXY` is exactly `http://127.0.0.1:<listenerPort>`. Competing
case-insensitive proxy variables and known competing CA environment variables
are refused. These are explicit supported application conventions (for
example an appropriately configured HTTPS client), not proof arbitrary code
honors either variable. Direct scripts still require an admitted ELF
interpreter and signed argv in the same image.

One CONNECT is **not one provider request**. Multiple requests may pass inside
the opaque tunnel; every actual provider request still needs the native
proxy's own policy, credential lease, release and proof checks. This first
adapter rejects protocols requiring multiple proxy connections; it does not
redefine the overall ordinary-application or N06 completion scope.

The relay has no worker thread and no blocking drive loop after preflight.
Each execution turn performs bounded local IO and at most one TLS wire read
and write alongside the existing output, leader, network and guardian checks.
Each direction has a separately counted signed 4096–16777216-byte bound.
The original invocation's at-most-30-second admission/transport deadline is
never renewed. EOF/error cannot open a second socket, accept or CONNECT.
After the tunnel closes, any remaining application computation is governed
only by its preexisting signed stop/cleanup limits, not new network authority.
An application that exits without actual bidirectional tunnel bytes cannot
produce a successful application-profile observation. This still does not
assert HTTP/provider success.

CA installation and execution outcomes remain separately truthful. A later
connection, release or execution failure does not roll back a completed CA
installation or authorize reinstall/retry. Relay owners drop before exclusive
child network-pin retirement; the original listener drops with child network
pins only after genuine child/guardian cleanup. Independent emergency cleanup
remains live even if transport, output or durable publication fails.

V9 capture has the same twelve fields and 1.5MiB-including-LF limit as v8, with
scope `local-fixed-endpoint-bootstrap-application-proxy-observation` and a
required nonnull installation receipt. The existing execution/retirement and
durable outcome originals are retained; SDK extraction remains data-only.
No tunnel plaintext, provider secret, action permission or restart right is
added. Kernel/issuer/grant provisioning, actual application behavior and the
measured enclave credential path still require independent runtime evidence.
