# Native static network attachment authorization

This separate trusted-host-local authority permits only the fixed static
bridge/veth attachment profile. It is neither an egress grant upgrade by label
nor application-start, host routing/NAT, recovery or persistent-supervision
permission. The paired Python producer/verifier and Rust reader authenticate
original bytes. Their result is signed constraints, not a successful network
observation or permission imported from a diagnostic DTO.

## Original wire and scope

The [closed schema](../schemas/native-network-attachment-authorization.v1.schema.json)
has exactly `schema`, `payload` and `signature`. The envelope is
`catchplate.signedNativeNetworkAttachmentAuthorization/v1`; the payload is
`catchplate.nativeNetworkAttachmentAuthorization/v1`, purpose
`native-network-attachment`, trust mode `trusted-host-local`. Ed25519 signs the
payload schema's ASCII bytes, NUL and the exact sorted compact `ensure_ascii`
JSON payload (including escaped DEL), with no LF. The entire original is bounded
to 32 KiB and nesting depth six; signatures use canonical `ed25519:` plus
unpadded base64url raw64. Public/private key originals are bounded to 16 KiB;
only the producer accepts an explicit canonical PKCS8 private original. The
native public-root reader also refuses weak keys.

The exact thirty payload fields bind source revision and authorization identity;
sixteen nonzero SHA-256 commitments to the egress grant, launch manifest,
setup/delegation/request/requirements, runtime release/policy/configuration,
runtime CA DER/SPKI and ingress leaf DER, client roots/challenge, target SPKI and
machine ID; exact target principal/nonce; launcher-host network owner; bridge;
attachment plan; independent capability/token hash and journal; and original
issue/expiry times. Target principal preserves the existing request-first
1024-byte UTF-8 profile, not an invented ASCII narrowing. The current positive
i64-nanosecond interval is at most 300 seconds and contained in capability
expiry. Native admission additionally intersects the genuine parent lifetimes;
it never refreshes the original processing allowance.

The actual orchestrator must independently re-admit the exact egress **v3**
original, whose signed `childNetworkPolicy` is
`manual-dual-stack-no-autoconfiguration-v1`. That policy is creation-claimed
before clone and permits the fixed child-only network configuration controls;
older egress profiles do not gain that authority. Setup, delegation, request,
manifest, runtime, caller/challenge and host associations must equal genuinely
retained originals. Future child namespace/PID values are not guessed into the
pre-contact grant: the actual created child, fresh proof and exact RTNL plan join
the irreversible operation association afterward.

## Preprovisioned gateway bridge

The bridge is exactly `{name,ifindex,macAddress,mtu,kind,lock}`, with `kind` equal
to `bridge`. The signed lock is exactly `{path,device,inode}`: a separately
preprovisioned root:root `0600`, empty, single-link regular file. Its actual
held/named identity and nonblocking exclusive lock must survive all effect and
readback phases. It is not the attachment journal directory. Neither the bridge
nor lock is created or repaired by the attachment backend.

This first profile is an explicit **gateway-bridge topology**. Every signed
gateway IP must already be present on that actual bridge. Every child IP must
already have a permanent host bridge neighbor mapping to the signed child MAC.
Every route's `gatewayMacAddress` equals the actual signed bridge MAC. The
backend observes those host prerequisites; it never installs host addresses,
neighbors, routes, DNS or NAT. Missing prerequisites refuse rather than adding a
fallback or weakening the egress firewall to allow discovery traffic.

## Fixed attachment plan

The attachment object has exactly `profile`, `hostVethName`, `childVethName`,
`mtu`, `hostMacAddress`, `childMacAddress`, `addresses` and `routes`. Profile is
`rtnetlink-veth-bridge-static-v1`. Bridge/host/child names are distinct bounded
ASCII interface names (1–15 bytes); their canonical lowercase MACs are nonzero,
unicast and distinct. MTU is 1280–65535 and cannot exceed the bridge MTU.

Addresses are one per used family (at most two), exactly
`{family,address,prefixLength}` with `/32` IPv4 or `/128` IPv6. Routes are at most
sixteen exact `{family,destination,gateway,gatewayMacAddress}` objects, ordered
IPv4 before IPv6 by packed destination bytes. Their destinations must exactly
match the genuine egress rules' proxy addresses, in that same order; no default,
DNS or CIDR-expanded remote route is allowed. All routes have a selected
same-family child source; child addresses cannot equal a destination or gateway.
IPv4-mapped and zone-suffixed IPv6 spellings are refused in this plan.

The fixed backend exclusively creates the new veth pair with the signed
names/MACs/MTU, disables automatic address generation, attaches only its new host
end to the pinned bridge, and installs permanent manual child addresses with
`NOPREFIXROUTE` and IPv6 `NODAD`. It installs permanent child gateway neighbors
and static MAIN-table UNICAST host routes, metric 1024, explicit `ONLINK` and the
selected preferred source, then brings **both** new links UP. It does not replace
existing names or accept arbitrary netlink commands. Typed readback must account
for only exact profile-derived local/multicast state, not tolerate arbitrary
extra remote routes. Address/link configuration alone does not prove connectivity.

A separate attachment root, protected token, capability and journal are required.
The actual owner enforces separation from egress creation/kernel and CA purposes.
The attachment claim must be durable before its first effect, with exact plan
and bounded original transcript custody. An unknown or partial outcome gives no
retry, deletion, repair, rollback or workload-start authority. Actual owners and
the original clock must remain live through final observation.

Python `_verify_on_work` and `_produce_on_work` use raw originals plus inherited
work/window/deadline/current inputs; neither accesses files or networks or mints
an allowance. Rust `attachment_authority::admit` accepts original grant/public
root/pin, independently expected source revision and the existing `OriginalClock`.
Its typed result has no serialization, cloning or successful-DTO constructor.
Separate canonical shape/schema checks do not authenticate kernel state.

The [Linux v6.12 rtnetlink UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rtnetlink.h),
[address UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_addr.h),
[link UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_link.h)
and [neighbor UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/neighbour.h)
identify the fixed protocol vocabulary, not evidence that these sources have
run successfully. No build, test, runtime, host provisioning, application start,
connectivity, Kubernetes or production-acceptance result is claimed.
