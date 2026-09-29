# Native network attachment client v4

The fixed native bootstrap client has an explicit, independently pinned
[`serverware.nativeBootstrapClient/v4`](../schemas/native-bootstrap-client.v4.schema.json)
configuration. It adds a separately authorized typed network attachment to the
[v3 creation/firewall flow](native-egress-client.md). This is source integration,
not an executed pilot, application-start path or production acceptance gate.

The command line remains the fixed `--configuration /absolute/client.json` and
independent `--configuration-sha256 sha256:<pin>` pair. The closed configuration
has the same 18 base fields plus two required nonnull objects: `egress` with
`authority`, `authorityRoot`, `capabilityToken`, `launchManifest`; and `attachment`
with `authority`, `authorityRoot`, `capabilityToken`. Every entry is an existing
pinned artifact description. `installation` is forbidden, even null, and older
client profiles reject `attachment`, even null. There is no implicit upgrade or
combined CA-installation/egress/attachment mode.

The egress authority must be the explicit v3 signed grant with a separate
`creationJournal` and
`childNetworkPolicy: manual-dual-stack-no-autoconfiguration-v1`. Its creation
claim therefore binds the fixed child-only network settings before clone.
The separate [attachment authority](native-network-attachment-authorization.md)
has its own independent root, protected token, capability and journal; it binds
the exact egress grant, launch manifest, setup/delegation/target, runtime and host
scope. It never guesses a future child PID or namespace inode. The actual
never-executed child and fresh proof enter the operation association instead.

Startup is genuinely admitted before protected attachment/egress preparation,
client private-key access and network contact. The client uses one original
nonrenewing clock, one fixed endpoint and the same authenticated TLS connection.
Actual retained bootstrap verification precedes the irreversible creation claim;
the consumed permit remains with the child owner. The existing kernel claim,
exclusive firewall transaction and exact readback precede attachment. A separate
attachment claim records the exact intended operations before their first effect.
Unknown or incomplete outcomes are consumed: no automatic retry, deletion,
reattachment, reconstructed success or new time allowance is supplied.

## Fixed topology and effects

The signed topology is a preprovisioned gateway bridge with pinned name, ifindex,
MAC, MTU and protected cooperative lock. The bridge gateway addresses and
permanent host bridge neighbors for the exact child IP-to-MAC mappings must
already exist; the backend observes them and does not provision them. The signed
gateway MAC is the actual bridge MAC. The lock and purpose-separated journal
must be preprovisioned with their required root ownership and protected modes.

Only an exclusive new veth pair is permitted: exact names, MACs and MTU, with the
new host end attached to that bridge. The fixed child profile suppresses
autoconfiguration. Explicit child IPv4/IPv6 addresses use /32 or /128 with
`NOPREFIXROUTE`; IPv6 also uses `NODAD`. Permanent child gateway neighbors and
proxy-destination-only `ONLINK` routes use the signed same-family source address.
Both new links are brought UP. Readback admits only the exact profile and its
specified kernel-derived local/multicast state; there is no default route,
implicit remote allowance, DNS/NAT configuration, host-address/route/neighbor
mutation, existing-name replacement, arbitrary command or general RTNL program.

These are typed Linux operations, not a claim that traffic reaches a provider.
The existing firewall still excludes IPv4 fragments and IPv6 Fragment headers
before its exact TCP accepts. Static topology and UP links do not prove return
path correctness, service availability, application behavior or a canary result.
The fixed primary interfaces are the Linux v6.12
[link](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_link.h),
[address](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_addr.h),
[route](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rtnetlink.h)
and [neighbor](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/neighbour.h)
UAPI definitions. Linking them is not runtime validation of a host kernel.
The [kernel and journal contract](native-network-attachment-kernel.md) specifies
the exact preclaimed plan, lock ordering, ACK/transcript custody, readback and
partial-outcome limits.

## Public capture and continuation

The [v4 capture](../schemas/native-bootstrap-client-capture.v4.schema.json) has
exactly eleven fields: the nine original bootstrap fields plus `egress` and
`attachment`. Its scope is
`local-fixed-endpoint-bootstrap-and-network-attachment-observation`. The existing
ten-field egress child is unchanged. The new eight-field attachment child has
`apiVersion`, `resultScope`, `okForAction`, `status`, `authorizationSha256`,
`planSha256`, `evidenceSha256`, `semanticSha256`; its only status is
`observed-attached` and its scope is
`local-authorized-network-attachment-observed-before-owner-teardown`.
All three levels retain `okForAction: false`. Each child is at most 8191 compact
UTF-8 bytes; the complete capture is at most 1.5 MiB including its one final LF.

Actual owners remain held through bounded output, then the never-executed child
is torn down. The capture is not persistent deployment, hostile-host/off-host
rollback proof, a live capability or permission to repeat an effect. Keep the
producer exit status: partial output or a parseable capture after failure is not
successful acquisition. An external watchdog remains necessary for blocked
host calls. No application exec/start, persistent supervision, automatic recovery
or Kubernetes setup is provided.

The same exact bootstrap evidence is retained. The
[data-only SDK extractor](native-bootstrap-capture.md) can publish the embedded
packet for the separate native identity submission path without another
bootstrap request. It checks closed representation and exact request association,
not the grant, journal, proof, kernel state or diagnostic success. Parsing this
capture does not renew any signed lifetime or provide an automatic retry.
