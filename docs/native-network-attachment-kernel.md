# Native attachment: fixed RTNL effects and original custody

This is the source contract behind the [v4 client](native-network-attachment-client.md),
not a runtime acceptance report. The separately signed
[attachment authority](native-network-attachment-authorization.md) is joined to
the genuine retained bootstrap, host, stopped-child and installed-firewall owners.
Public observations, JSON diagnostics, descriptor numbers and copied hashes are
not constructors for those owners. No application is executed by this path.

## Locks and irreversible local journal

`attachment::execute` opens the dedicated signed attachment journal before the
separately signed bridge lock. The journal is a preprovisioned root:root 0700
directory with pinned path/device/inode. Its nonblocking exclusive directory lock
precedes the bridge's nonblocking exclusive file lock. That bridge file must be
preprovisioned root:root 0600, empty, single-link and match its signed path/device/
inode; it is not a record inside the closed journal. Protected ancestor and leaf
descriptors remain held, with no-follow opening and named/held identity checks.
These locks are cooperative local serialization, not protection from hostile root
or proof against filesystem rollback.

The slot is SHA-256 over `catchplate/native-network-attachment-slot/v1` plus NUL,
then each signed journal namespace and capability ID framed with its big-endian
u32 byte length. A fresh child, proof, operation or token does not create a fresh
slot. The separate operation association binds actual retained owners and exact
originals; raw token bytes are never journaled or output.

`SWNATRS1` is purpose-separated from creation and nft journals. Every record starts
with a 137-byte prefix: eight-byte magic, one-byte stage, then four raw 32-byte
hashes in order: slot, operation association, token and exact intended plan.
Only `<slot-hex>.reserve`, `.claim`, `.observed` and `.complete` records are allowed.
The inventory is bounded at 64 slots and 256 records, with exact predecessor masks
1, 3, 7 or 15. Lengths below are big-endian u32; variable originals are nonempty.

| Stage | Suffix bytes after the common prefix | Original bound |
| --- | --- | --- |
| 1: reserve | plan length, exact plan | 64 KiB |
| 2: claim | none | prefix only |
| 3: observed | transcript SHA-256, transcript length, exact transcript | 1 MiB |
| 4: complete | transcript SHA-256, semantic SHA-256, semantic length, exact semantic original | 64 KiB |

Publication uses exclusive creation, exact protected mode/single-link checks,
bounded writes, file fsync, directory fsync and exact held/named readback. Plan,
transcript and semantic lengths/hashes must match their actual originals. The
claim is durably published before the first mutation attempt. An existing
incomplete slot is consumed; no deletion, rewrite, repair or automatic retry is
provided. Private completed-original access requires the same association and
exact plan, but the public continuation refuses `Completed` rather than repeating
attachment or reporting a fresh action.

## Preclaimed typed plan and socket custody

The backend obtains only source-owned namespace/socket aliases from the actual
stopped-child owner. It creates the host route socket in the retained launcher
namespace and uses the child route socket created inside the new child namespace.
It never switches namespaces or accepts caller-supplied descriptors. Currentness
checks retain exact file identities, `NETLINK_ROUTE` type, actual local port IDs,
nonblocking/close-on-exec flags and socket namespace membership through
`SIOCGSKNS`, nsfs identity and namespace-type checks. The same original deadline
and real guard bracket IO; checking ownership opens no fresh IO allowance.

Read-only preflight chooses unused host/child ifindices. The private
`AttachmentPlan` then retains `SWNATPL1`: authority digest, actual namespace
identities, selected ifindices and every ordered side-tagged request original.
Its entire original is at most 64 KiB, with at most 64 operations and 16 KiB per
request. Actual port IDs and nonreused per-socket sequences are fixed before the
journal reserve/claim; no mutation template is completed after claiming.

The only mutation recipe is:

1. Exclusively create the exact veth pair, moving its child peer to the held new
   namespace, with signed names/MACs/MTU and the preselected unused ifindices.
2. Set IPv6 address generation to NONE on both new links; attach only the new
   host link to the pinned bridge.
3. Add exact child /32 and /128 permanent addresses with `NOPREFIXROUTE`, plus
   `NODAD` for IPv6; add deduplicated permanent child gateway neighbors.
4. Bring both new links UP, then add only the signed proxy-destination host
   routes: MAIN table, static/unicast, metric 1024, ONLINK and exact same-family
   preferred source.

The bridge's gateway addresses and permanent host bridge neighbors mapping each
child IP to its signed MAC must already exist. The signed gateway MAC equals the
actual bridge MAC. This explicit return-neighbor topology supports the fixed
profile without adding nft ICMP allowances. No host address/neighbor/route writes,
NAT, DNS, default routes, arbitrary RTNL input, replacement or deletion are exposed.

## ACKs, transcript and semantic readback

Each request is attempted once. Mutation acceptance requires one exact zero-error
`NLMSG_ERROR` ACK, its capped-ACK framing, actual sequence/port and byte-for-byte
echoed request header. Datagram reception requires kernel source port zero,
unicast provenance and no data/control truncation. Lost data, extra replies,
unexpected flags, interrupted dumps or nonzero errors refuse the operation;
there is no resend or optimistic success.

The typed `SWNATBE1` transcript is at most 1 MiB: magic, big-endian u32 event count,
then tag byte, side byte, big-endian u32 length and exact raw original. Tags 1 and
2 record read-request and mutation attempts **before** their sole send; tag 3
records a complete received datagram before semantic parsing. Limits are 512
events, 64 KiB per raw datagram and 256 parsed received messages. Attempt records
do not assert delivery, and raw replies do not themselves assert semantic success.

Each snapshot contains fourteen actual dump exchanges: host links, IPv4/IPv6
addresses and neighbors; the same child inventory plus IPv4/IPv6 routes; then
closing host and child link dumps. A private `Snapshot` binds the actual owner,
plan digest and exact transcript digest. The independent typed readback consumes
these originals, not a supplied successful result. It compares the signed bridge,
managed links, manual addresses, permanent neighbors and exact proxy host routes,
normalizing only the specified kernel metadata and derived local/IPv6 multicast
routes. Host dump scope is not a claim that unrelated host interfaces or routes
are absent. Closing link checks do not make separate RTNL dumps an atomic global
snapshot or prevent noncooperating privileged changes afterward.

The existing nft ruleset and TCP destination/port allowance are unchanged,
including the IPv4-fragment and IPv6-Fragment-header exclusions. Genuine nft
readback is required before attachment mutations and again after attachment
readback. Only then can the journal accept the source-owned semantic original
and complete its exact plan/transcript association. Completion is local original
custody, not application connectivity, provider authorization or a canary result.

The fixed Linux v6.12 normalization references are
[link and RTNL output](https://github.com/torvalds/linux/blob/v6.12/net/core/rtnetlink.c),
[bridge attributes](https://github.com/torvalds/linux/blob/v6.12/net/bridge/br_netlink.c),
[IPv4 addresses](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/devinet.c),
[IPv6 addresses and multicast routes](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/addrconf.c),
[neighbors](https://github.com/torvalds/linux/blob/v6.12/net/core/neighbour.c),
[IPv4 routes](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_semantics.c)
and [IPv6 routes](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/route.c).
These source references do not certify another kernel's dump profile.

## Failure and lifetime boundary

Mutations are ordered, not an atomic rollback transaction. A late failure can
leave a partially attached pair until owner teardown. The public path attempts
to preserve available typed transcript originals only while its original guard
remains live; it does not promise all bytes survive a crash, expiry or write
failure. A partial or uncertain claim remains consumed even when no completed
observation is emitted. No reverse RTNL transaction or historical-child recovery
is fabricated.

Owners and both locks remain held through bounded v4 capture writes and flush.
The child remains never-executed and is torn down on owner drop; output is an
observation before that teardown, not persistent deployment. The SDK only extracts
the existing exact bootstrap packet and never resumes attachment. Application
exec/start, persistent supervision, hostile-host/off-host rollback guarantees,
Kubernetes ownership and production gates remain separate. This implementation
has not been built, tested, run or provisioned in this source-only slice.
