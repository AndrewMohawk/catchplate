# Native egress kernel transaction and semantic readback

This `.252` slice connects an internal source-only kernel pipeline. It does not provide a public egress
configuration, CLI, installer invocation or workload-start permission. The
[independent egress grant and retained owners](native-egress-installation.md)
remain required. Kernel submission, an ACK, a parser result or a digest alone
cannot supply missing launch admission, installation authority or runtime proof.

## Fixed transaction scope

The only intended ruleset is the separately authorized, create-only nftables
`inet` table with one `output` filter base chain, priority `-10`, policy `drop`.
Two explicit fragment-drop rules precede the ordered effective-address rules:
IPv4 MF or nonzero offset is excluded, with DF permitted; every IPv6 Fragment
header, including atomic fragments, is excluded. Remaining accepts match the
exact effective IPv4/IPv6 address, resolved TCP protocol and delegated destination
port. There are no implicit loopback, established, DNS, UDP or ICMP exemptions.
Signed CIDRs are membership limits, never expanded destinations.

The profile deliberately refuses legitimate pre-fragmented traffic. Ordinary
non-fragment IPv6 extension resolution uses `meta L4PROTO`; this is not arbitrary
encapsulation authorization or a guarantee against fragmentation after the output
hook. The [design](native-egress-installation-design.md) preserves these limits.
Typed encoding supplies no caller nft text, shell, replacement or delete command.
Exclusive atomic creation does not eliminate uncertain delivery or completion.

## Private claim-to-completion pipeline

`effect.rs` opens the separate kernel journal, then acquires its protected
preprovisioned `backend.lock`. On the actual controlled namespace socket it takes
an empty six-dump snapshot bracketed by GETGEN. `verify_empty_namespace` requires
zero objects in every family, the exact query originals and stable positive
generation. This observation precedes the exact encoded-intent reservation;
exclusive create and the batch generation pin still protect against later races.

Only a durably read-back `Fresh` claim permits one submission. All requested ACKs
must succeed, followed by a new bracketed snapshot. The pipeline retains the
bounded raw `SWNEGBE1` transcript, verifies exact semantics, then consumes the
reservation into completion. `Installed` retains the genuine guard, backend and
both locks after completion, exposing read-only recheck rather than start
authority. Completed replay uses retained intent and current exact readback; it
never resubmits a transaction or repairs missing/changed state.

The distinct `SWNEGRS2` journal in `kernel_reservation.rs` retains raw transaction
bytes in reserve and raw transcript bytes in an observed record; completion binds
both semantic and evidence hashes. It requires the preprovisioned backend lock.
The older `SWNEGRS1` hash-only format remains separate and is not relabeled or
accepted as v2 custody. Failure observation is bounded best effort under the
still-live guard, not a promise to persist every received byte after expiry,
process death or storage failure. An incomplete claim remains consumed.

## Original replies, not echoed request bytes

The private backend retains the actual namespace-bound socket and received
datagrams. It checks kernel sender identity, request sequence/local port,
truncation/errors and the original nonrenewing guard. The parent must retain raw
request, transaction, acknowledgement and readback originals under the separate
durable egress claim; a semantic hash does not replace those bytes. No caller
JSON result, reconstructed namespace or successful diagnostic is accepted instead.

`readback::generation`, `readback::verify_empty_namespace` and `readback::verify` interpret only the backend's
retained `ReplyOriginals`. Their non-serializable result contains a generation
and semantic digest, not permission. The parent brackets parsing and all effects
with its genuine live guard. No parser callback supplies a clock or new allowance.

Readback requires a GETGEN reply, six sequential unfiltered AF_UNSPEC dumps
(table, chain, rule, set, object, flowtable), then another GETGEN reply. Both
generations must be identical and nonzero. All objects must belong to the one
expected `inet` table/chain; other families are not silently hidden by a filter.
Sets, objects and flowtables must be absent. Each multipart dump must end in one
successful terminal DONE; unknown messages, interrupted/filtered dumps, errors,
duplicates or trailing data refuse. The parser repeats the 1 MiB/256-message
bound; shared framing limits each message to 4 KiB and each datagram to 64 KiB,
with at most 64 attributes per container and depth eight. The backend additionally
bounds its whole retained transcript, including requests, submission and event
framing, to 1 MiB and 512 events; received frames remain capped at 256. These are
refusal caps, not a promise that every larger kernel response can be accepted.

The pinned Linux v6.12 dump contract includes generation-low16 header values,
legacy containers without nested flags, ordered rule replies with APPEND and
previous-handle attributes, and kernel handles/use counts. These representations
are interpreted structurally, not compared byte-for-byte with create requests.
Only optional base-chain packet/byte accounting is ignored semantically; a rule
counter expression is not accepted. No unsupported attribute is discarded.
[Kernel dump implementation](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c).

The parser requires the exact table flags, base-chain type/hook/priority/drop
policy, complete ordered expressions/registers/data and fragment exclusions.
It accepts only the fixed meta, payload, compare, bitwise, extension-header and
immediate-verdict expression shapes. Explicit bitwise and extension-operation
fields match the kernel's dumps; unsupported expressions fail closed.
[Bitwise dump](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nft_bitwise.c#L221-L246),
[extension-header dump](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nft_exthdr.c#L616-L642).

The digest domain is `serverware/native-egress-observed-semantics/v1` followed by
NUL. It commits the canonical signed ruleset and the fully matched normalized
ordered expression tree, with lengths and typed fields. Generation, kernel
handles, use counts and packet counters are excluded from this stable semantic
digest, but remain in retained original replies. Names, comments, handles or a
successful ACK alone never establish rule equivalence.

## Remaining authority and recovery boundary

Fresh durable claim must precede any firewall mutation. Completed replay may
compare actual current kernel state only; it cannot reinstall or repair. Partial
submission, changed generation/state, exhausted limits or lost replies remain
consumed uncertainty, without retry, rollback or automatic start. No claim
completion may substitute a supplied digest for the actual readback owner.

Cross-invocation launch admission, public cold configuration/CLI, network
attachment and independently authorized exec/start/lifecycle remain separate
gates from the private pipeline.
One child per retained owner is not a durable global creation claim. Cooperative
locks do not defeat a hostile privileged writer, and local durability is not an
off-host rollback witness. Connectivity, provider/canary behavior, Kubernetes
ownership and production acceptance remain unverified. No build, test, socket
execution, runtime, NSM or AWS/spend evidence is claimed by this source work.
