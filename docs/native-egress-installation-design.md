# Native egress installation design

This is the agreed architecture for a separately authorized native host egress
installer. The `.251` [grant, stopped-workload and journal foundation](native-egress-installation.md)
now joins the `.252` [kernel transaction/readback pipeline](native-egress-kernel.md)
and `.254` [durable precreation admission](native-egress-creation.md) through the
[public v3 client](native-egress-client.md). Exec/start, network attachment,
persistent supervision and combined CA-plus-egress orchestration remain open.
Source integration is not
a successful firewall transaction or runtime evidence. Existing native
enrollment, CA installation and legacy firewall profiles remain unchanged.
No commands in this document authorize deployment or a canary.

## Existing inputs and their limits

The genuine [bootstrap setup](native-enrollment-bootstrap-setup.md) verifier's
`proxy` scope binds the delegated endpoint and origin, 1–16 sorted explicit
`hostAddresses`, and 1–32 sorted canonical, non-universal `egressCidrs`. Every
address must lie inside a signed CIDR and the delegated endpoint address must be
included. These facts bound destinations; neither the CIDRs nor the setup's
`networkOwner` or optional Kubernetes selectors grant firewall ownership.

The [.246 host owner](native-install-host-owner.md) retains actual machine/boot
originals, current PID/TID, and the held current-thread network namespace's
device/inode, nsfs type and root ownership. The concrete CA `InstallGuard` also
retains original inputs, private material, the genuine native proof, connection
and nonrenewing clock. This is a reuse seam, not an egress permission: observed
namespace ownership does not establish exclusive membership, launcher control,
Kubernetes ownership or isolation against a privileged host.

The existing [CA reservation](native-install-reservation.md) supplies the useful
reserve → durable claim → effect/readback → complete pattern. Its purpose,
domains, token and journal records are CA-specific. The legacy
`serverware/enrollment.py::_nftables_firewall` emits a create-only table script,
but its environment-supplied namespace comparison and table/chain/comment
readback are not the native ownership or exact rule-expression checks required
here. Do not execute that script as the new installer or reinterpret its receipt.

## Separate authority and retained ownership

The `.251` closed, versioned **egress-installation grant** has a dedicated,
explicitly pinned public root and purpose-specific original verification. This
source foundation alone is not a public effect entrypoint; the v3 client requires
the additive v2 grant and separate precreation claim. Its scope and actual
operation-side joins preserve these distinctions:

- The precontact grant pins setup, delegation and target-request associations,
  target principal/key/nonce, and expected policy/configuration/runtime scope.
  It cannot contain hashes of fresh evidence or packet originals not yet
  acquired. Those exact fresh originals must be admitted and bound into the
  operation-side association. Re-admit originals under independent roots; a
  packet, capture, CA receipt or successful preflight JSON is not proof.
- Host label mapped to exact machine-id original hash, boot ID, network namespace
  device/inode/owner, and an independently authorized **controlled workload**
  association. The latter needs an actual retained launcher/process-lifecycle
  owner: the target workload must be stopped or not yet started, its namespace
  membership fixed, and unrelated workloads excluded throughout the effect.
  Signed setup `networkOwner` refers to the launcher-host namespace. The grant
  separately authorizes creation of one never-started `NEWNET` child before the
  journal firewall claim; its new namespace identity is retained operation-side,
  not predicted or substituted for the signed host namespace.
  Signed labels, PID text, environment variables and a one-time process list
  cannot substitute for that owner. Kubernetes requires its own actual cluster,
  namespace and workload ownership contract; this host profile does not supply it.
- Exact backend/profile, namespace-local table identity, chain type/hook/priority,
  default drop policy and the complete ordered allow-rule set. The initial profile
  is create-only; it contains no replacement, deletion or broad command permission.
- A distinct protected reservation namespace/slot, exact journal path/device/inode
  and capability association, including the original protected token hash if the
  profile uses a token. An installation token or reservation is not reusable as
  an egress token. Only hashes/public associations may appear in public output.
- A short current validity interval contained in the genuine parent authorities,
  with all work clipped to the same original processing deadline. Effects and
  output must keep the actual host, workload, proof, connection and input owners
  live; checks cannot manufacture a new allowance.

The independent authority must explicitly permit the namespace-wide deny effect,
not merely connectivity to an endpoint. The `.251` stopped-child owner provides
no target start API and tears down only its child through retained pidfd ownership
on failure/parent death. Creation is separately grant-authorized; the later
durable claim must precede firewall mutation. Full start/lifecycle permission
still requires a future contract, not today's `HostOwner` or CA `InstallGuard`.

The exact five-field [pre-exec launch manifest](../schemas/native-egress-launch-manifest.v1.schema.json)
is `apiVersion: serverware.nativeEgressLaunchManifest/v1`,
`profile: native-egress-create-new-workload-v1`, `executable: {path, sha256}`,
`argv: [executable.path]`, and `environment: {}`. Its exact sorted compact
`ensure_ascii` original has no newline and is bounded to 4 KiB; the native owner
admits the actual executable original up to
16 MiB. This pins a selected artifact, **not** full execution configuration or
permission to execute it. Additional arguments, environment, working directory,
UID/GID or capabilities need an explicit new profile; none may be inferred from
the manifest or inherited silently as target authority.

## Exact rules, one transaction, actual readback

Construct rules only from the genuine setup's explicit `hostAddresses`, each at
the delegated endpoint's port and **TCP only**. The grant must authorize exactly
that set. CIDRs remain membership constraints, never expanded allow rules. Keep
the delegated endpoint and the actual held proxy peer consistent with this set.
No DNS lookup, incoming-client CIDR, upstream route CIDR or inferred canary may
add a destination. Address-family handling must preserve the admitted original's
meaning, including explicitly supported mapped-address forms.

The fixed first backend is a dedicated nftables `inet` table containing only an
`output` filter base chain at the explicitly signed priority (initially `-10`),
default policy `drop`, and exact address/family + TCP destination-port accept
rules. There are no implicit established/related, loopback, DNS, UDP, ICMP or
control-plane exceptions. If a deployment needs additional control traffic,
stop for a separately reviewed profile; do not widen the set to make it work.

Before any accept, the fixed backend must exclude every IPv4 packet with MF or
a nonzero fragment offset (DF is permitted), and every IPv6 packet containing a
Fragment header, including atomic fragments. Ordinary non-fragment IPv6
extension-header resolution remains supported through `meta L4PROTO`; this is
not permission for arbitrary encapsulated protocols. These are explicit rule
constraints, not reliance on implicit payload-evaluator fragment handling. The
source basis is Linux v6.12's [IPv4 packet initialization](https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables_ipv4.h#L6-L15),
[IPv6 extension walker](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/exthdrs_core.c#L179-L267)
and [payload evaluation paths](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_core.c#L136-L165).
This deliberately excludes otherwise legitimate pre-fragmented traffic. An
output-hook check is not a guarantee against fragmentation after that hook;
neither this design nor the source inspection is runtime evidence.

Other hooks and networking configuration are outside this transaction, so this
does not itself establish end-to-end connectivity or protection against host
administrators changing routing, NAT or rules.

The private effect owner uses a bounded typed kernel transaction, not
caller-supplied nft text or a generic shell/command runner. Retain the observed
namespace and open the backend socket there; do not accept a caller namespace
path or switch to an unverified namespace. Acquire the protected journal lock
before a fixed namespace/backend lock, both nonblocking. Hold them and the
controlled workload owner through claim, effect, readback and completion.

1. Verify authority and retained owners; bound all input, transaction and readback
   sizes. Require a stable GETGEN-bracketed empty snapshot across all six
   unfiltered table/chain/rule/set/object/flowtable dumps, then reserve the exact
   encoded intent. A precheck alone is not enough: the single atomic batch also
   uses exclusive creation and a generation pin.
2. Persist and fsync the irreversible purpose-bound claim **before any ruleset
   mutation**. The stable slot must not change when operation inputs change;
   changed scope under an existing slot conflicts rather than allocating a retry.
3. Submit exactly one atomic create transaction. Never flush or replace an existing
   table, modify another owner's rules, or retry after submission uncertainty.
4. Read actual kernel state from the same held namespace. Require the exact table,
   chain family/type/hook/priority/policy and full ordered rule expressions,
   addresses, protocols, ports, fragment exclusions and verdicts; reject extra
   chains, sets or rules.
   Names, comments, handles, an ACK or a matching supplied digest are insufficient.
   Kernel-generated identifiers must be separated from semantic comparison.
5. Retain the actual bounded raw transcript, verify exact semantics, recheck all
   owners and original bounds, then consume the journal into completion. The
   private `Installed` owner retains the guard, backend and both locks for
   read-only recheck. It supplies no start API. Rule installation is not provider,
   CONNECT, canary or application authorization.

## Uncertainty and recovery

A missing reply, interrupted transaction, expired guard or failed readback leaves
the claim consumed. Preserve the journal, exact intended transaction and bounded
observed state; do not reset the claim, resubmit, delete a deny policy or perform
automatic rollback. An atomic kernel batch avoids intermediate rule sets, not the
uncertainty between kernel commit and durable local completion.

The `.252` kernel journal uses distinct `SWNEGRS2` raw-intent/observed/completion
records and a preprovisioned protected `backend.lock`; the `.251` SWNEGRS1
hash-only journal is neither relabeled nor accepted as raw custody. The bounded
`SWNEGBE1` transcript includes actual requests, attempted submission and received
replies. Failure observation still requires the live guard and is best effort;
expiry, process death or storage failure may prevent persistence. Missing bytes
never authorize retry or weaken the consumed-uncertainty rule.

An exact completed slot permits **read-only** confirmation of the actual current
rules and owners, never reinstallation. Missing or altered kernel state, a new boot
or namespace, or an incomplete claim requires independently authorized recovery.
The workload stays stopped; signed expiry does not silently remove installed rules.
Cooperative locks cannot defeat unrelated privileged writers, and local fsync is
not an off-host rollback witness. Restart, retention, revocation, teardown and
cross-session recovery require explicit lifecycle contracts.

## Implementation sequence and open acceptance

The `.252` source connects the original grant/workload/guard foundation to typed
exclusive kernel submission, exact raw custody, full semantic readback, guarded
completion and read-only completed replay. The `.254` public v3 client now joins
a separately signed creation-journal identity, irreversible durable claim before
the one clone attempt, retained genuine owners and an explicit no-action capture
with an SDK receiver. Historical or uncertain claims never permit recreation or
PID reattachment. Independent provisioning, separately authorized exec/start,
network attachment and persistent supervision are not supplied. Local creation
admission is not a global rollback-resistant claim. Keep CA installation
and old enrollment profiles strict; no data projection becomes authority.

The kernel pipeline has not been built or executed. Privileged-writer exclusion,
lifecycle/recovery and deployment compatibility require independent acceptance.
Later authorized
acceptance must separately establish deny/allow behavior, no direct bypass, real
CONNECT/provider policy, canaries, interruption and recovery, and Kubernetes
ownership where applicable. No test, build, runtime/network change, AWS/spend,
production gate or N04/N05 completion is claimed here.
