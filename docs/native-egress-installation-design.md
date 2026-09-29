# Native egress installation design

This is the agreed architecture for a future, separately authorized native host
egress installer. It is not an implemented wire profile, installer, successful
firewall transaction or completion credit. Existing native enrollment, CA
installation and legacy firewall profiles remain unchanged. No commands in this
document authorize deployment or a canary.

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

A new closed, versioned **egress-installation grant** must be independently signed
under a dedicated, explicitly pinned public root. Its schema, byte bounds and
canonical signature domain must be frozen with paired producer/verifier code;
this design does not introduce a callable schema. The grant must bind:

- Exact setup, delegation and target-request original hashes, target principal
  and key/nonce association, policy/configuration/runtime scope and the genuine
  native proof used by the operation. Re-admit originals under independent
  roots; a packet, capture, CA receipt or successful preflight JSON is not proof.
- Host label mapped to exact machine-id original hash, boot ID, network namespace
  device/inode/owner, and an independently authorized **controlled workload**
  association. The latter needs an actual retained launcher/process-lifecycle
  owner: the target workload must be stopped or not yet started, its namespace
  membership fixed, and unrelated workloads excluded throughout the effect.
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
not merely connectivity to an endpoint. The launcher must prevent workload start
until verified completion and must remain able to keep it stopped on failure.
This lifecycle contract is required implementation, not a property of today's
`HostOwner` or `InstallGuard`.

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
Other hooks and networking configuration are outside this transaction, so this
does not itself establish end-to-end connectivity or protection against host
administrators changing routing, NAT or rules.

The future private effect owner must use a bounded typed kernel transaction, not
caller-supplied nft text or a generic shell/command runner. Retain the observed
namespace and open the backend socket there; do not accept a caller namespace
path or switch to an unverified namespace. Acquire the protected journal lock
before a fixed namespace/backend lock, both nonblocking. Hold them and the
controlled workload owner through claim, effect, readback and completion.

1. Verify authority and retained owners; bound all input, transaction and readback
   sizes; require the dedicated table to be absent. A precheck alone is not enough:
   kernel creation must also be exclusive within the single atomic batch.
2. Persist and fsync the irreversible purpose-bound claim **before any ruleset
   mutation**. The stable slot must not change when operation inputs change;
   changed scope under an existing slot conflicts rather than allocating a retry.
3. Submit exactly one atomic create transaction. Never flush or replace an existing
   table, modify another owner's rules, or retry after submission uncertainty.
4. Read actual kernel state from the same held namespace. Require the exact table,
   chain family/type/hook/priority/policy and full ordered rule expressions,
   addresses, protocols, ports and verdicts; reject extra chains, sets or rules.
   Names, comments, handles, an ACK or a matching supplied digest are insufficient.
   Kernel-generated identifiers must be separated from semantic comparison.
5. Recheck all owners and original bounds, then durably publish completion and a
   bounded local diagnostic. Only then may the independently controlled launcher
   consider its separate start decision. Rule installation is not provider,
   CONNECT, canary or application authorization.

## Uncertainty and recovery

A missing reply, interrupted transaction, expired guard or failed readback leaves
the claim consumed. Preserve the journal, exact intended transaction and bounded
observed state; do not reset the claim, resubmit, delete a deny policy or perform
automatic rollback. An atomic kernel batch avoids intermediate rule sets, not the
uncertainty between kernel commit and durable local completion.

An exact completed slot permits **read-only** confirmation of the actual current
rules and owners, never reinstallation. Missing or altered kernel state, a new boot
or namespace, or an incomplete claim requires independently authorized recovery.
The workload stays stopped; signed expiry does not silently remove installed rules.
Cooperative locks cannot defeat unrelated privileged writers, and local fsync is
not an off-host rollback witness. Restart, retention, revocation, teardown and
cross-session recovery require explicit lifecycle contracts.

## Implementation sequence and open acceptance

Implement separate bounded components in this order: (1) original grant
producer/verifier and independent-root provisioning; (2) actual controlled
workload/launcher ownership beside the existing host owner; (3) purpose-specific
protected claim owner; (4) fixed typed transaction and full kernel readback owner;
(5) guarded orchestration and read-only completed recovery. Keep CA installation
and old enrollment profiles strict; do not turn a shared data projection into an
authority object.

None of those new egress components is implemented by this document. Exact wire,
backend dependency/capacity choices, privileged-writer exclusion and deployment
compatibility still need source integration and independent review. Later
authorized acceptance must separately establish deny/allow behavior, no direct
bypass, real CONNECT/provider policy, canaries, interruption and recovery, and
Kubernetes ownership where applicable. No test, build, runtime/network change,
AWS/spend, production gate or N04/N05 completion is claimed here.
