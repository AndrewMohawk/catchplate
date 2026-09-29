# Same executable-child network ownership

This source path connects the independently admitted egress and attachment grants
to the **actual blocked executable child**. It does not convert the diagnostic
`WorkloadOwner`, adopt an existing PID, or infer permission from a captured
observation. The cold execution parents, start/creation claims, admitted
filesystem, containment leaf, and child remain retained by their existing owners.

The child creates its own `NETLINK_NETFILTER` and `NETLINK_ROUTE` sockets after
entering its new network namespace and applying the signed fixed network policy.
It transfers the originals over its inherited private seqpacket before dropping
privilege, closes its copies, and only later reports readiness. The launcher
requires that ordering, CLOEXEC/nonblocking sockets, exact domain/protocol/port
and metadata, and `SIOCGSKNS` association to the held child namespace. No socket
is obtained by `setns`, from a caller FD, or through a namespace label. No socket
survives into the unprivileged application.

`PreparedNetwork::open(&BlockedChild)` consumes a one-attempt latch on the genuine
child. Its durable operation association binds the actual start and parent
operations, signed grant, child pidfd/PID and namespace, and both observed socket
identities. The in-memory closed owner identity is separate and never serialized
as authority. Installation retains the same parent/TLS/clock originals and uses
the existing fixed nft and RTNL recipes:

1. Hold the protected purpose-specific journal before its backend/bridge lock.
2. Reserve the exact source-produced transaction or attachment plan; persist the
   irreversible fresh claim before mutation.
3. Make the single admitted mutation attempt, retain exact ACK/readback originals,
   and verify complete kernel semantics under the actual owner.
4. Persist observation before semantic completion and retain the resulting owners
   and locks. Existing completed executable slots are not fresh permissions.

The old diagnostic APIs remain wrappers over their own closed owner variant.
They gain no execution continuation. Errors do not authorize retry, replacement,
repair, or rollback; only best-effort original custody remains while admission is
still live. The attachment owner owns the genuine installed firewall, and neither
that firewall nor the prepared owner points back to the attachment owner: there
is no authority-retaining `Arc` cycle.

`NetworkReady` is non-cloneable and non-deserializable. The lifecycle must consume
it and retain it, the prepared owner, and the actual guarded child through terminal
cleanup. `require_child` is pointer-exact; its pre-release checks cannot succeed
for another child. It does not itself send an exec command or detach a tracee.
The separate release owner requires both the real guardian and this permit,
observes the first positive EXEC event, and only then uses `check_running`.

Admission and continuation are distinct. Before release, all operations remain
under the original nonrenewing admission clock. The first `check_running`, at the
positive EXEC stop before detach, makes one final complete nft/RTNL semantic
comparison, additionally clipped to that original admission. Later calls are
query-free checks of the actual child, namespace/socket originals and retained
protected locks under the separately signed absolute stop time. They do not
renew admission or claim a continuously sampled kernel state. Transaction
building, journal claims, mutation, and completion are permanently unavailable in
continuation. The sockets, original namespace identities, protected cooperative
locks and source-created plan remain retained. Query budgets are not reset:
each backend retains its original aggregate
1 MiB transcript, 256 received-message and 512 event bounds, so exhaustion fails
closed rather than granting another monitoring allowance. There is no periodic
dump schedule. The nonroot application has no network administration capability;
independent privileged host mutation remains outside this trusted-launcher claim.

The four exposed semantic/evidence hashes describe the completed installation
originals, not later connectivity or application success. Running comparisons do
not overwrite the completed journal or publish a fresh completion. The retained
network owners remain alive through cleanup, but do not suppress emergency
termination when admission or continuation has ended. Workload-leader reap,
whole-leaf empty observation, and guardian termination/reap remain separate
lifecycle obligations. Host bridge/route/neighbor provisioning and connectivity
are not inferred from an ACK or from the existence of this permit.

This is source-only integration. No build, test, kernel operation, application
launch, network probe, deployment, or pilot acceptance is claimed here.
