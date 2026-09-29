# Native execution resource retirement

This is source-only support, not a tested pilot or a reusable cleanup receipt.
The explicit cold `serverware.nativeBootstrapClient/v7` profile requires actual
egress, attachment and execution inputs. `installation` is required: null means
execution-only; an object selects the existing separately authorized CA install
and immutable in-image trust path. No output flag selects permission.

V7 requires independently signed
`serverware.nativeWorkloadStartAuthorization/v2` inside its matching signed-v2
envelope. The original payload schema plus NUL plus canonical ASCII payload is
the signature domain. Containment adds exactly
`retirementProfile: remove-empty-owned-leaf-v1`. V1 grants and cold profiles v5/v6
retain their old contracts and do not authorize directory removal. Neither an
empty-leaf observation nor a filesystem path grants that effect.

## Actual ownership and order

1. The actual installed `NetworkReady` privately prepares a non-Clone host-only
   retirement owner before exec. It retains a checked duplicate of the actual
   host NETLINK_ROUTE socket, its actual host namespace, the same acquired bridge
   flock and protected ancestor originals, and the fully verified bridge/veth
   link semantics. It has no child namespace/socket pin and no edge borrowing
   the child. Signed original parents and exact operation/plan associations remain
   held; no caller-supplied FD, digest or verdict constructs it.
2. The existing lifecycle runs the workload, attempts both cleanup actors and
   requires exact workload leader reap, populated-zero, independent guardian
   empty observation/reap, and bounded output EOF. Kill acknowledgement alone is
   insufficient. Emergency termination remains independent of expired admission
   and never becomes conditional on successful retirement.
3. `NetworkReady` drops its actual firewall/RTNL backend copies and child namespace
   pins; `PreparedNetwork` leaves scope. Only exclusive access to the actual
   cleaned child can then close its original NETLINK_NETFILTER/NETLINK_ROUTE
   sockets followed by its five namespace FDs. A sealed local token associates
   that transition with the same operation, namespace and cleanup bound.
4. The independent host owner issues only full RTM_GETLINK dumps. It requires the
   original bridge semantics and absence of both the original host-veth ifindex
   and its signed name, then confirms both in a separate closing dump. A renamed,
   replaced or reused identity refuses success. No RTM_DELLINK, host route,
   neighbor, bridge or firewall mutation is emitted.
5. Under the explicit v2 permission, the actual containment owner rechecks its
   retained parent/leaf/control identities and irreversible claim integrity,
   populated-zero, empty `cgroup.procs`, and zero live/dying descendants. It burns
   a private one-attempt latch before one parent-relative `unlinkat` with
   `AT_REMOVEDIR` of its exact created name. Success additionally requires the
   same held parent/leaf identities and an independent no-follow ENOENT
   observation. No
   recursive deletion, adoption, repair, retry, automatic Drop removal or
   journal reset is available.

Host absence and directory removal are independently evaluated after genuine
cleanup. A failed/late observation produces no successful retirement capture;
already completed effects are not rolled back or retried. A failure before a
fully installed network owner exists still attempts existing emergency cleanup,
but does not manufacture host-absence or directory-retirement evidence.

## Bounds and evidence

All retirement observation/removal uses the originally projected signed absolute
`cleanupBeforeEpochNs` BOOTTIME bound. It does not call `OriginalClock` to renew
admission or require a fresh CA/network permit after exec. Host observation has
fixed aggregate limits of 16 read requests, 256 received messages and 1 MiB of
length-framed request/kernel originals. Namespace teardown is asynchronous, so
bounded read-only polling may observe the original link still present; framing
loss, dump interruption, changed identity, exhausted budget or deadline fails
closed. There is no effect resubmission.

The v7 capture is the closed eleven-field capture with nullable installation and
scope `local-fixed-endpoint-bootstrap-execution-retirement-observation`.
Execution observation v2 preserves the previous eight fields and adds a closed
retirement object recording operation, original cleanup deadline, actual host
absence and exact cgroup-name removal observations. It remains data-only with
null action authorization and `okForAction: false`. Execution is bounded to
24 KiB; the capture reserves 32 KiB for execution plus the optional existing CA
receipt and remains at most 1.5 MiB including LF.

Actual host transcript originals/flock, removed-leaf FD and original claimed
owners remain held through serialization and stdout flush. The capture contains
the transcript digest, not a durable/replayable copy of those raw originals.
Removal reports namespace disappearance, not synchronous reclamation of every
kernel cgroup allocation. It does not require `st_nlink == 0`: kernfs refreshes
directory link counts from its retained node, which is not a removal oracle
([v6.12 `kernfs_refresh_inode`/`kernfs_iop_getattr`][kernfs]). Host CA removal,
durable retirement journaling, journal archival, restart/reuse permission and interruption recovery remain
separate. Trusted-host-local assumptions still exclude an independently
privileged actor concurrently replacing the protected objects.

The kernel destroys veth devices when their network namespace is freed; closing
one owner is not proof that this happened. Linux v6.12 schedules final network
namespace cleanup asynchronously in [`cleanup_net`][net]. Cgroup removal requires
an empty childless group, and destruction can retain dying kernel references;
see the [cgroup-v2 interface][cgroup] and [v6.12 removal implementation][remove].

[net]: https://github.com/torvalds/linux/blob/v6.12/net/core/net_namespace.c
[cgroup]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#organizing-processes-and-threads
[remove]: https://github.com/torvalds/linux/blob/v6.12/kernel/cgroup/cgroup.c
[kernfs]: https://github.com/torvalds/linux/blob/v6.12/fs/kernfs/inode.c
