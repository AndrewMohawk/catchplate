# Native installer host and namespace owner

The private `native_bootstrap_client/install/host.rs` owner observes the actual
local Linux host inputs before an installer effect and rechecks them through the
original operation. It is a **trusted-host-local** check, not hardware identity,
measured custody, hostile-kernel isolation or permission to install by itself.
This is source-only implementation, not deployed or runtime-tested evidence.

The separately admitted installation authority associates its exact `hostId`
with the SHA-256 of the original `/etc/machine-id` bytes. The host owner checks
that pin and the signed setup's `bootId`, `namespaceDevice`, `namespaceInode` and
`ownerUid`. `hostId` is an independently authorized deployment label: it is not
learned from hostname, environment variables or a successful-verification JSON.

## Retained actual observations

`Spec` contains `host_id`, `machine_id_sha256`, `boot_id`,
`namespace_device`, `namespace_inode` and `owner_uid`. The source-owned,
non-Clone `HostOwner::open(&Spec, &OriginalClock)` returns no action verdict or
exportable descriptor. Its `check(&mut self, &OriginalClock)` accepts only the
same original clock object; it cannot start or renew a timeout. The parent
installer guard owns this observation state and calls it before and after
protected effects and final readback.

The owner requires real/effective UID and GID zero and retains the actual PID
and thread ID. Every check requires the same process and thread. Root inside a
user namespace is not thereby proved to be initial-user-namespace or physical
host root; that distinction is outside this local profile's claim.

It opens and retains the filesystem root and each fixed ancestor without
following symlinks. Ancestors must be root-owned, root-group-owned directories
without group/other write permission. Named and held device, inode, mode and
owner must stay equal; proc ancestors must actually be procfs. Reopening `/`
also detects a changed root path. Directory content timestamps are intentionally
not fixed, since unrelated directory entries can change.

The held `/etc/machine-id` must be a root-owned regular single-link original,
without group/other write permission, containing 32 lowercase hexadecimal digits
(not all zero) with an optional single LF. Its exact original bytes, including that LF
when present, are hashed. The kernel `/proc/sys/kernel/random/boot_id` must be the
signed nonzero lowercase UUID followed by exactly one LF. Both originals retain
metadata and bounded bytes and are reread through their held and named file
descriptors. The read bounds are 33 and 37 bytes plus one EOF probe respectively.

The current-thread namespace path is constructed only from actual kernel IDs:
`/proc/<pid>/task/<tid>/ns/net`. The final `net` magic link is the sole permitted
symlink traversal, after no-follow procfs ancestor admission. Its actual link
text must equal `net:[<signed inode>]`, its own held identity must remain unchanged,
and the opened namespace descriptor must be nsfs.
Linux `NS_GET_NSTYPE` must report `CLONE_NEWNET`; unsupported or refused ioctls
fail closed. The held descriptor and a freshly opened current-thread namespace
descriptor must have the exact signed device/inode and unchanged metadata.

Here **`ownerUid` means the observed nsfs inode `st_uid`**, which must equal the
actual privileged effective UID zero. Namespace inode group is also required
to be zero. This does not mean namespace creator identity, owning-user-namespace
creator, arbitrary namespace-management authority, or proof that a container
has escaped isolation. No namespace ID supplied in an environment variable,
pathname, socket hint or JSON verdict substitutes for the actual observation.

## Lifetime and remaining authority

Every filesystem read/open/stat and namespace ioctl is bracketed by checks of
the caller's original clock. Failure permanently stops this host owner. No
fallback path, alternate namespace, descriptor export or automatic retry is
provided. Kernel and filesystem calls still require an external watchdog for
hard cancellation; late-result rejection does not interrupt a blocked syscall.

This owner does not verify installation signatures, create a durable reservation,
claim a capability token, choose a destination, mutate system trust or networking,
or certify an egress canary. Those gates must use their own actual retained
owners and the same nonrenewing operation. Signed host labels, machine-id files,
procfs and nsfs observations are not protection against a hostile privileged
host/kernel; deployment trust and production acceptance remain separate.
