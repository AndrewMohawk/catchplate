# Native execution filesystem and entry admission

This source adds a closed manifest and a retained admission mechanism, not a
workload start path. No build, test, image provisioning, mount operation or
execution was run. It neither changes the static custody launcher's ELF
allowance nor converts an existing never-executed egress child into a runnable
child.

## Closed original and authority boundary

`serverware.nativeExecutionManifest/v1`, profile `native-elf-erofs-v1`, has
exactly eight fields: `apiVersion`, `profile`, `rootfs`, `entry`, `argv`,
`environment`, `cwd`, and `loaderPolicy`. The original is canonical ASCII JSON
without a trailing LF, at most 32 KiB, selected by an independent SHA-256 pin.
Duplicate/unknown fields, omitted required fields, alternate encodings and
zero digest pins refuse. [Manifest schema](../schemas/native-execution-manifest.v1.schema.json)

The manifest is input data, not permission. A separate source-owned start
authority must authenticate the exact original, associate it with the genuine
creation/egress/attachment and workload owners, and retain the same admission
object. Neither the schema, a digest comparison, a serialized observation nor
a returned successful-admission object grants start authority. This module
exposes no raw descriptors, execution callback, shell command or exec method.

`execution::filesystem::PreparedFilesystem::open(&ArtifactV1,
Arc<OriginalClock>)` returns a non-Clone private-field owner. `check(&self)`
revalidates the actual originals and has sticky failure. `manifest_sha256()`
is a data-only projection for the real authority owner's exact association;
it is not a capability. The caller keeps the same original clock: no new
30-second window, continuation allowance or successful-IO-based renewal is
created. Blocking syscalls still require an independent watchdog; the clock
checks do not claim to preempt them.

## Complete supported image, not arbitrary EROFS

The exact rootfs fields are `profile`, `mountPath`, `blockDevicePath`,
`imagePath`, `imageFsVeritySha256`, `loopOffset`, and `loopSizeLimit`.
`single-device-erofs-loop-fsverity-v1` requires offset and size limit zero.
The source owner retains all actual path ancestors, root, block and image FDs;
the manifest also retains its original bytes and independently pinned file.
Host paths are bounded, protected root-owned originals opened one component
at a time without following symlinks. The selected block node must also be
root:root and not group/world writable; a default group-writable loop node
requires appropriate independent provisioning rather than a silent exception.

The shared [EROFS association mechanism](native-erofs-rootfs-mechanism.md)
observes the actual read-only mount, block device, fs-verity measurement and
loop mapping. That observation alone does **not** close all possible EROFS
deployments. This new owner additionally reads the measured image's actual
superblock and admits only 4 KiB blocks whose total equals the complete image
length, at most 64 GiB. Compatibility and incompatibility feature masks are
each limited to the low two baseline bits; extension slots, extra devices,
device-table location and later/reserved superblock fields must be zero.
Thus device-table/chunk forms, external blobs, head2 compression, fragments,
dedupe, tailpacking, extended xattr prefixes and unknown future forms refuse.
The narrow profile can contain ordinary static or dynamically linked ELF;
it is a filesystem-format restriction, not a static-program substitution.
The pinned kernel format and device-opening paths explain why extra-device
closure must be checked separately. [Linux v6.12 EROFS format](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/erofs/erofs_fs.h),
[Linux v6.12 device association](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/erofs/super.c)

The owner creates only a nonrecursive detached clone of the actual admitted
root directory, with read-only, nosuid, nodev and private-propagation attributes.
It never attaches it to the host or clears an existing noexec flag. An overlay
root fails the actual EROFS check, and submounts underneath the supplied root
are not copied. The detached root, entry, loader and cwd descriptors are held
and rechecked. This is a trusted-host-local ownership mechanism, not exclusion
of hostile privileged host/kernel changes. [Linux detached-mount semantics](https://man7.org/linux/man-pages/man2/open_tree.2.html)

## Static and dynamic entries

`entry` is exactly `{path, sha256, interpreter}`. A static entry has explicit
`interpreter: null`, no `PT_INTERP` and no `DT_NEEDED`. A dynamic entry has one
`PT_INTERP`, exactly equal to the separately pinned `{path, sha256}` interpreter
original. Both actual FDs must refer to root-owned, non-setid, non-group/world-
writable executable files within the same retained mount, without file
capabilities. The entry and loader are each at most 16 MiB. The new bounded
ELF64 little-endian parser supports host x86_64/aarch64 ET_EXEC and ET_DYN,
bounded segment/dynamic tables, an executable entry, nonoverlapping loads and
a declared non-executable stack. The loader is itself architecture-compatible
and self-contained, with no nested interpreter or `DT_NEEDED`.

Dynamic `DT_NEEDED` entries are permitted for the main program. Libraries,
loader cache/configuration, scripts and language modules are authenticated by
the entire immutable image, not inferred from the entry digest. This admission
does not run the loader or claim that all dependencies will successfully load.
Direct script entries are unsupported: select the actual in-image interpreter
ELF and include the script's in-image path in the exact signed argv instead.

All entry/loader/cwd opens use `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS |
RESOLVE_NO_XDEV`. Ordinary relative or absolute image symlinks therefore work,
without traversing ambient mounts or magic links. At an eventual exec, Linux
opens the `PT_INTERP` pathname; retaining its FD alone cannot redirect that
lookup. The future start owner must first install this exact closed root in
the new child's private mount namespace and verify the path/FD association
there. It must not manually invoke a different loader or fall back to host
libraries. [openat2 resolution](https://man7.org/linux/man-pages/man2/openat2.2.html),
[Linux v6.12 ELF interpreter lookup](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/binfmt_elf.c)

`argv` has 1–64 elements and starts with the exact entry path. The complete
explicit environment has at most 64 conventional identifier keys; no values
are inherited. Each argument/value is at most 4096 UTF-8 bytes and excludes
NUL; combined argv/environment, including terminators and equals separators,
is at most 16 KiB. `loaderPolicy` is `in-image-system-loader-v1`, excluding
`LD_*` and `GLIBC_TUNABLES` overrides. `cwd` is an explicitly retained directory
inside the same image. No PATH lookup, shell expansion or ambient cwd is used
by admission.

## Required next caller, not current execution closure

A future actual `StartOwner` must admit a distinct signed start grant before
using the manifest and retain this exact owner alongside the genuine original
proof, clock, egress/attachment owners and separately admitted cgroup/guardian
ownership. Its new child-creation branch must receive the filesystem owner
before clone and consume independent durable creation and start permissions.
The existing never-exec trampoline closes executable/stdio FDs, stops and exits
on continuation; its profile is unchanged and cannot be relabelled as runnable.

Before successful exec can be claimed, the new child branch still needs exact
root installation, removal of old roots/submounts and escaping inherited FDs,
explicit stdio/UID/GID/capability/signal policy, namespace/mount restrictions,
a private consuming start gate and positive exec acknowledgement. Whole-tree
supervision and confirmed termination need the separate cgroup/guardian owner.
No extra mounts, writable library locations or host descriptor escapes are
authorized here. Any broader writable-runtime filesystem profile requires its
own explicit admission; longer execution requires separately signed absolute
continuation authority. There is no public execution configuration, workload
start, connectivity, runtime compatibility or pilot result from this module.
