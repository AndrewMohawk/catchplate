# Read-only EROFS rootfs association mechanism

`catchplate_decision_gate::erofs_loop_v1` extracts the existing static custody
launcher's EROFS/loop/fs-verity checks into a small, read-only mechanism. This is
source integration only: no image was provisioned, mounted, measured or launched,
and no build or test ran.

## Interface and ownership

`verify(root_fd, loop_block_fd, image_fd, &ErofsLoopExpectationV1)` accepts three
`BorrowedFd` values and explicit expected SHA-256 fs-verity digest, loop offset
and loop size limit. It returns a private-field `ErofsLoopObservationV1` with
read-only getters for the actual root/image descriptor metadata, block device,
measured digest and loop mapping. It accepts no successful-verification DTO,
callback, pathname, mount string, process label or serialized observation.

The mechanism does not open or retain descriptors, set up a loop device, enable
fs-verity, mount anything, hash a signed identity, authorize execution or extend a
deadline. The caller must independently authenticate its expectations, retain
all actual descriptors and ownership controls, bracket calls with its original
lifetime checks, and revalidate before their use. An observation is not a durable
capability; it cannot exclude later changes by privileged host code. Unavailable
kernel features and failed observations refuse without fallback or retries.

## Actual observations

The verifier checks the supplied directory with `fstat`/`statx`, including the
mount ID, requires EROFS from `fstatfs`, and requires the actual mount's read-only
flag from `fstatvfs`. The retained root-owned block descriptor must be a nonzero
block device with `BLKROGET == 1`, and its device identity must equal the mounted
filesystem's device identity.

The image descriptor must be nonempty root-owned regular data, not group/world
writable, and at most the existing 64 GiB bound. `FS_IOC_MEASURE_VERITY` must
return SHA-256 and exactly 32 bytes matching the independently supplied pin.
This is the kernel's fs-verity file digest, **not** an ordinary SHA-256 of image
bytes. The Linux documentation describes both the read-time integrity checks
and the need to authenticate this digest independently. [Linux fs-verity](https://docs.kernel.org/6.12/filesystems/fsverity.html#fs-ioc-measure-verity)

`LOOP_GET_STATUS64` must report a read-only loop mapping to the same image device
and inode with the exact expected offset and size limit. The UAPI layouts and
constants remain those used by the previous launcher. Closing observations
repeat the descriptor, mount, block, measurement and mapping joins to refuse
drift during the query; they are not a kernel lock or hostile-root exclusion
proof. [Linux v6.12 loop UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/loop.h)

## Static compatibility and future dynamic ownership

`policy_custody::launcher::VerifiedRootfs` calls the shared mechanism in both its
EROFS constructor and revalidation, while retaining the same three `OwnedFd`
values itself. It still computes and compares the original
`catchplate.policyCustodyRootfs.erofs/v1` identity. Its ordered frames remain:
domain; root device, inode and mount ID; block rdev; image device, inode and
length; measured fs-verity SHA-256; loop offset and size limit. Numeric bytes
retain their original widths and big-endian encoding; each frame retains its
u64 big-endian length prefix. No signature, expectation or identity version is
relabelled. The dm-verity branch is unchanged.

A verified image can later hold an admitted dynamic runtime filesystem,
including an interpreter and shared libraries, instead of attempting to prove
only a single executable file. This extraction supplies only the existing
read-only image/mount association mechanism. A native dynamic owner still needs
its own signed filesystem/launch policy, complete filesystem and descriptor
ownership, executable/interpreter/library admission, namespace installation,
privilege/FD/signal policy, successful-exec acknowledgment and descendant-safe
supervision. None is granted by this observation or implemented here.

The actual static custody launcher remains static: its existing `PT_INTERP`,
dynamic dependency, architecture, executable digest and static-PIE checks are
untouched. The shared verifier does not broaden that ELF allowance, the
dm-verity profile, or any native start/continuation authority. Original caller
deadlines remain caller-owned; blocking kernel calls still require the existing
external watchdog rather than a claimed preemptive timeout in this mechanism.
