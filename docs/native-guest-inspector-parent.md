# Native guest inspector parent

This source slice connects a real parent launch to the fixed guest inspector,
not a simulated measurement service. It has not been built or executed. An
initialized inspector does not establish the seven-role custody cohort, EIF
measurement, release admission, provider readiness or pilot acceptance.

## Cold selection and originals

Only native startup configuration v8 with the explicit
`--native-startup-inspector-v8` mode selects this parent. The fixed production
entrypoint maps its first `--guest-inspector-v8` selector to that mode;
`--measured-refresh-v7` maps to the separately existing measured-refresh mode,
and no selector preserves v6. It never derives a mode from configuration
contents or HTTP. Older configurations and CLI modes do not acquire this owner.

V8 preserves all v7 encrypted service-token Pending-to-Installed and measured
refresh joins. It adds the closed four-field `guestInspector` object:
`apiVersion=serverware.nativeGuestInspector/v1`, `executable`,
`configuration` and `delivery`. Each artifact has exact `path` and
`sha256` fields. Configuration/delivery paths are distinct canonical absolute
paths, distinct from the executable. The configuration is independently pinned
and retained by actual native startup; the inspector separately re-admits the
genuine signed router delivery, boot, generation and role identities. Its
actual configuration hash must match the cold pin, and actual router UID and
generation must match the selected response client. Browser metadata, an
initialized frame or an equality of unowned digests cannot replace these owners.

The only inspector executable is
`/usr/local/bin/serverware-response-v2-guest-inspector`: protected root-owned
ancestors, regular root:root single-link file, no group/other write, no special
mode bits, owner execute and at most 64 MiB. The observed bytes must match the
independent SHA-256. The supported image is native 64-bit little-endian ELF with
an executable entry, no PT_INTERP/DT_NEEDED, writable-executable load segment or
executable stack. The parent copies these bytes to a read-back-checked sealed
memfd and executes that retained descriptor, not the mutable pathname.
The sibling image helper also has a separate fixed-only guest-role image
constructor for the actual cohort factory; image observation alone grants no
role or launch authority.

The production Dockerfile adds a static build/check recipe, artifact target and
root:root0555 image copy. These are source packaging instructions, not a claim
that a compiled image or measured enclave exists.

## Real child creation and initialized handshake

The actual root `native_serving_privileges::Prepared` owner proves the creating
main thread is still single-threaded. Parent launch precedes permanent gate
privilege drop, response-client initialization and native serving key creation.
`clone3(CLONE_PIDFD)` supplies the child identity atomically. The child follows
only a fixed syscall trampoline with no allocator, environment, callback or
unwinding: parent-death protection, original-parent race check, fixed descriptor
mapping, signal reset/unmask, closed stdio and fixed `execveat(AT_EMPTY_PATH)`.
Every other inherited descriptor is CLOEXEC. There is no numeric-PID fallback.

FD3 is the private gate-lifetime seqpacket channel; FD4 is the independent
router channel; FD5 is the exact root:root0600, regular, unlinked, all-four-seals
bootstrap original. The bootstrap is canonical JSON without LF, at most 16 KiB,
with exactly seven fields: API version, configuration path/hash, delivery
path/hash, original gate-lifetime BOOTTIME deadline as a canonical decimal
string and fresh nonzero 32-byte base64url channel nonce. It is consistency
metadata supplied only by this actual parent, not a signed authority.

The fixed worker re-admits signed originals, pins its actual parent, changes to
UID/GID64990 distinct from the gate and seven roles, retains only
CAP_SYS_PTRACE and installs its no-memory/ptrace/exec/connect confinement.
It resets PDEATHSIG after changing credentials and separately arms an
unmodifiable absolute BOOTTIME termination timer. Its initialized frame has
exact API version, nonce and bootstrap hash. The parent enables PASSCRED and
PASSPIDFD before creation and accepts only actual kernel credentials64990 plus
SCM_PIDFD matching the owned clone3 PIDFD. Ancillary originals are owned before
validation, and unexpected/truncated frames fail closed. Initialization stays
within both the original delivery startup bound and original native lifetime;
no startup timer is renewed.

Linux semantics used here are the primary
[clone3/PIDFD documentation](https://man7.org/linux/man-pages/man2/clone.2.html),
[execveat descriptor execution](https://man7.org/linux/man-pages/man2/execveat.2.html)
and [Unix ancillary credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
Parent-death protection is deliberately reset after credential changes, as
documented for [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
The fixed 64-signal syscall layout follows the pinned Linux v6.12
[signal UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/asm-generic/signal.h),
including its [arm64 restorer layout](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/include/uapi/asm/signal.h).

## Retained serving lifetime and router handoff

The initialized owner retains actual signed originals, immutable executable
and bootstrap, child PIDFD and private lifetime socket. An exact private
Prepared-origin association must join the permanent serving owner; equal
deadline values alone are insufficient. Native serving receives the SAME
inspector-bearing startup lifetime Arc, not a replacement clock owner.
Existing serving checks reach its process/socket/original checks. There is no
Arc cycle back from the inspector to the runtime lifetime.

The non-Clone router endpoint may be taken once from the actual initialized
owner. Its crate-private sealed inheritance borrow exposes only the held
channel, actual child PIDFD and SAME sealed bootstrap for the source-owned
cohort factory, with a check and exact common configuration/router delivery
path/hash join. It cannot be constructed from arbitrary descriptors. Router
fixed slots8/9/10 are channel/PIDFD/bootstrap; final response authentication
uses each actual kernel64990 SCM credential/PIDFD, not socketpair creation
credentials or an initialized frame forwarded by the parent.

Cancellation shuts down FD3 even after admission/lifetime expiry; the child's
original parent protection and absolute timer remain independent. A parent
PIDFD SIGKILL attempt is best effort and may be denied after the gate becomes
UID65534 while the child is64990. No signal result is a reap receipt. The
explicit serving finish attempts actual waitid(P_PIDFD) under the original
absolute bound and reports late/unavailable reap as error. Drop performs only
emergency cancellation plus nonblocking reap, with no success claim. Failed
initialization never becomes readiness and never authorizes a replacement
child, retry, new allowance or arbitrary inspection target.

Actual seven-role child creation, signed all-role inputs, fixed listener
handoff, dependency/readiness ordering and complete EIF/cohort lifetime
integration remain separate source work. This v8 inspector-only selection
does not substitute for any of them.
