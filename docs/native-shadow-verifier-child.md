# Fixed external verifier child confinement

This source slice supplies `native_shadow_verifier_supervisor_v1/child.rs`, now called by the [fixed external supervisor](native-shadow-verifier-supervisor.md). The child module does not install a service, admit FD4/5 authority, create an operation window, collect output, or verify a signed result. Source review is not build, syscall-compatibility, kernel, or runtime acceptance.

## Actual parent contract

The private `PreparedChild::prepare(&RuntimeBorrow, seed, evidence, output, gate)` consumes no secret bytes. It borrows the genuine [retained runtime preparation](native-shadow-verifier-root.md), duplicates the exact root/interpreter/configuration/seed/evidence/pipe originals above FD127, retains a genuine parent PIDFD, and prepares the fixed argv and seccomp program before clone. It opens and checks the actual root-owned `/dev/null` character device before the child loses access to the host filesystem. It returns no successful verification or readiness DTO.

The parent supplies separately admitted seed/evidence originals, a blocking CLOEXEC output-pipe write end, and a distinct blocking CLOEXEC gate-pipe read end. The parent must own the corresponding endpoints; only its output-read end may be nonblocking. Seed and evidence remain distinct final-verifier-owned 0600 zero-link sealed originals, respectively exactly 32 bytes and at most 128 KiB. Their public-key, evidence, boot, authority, and original-byte admission remains the parent inputs owner and actual Python verifier's job, not these metadata checks.

The parent must arm its original absolute CLOCK_BOOTTIME SIGKILL watchdog before potentially blocking runtime preparation. It then uses actual `clone3(CLONE_PIDFD)` without `CLONE_VM`, `CLONE_FILES`, or `CLONE_SIGHAND`, calls `unsafe PreparedChild::enter(&self) -> !` immediately in that child, and binds the original returned PID/PIDFD to the same runtime owner. Only after successful binding may the parent write the source-fixed byte `0xA5` to the gate and close its gate endpoint. That byte orders execution after real parent ownership; it is not authorization, a new deadline, or a result.

## Fixed child sequence

The child path uses only retained immutable buffers, stack values, and libc/raw syscalls: it performs no heap allocation, locking, formatting, arbitrary callback, or Rust secret read after clone. Failures call `exit_group(127)` without emitting output.

It checks the actual parent PIDFD and parent relationship, installs parent-death SIGKILL, resets inherited signal handlers/mask, and verifies the same inherited descriptor identities. It changes root using the retained runtime root, sets cwd to `/`, and installs only these non-CLOEXEC slots:

| FD | Original |
| --- | --- |
| 0 | Actual `/dev/null` |
| 1 | Private output-pipe write end |
| 2 | Actual `/dev/null` |
| 3 | Retained protected named verifier configuration |
| 4 | Independently admitted verifier seed original |
| 5 | Exact sealed evidence original |

All other inherited descriptors are marked CLOEXEC, including the high pinned interpreter, parent PIDFD, runtime roots and gate. The child clears supplementary groups and ambient capabilities, drops every supported bounding capability, locks securebits, installs no-new-privileges, permanently sets all three UID/GID slots to the runtime's independently admitted final identity, and clears effective/permitted/inheritable capabilities. It verifies those results before proceeding. Core/file output/memlock limits are zero, process count is one, FD limit is 96, address space is 512 MiB, and stack is 16 MiB. These fixed ceilings do not extend the original wall-clock operation window; concurrent processes under the same verifier UID can cause fail-closed process-limit refusal.

Credential changes clear the parent-death setting, so the child reinstalls SIGKILL after the UID/GID transition and repeats the actual parent PIDFD/relationship check. This follows the kernel's [parent-death signal contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

The child sets nondumpability before exec. Ordinary exec can reset dumpability; no uninterrupted cross-exec nondumpability claim is made. The existing Python `Originals` owner reasserts and verifies nondumpability and no-new-privileges before reading its seed/evidence. The dedicated final identity must not be shared with untrusted processes. See [execve process attributes](https://man7.org/linux/man-pages/man2/execve.2.html).

## Closed syscall boundary and initial exec

The filter is installed before waiting on the gate or executing the interpreter. It accepts only the native x86_64 audit architecture and kills x32/other ABI entry. All unlisted calls return EPERM. In particular there are no fork/vfork/clone/clone3, socket/connect/sendmsg/recvmsg, namespace/mount, io_uring, ptrace/process-memory, descriptor-duplication/transfer, or generic execve permissions. `open`/`openat` accept only read-only access; filesystem mutation calls are absent. Writes/writev go only to stdout or null stderr. `fcntl` allows only fixed read queries and setting CLOEXEC; ioctl permits only terminal/byte-count queries and setting CLOEXEC. The prepared filter's sole child-PID field is filled from actual `getpid()` in the clone child so that `pidfd_open` permits only its own process with flags zero, as required by Python `Originals`.

The allowlist preserves read/stat/directory operations, signals, clocks, memory management, randomness, libc thread-local initialization, and fixed hardening queries needed by the pinned Python/cryptography/COSE verifier. `prctl` can only query dumpability/NNP or set them to the required safe values. Resource changes are limited to the already hard-zero core limit; other resource operations are read-only. The `mmap` rule rejects initial shared-writable mappings, but is not a general memory-protection policy: `mprotect` remains available to the pinned runtime. This is a fixed offline verifier TCB, not a hostile-Python sandbox or memory-execution policy. Any concrete compatibility correction still requires an exact source/runtime dependency and must not introduce process or network fallback.

After a genuine gate byte, the child repeats the original BOOTTIME and actual parent checks and invokes only the high held interpreter through `execveat(AT_EMPTY_PATH)`, with argv `/usr/local/bin/python3.11 -I -B /opt/serverware/scripts/verify_native_shadow_custody.py` and an empty environment. The filter constrains this initial exec to the original descriptor/flag pair; no broader Python self-exec prohibition or control-flow guarantee is claimed. The pinned ELF descriptor is CLOEXEC, unlike the script-descriptor case described by [execveat](https://man7.org/linux/man-pages/man2/execveat.2.html); the script is instead selected by the fixed path inside the immutable image. The kernel preserves installed [seccomp filters across exec](https://man7.org/linux/man-pages/man2/seccomp.2.html).

The parent still owns original-deadline cancellation, actual child PIDFD stop/reap, runtime terminal-original checks, mount retirement, bounded stdout withholding, final input/time checks and signed-result verification. EOF, a gate byte, successful exec, or source-complete confinement does not replace those operations or prove native shadow custody admission. No build or runtime execution has been performed for this slice.
