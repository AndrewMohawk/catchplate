# External native-shadow verifier supervisor

The source-fixed `serverware-native-shadow-verifier` process joins the
[retained runtime root](native-shadow-verifier-root.md), original input custody,
[confined child](native-shadow-verifier-child.md), kernel deadline signal and
terminal-result handoff. It is external to the claimant enclave. This is
unbuilt source, not a deployed verifier, accepted attestation or pilot.

## Closed process interface

The Linux/x86_64 binary accepts no arguments, command, caller pathname or
environment-selected policy. Its only public Rust entrypoint exits the process;
there is no reusable launch, cancellation, restart or retry API.

| Input | Required original |
| --- | --- |
| Protected launch | Root-owned named `/etc/serverware/native-shadow-verifier-launch.json`, pinning the separate runtime image and exact verifier configuration |
| Protected configuration | Root-owned named `/etc/serverware/native-shadow-nitro-verifier.json`; its existing authorization, independent keys, boot/time namespace and original interval remain authoritative |
| Inherited FD4 | Fully sealed, zero-link, final-UID/GID-owned `0600` regular original containing exactly 32 verifier-seed bytes |
| Inherited FD5 | A distinct fully sealed original with the same ownership/mode constraints, containing at most 128 KiB of evidence |
| Inherited FD1 | Write-only pipe to the external public-result transport caller |

The supervisor checks both actual input slots before opening any new owned
descriptor, then retains their inode/device, ownership, sizes, timestamps,
flags and all four immutable seals. It never reads the seed or evidence bytes.
The actual Python verifier admits their content and authority. The external
provisioner supplies these originals; this process generates no verifier key,
trust policy, independent assignment, nonce or release authority.

The output pipe is retained and made nonblocking. Its identity is checked
through publication, but pipe metadata does not prove exclusive readership.
The transport caller must supply its own correctly owned reader. A terminal,
socket or arbitrary output file is refused.

## Original lifetime and actual child

`RuntimeAdmission::open()` first retains the actual protected public originals,
root supervisor identity and original BOOTTIME interval. The supervisor arms
`timer_create(CLOCK_BOOTTIME, SIGEV_SIGNAL/SIGKILL)` from that same admission
before consuming it in image copying, loop/mount preparation or child creation.
BOOTTIME includes suspension, and the selected notification targets the
supervisor process. No helper thread is responsible for checking a blocked
parent. See [Linux timer creation](https://man7.org/linux/man-pages/man2/timer_create.2.html).

`timer_settime(TIMER_ABSTIME)` uses the original absolute deadline and a zero
repeat interval; checks require that timer to remain armed. There is no disarm
method, renewed cleanup allowance or relative restart window. See
[absolute timer semantics](https://man7.org/linux/man-pages/man2/timer_settime.2.html).
The initial acquisition of the policy precedes timer arming and still requires
the external service's own launch bound. This source does not claim that a
userspace process can force synchronous kernel reap during uninterruptible
kernel execution, or that a pending deadline signal proves cleanup completed.

The parent preallocates the child buffers, then creates one actual child with
`clone3(CLONE_PIDFD)` and no shared address space, descriptor table or signal
handlers. The PIDFD comes from that clone operation, not a later numeric-PID
lookup. This follows [clone's PIDFD contract](https://man7.org/linux/man-pages/man2/clone.2.html).
The child immediately enters the fixed no-allocation confinement path.
The parent binds the returned PID/PIDFD to the retained runtime before sending
the private gate byte. Parent-death SIGKILL and parent-PIDFD checks are installed
around the permanent identity drop. The child forbids descendant creation and
network/descriptor-transfer syscalls; fixed argv and an empty environment select
only the admitted interpreter and verifier script.

## Result release and failure

The parent holds the private stdout pipe, collects at most 32 KiB and waits for
both EOF and actual PIDFD terminal readiness under the original deadline.
Canonical, duplicate-free, exact-purpose JSON shape is checked only as framing:
it is not a cryptographic verdict and does not replace the
[guest's signed-result admission](native-shadow-nitro-verifier.md).

Before public output, the same runtime owner checks terminal kernel evidence
and all image/configuration/process originals, reaps that exact child,
successfully retires its retained mounts and namespace, and requires
`CLD_EXITED` with status zero. Input identity and deadline are checked again.
Only then are original bytes written to the retained public pipe, without a
newline or reserialization. Publication failure can leave partial pipe bytes;
the receiving transport must require complete framing and successful process
settlement, and the guest must independently verify the original signature,
current trust and native-owner association.

Failure stops the retained child through its PIDFD and attempts exact retirement
without extending the interval. Partial cleanup retains the actual owner and
reap state. A failure after descriptor export, including a failed clone, exits
this one-shot process rather than accepting a caller assertion that teardown is
safe. No output, timeout, EOF or process exit is a successful-cleanup receipt.
Unsettled private workspace remnants may require separately authorized cleanup.
Failures use a fixed exit status without logging secret-bearing error text.

## Build and remaining integration

The existing admitted offline static Rust stage includes this binary and
checks absence of ELF interpreter/shared-library dependencies plus a 64 MiB
size ceiling. The separate scratch target
`native-shadow-verifier-supervisor-artifact` exports only
`/serverware-native-shadow-verifier`. The independently packaged
[Python runtime](native-shadow-verifier-runtime.md) remains another artifact;
neither is copied into the claimant enclave's default image.

Actual artifact construction, protected installation, bounded external service
launch, independent seed/configuration provisioning and public-result transport
to the genuine guest consumer remain required. Native guest launch, receipt/proof
servers, fixed-peer checks and lifetime settlement remain separate implementation.
The consolidated frozen build and real positive/negative syscall, timeout,
cleanup, signature and end-to-end acceptance have not run.
