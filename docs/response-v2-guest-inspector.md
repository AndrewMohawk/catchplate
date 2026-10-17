# Fixed same-guest process inspector

This source adds the confined child needed to inspect a final-UID 65534,
nondumpable gate from distinct-UID response custody. It reuses the actual
[kernel measurement core](response-v2-peer-measurement.md); it is not an NSM
quote substitute, custody provider, relay identity or successful-verifier DTO.
Nothing here establishes a built image, launched cohort, working kernel/LSM,
or testable pilot.

The new binary is catchplate-response-v2-guest-inspector, with no arguments
or environment. Host measurement and the existing signed generation/TEE,
backend, readiness and response authorization contracts remain unchanged.
The source-owned privileged launcher and router client are separate required
integrations; this worker alone is not a reachable guest service.

## Original admission and private channels

The measured launcher must exec its independently pinned child before gate
secrets, worker threads and permanent gate privilege drop. It owns child exit,
reaping, original NativeRuntimeLifetimeV1 and exact endpoint custody. No
setuid/file-capability installation, public socket or general inspector CLI is
provided.

| FD | Actual original |
| --- | --- |
| 3 | Private gate-lifetime AF_UNIX/SOCK_SEQPACKET endpoint created by the actual launch parent |
| 4 | Private serialized router inspection endpoint, handed only to the signed final router |
| 5 | Root:root 0600 sealed memfd, link count zero, closed bootstrap up to 16 KiB |

FD 5 has all four WRITE/GROW/SHRINK/SEAL seals and canonical UTF-8 sorted JSON
without a trailing LF. Its exact seven fields are apiVersion,
configurationPath, configurationSha256, deliveryPath, deliverySha256,
gateLifetimeDeadlineBoottimeNs and channelNonce. The nonce is nonzero
canonical unpadded base64url for 32 random bytes. No secret/role-key originals
are sent to the inspector.

While still root, the child consumes a real ListenerPreparation admission:
the protected cold config, independently signed router delivery, signed role
topology, current boot and original startup window must all pass. Inspector
UID/GID 64990 must be distinct from every signed role UID/GID and gate identity.
This does not activate a generation or turn listener preparation into a quote.

The gate target comes only from FD 3's actual SO_PEERPIDFD, matching its
kernel peer PID to getppid() and retaining stable proc/PIDFD identity. No PID
or target path appears in the request grammar. The socketpair may have cached
root creator credentials: those are never relabeled as final gate or router
credentials.

Admission consumes the startup-only preparation owner. Afterwards the child
checks the retained config/delivery FDs, exact bytes/stat identity and boot;
it does not reopen root-private paths, change file ownership, or acquire DAC
capabilities. A path replacement cannot select a new original. The original
source-owned gate lifetime bounds runtime inspection independently of the
signed delivery's startup window; unsigned sealed metadata cannot create or
renew either authority. A one-shot absolute CLOCK_BOOTTIME SIGKILL timer,
parent PIDFD/channel checks and parent-death signal enforce child retirement.

## Measurement protocol

The [closed schema](../schemas/response-v2-guest-inspector.v1.schema.json)
describes data, not authority. IPC is canonical UTF-8 JSON, at most 4096 bytes,
one seqpacket per frame. Every router request carries genuine
SCM_CREDENTIALS and SCM_PIDFD; the first packet must have the signed final
router UID/GID and its actual process is retained for all subsequent packets.
There is no endpoint replacement, sequence reset or router rejoin.

Request fields are exactly apiVersion, channelNonce, requestSequence,
phase, frameSha256, operation, sessionId, sequence and
deadlineBoottimeNs. Required nullable fields must actually be present.
Channel sequence starts at 1 and strictly increases independently of the
zero-based local packet index (0–255).

- Connection phase uses operation connection, null frame/session/index,
  and exactly two SCM_RIGHTS originals: accepted socket, connection PIDFD.
- Packet phase uses before-dispatch or before-response, the exact actual
  inbound or outbound control-frame hash, nullable authenticated session hash,
  local packet index and exactly three originals: accepted socket, connection
  PIDFD, actual received gate-packet PIDFD.

The router must bind and compare these to its retained local frame and session,
not manufacture context by trusting an unauthenticated request. The inspector
does not consume the gate socket or independently claim to have observed frame
bytes. Each operation deadline can only narrow the unchanged gate lifetime.

The actual accepted socket's new kernel SO_PEERPIDFD, supplied connection
PIDFD and packet PIDFD must identify that same retained parent before and
after shared-core capture. The observed gate must be UID/GID 65534. The same
core obtains actual cgroup, security-label and executable hashes, retaining its
existing integrity-conditioned executable cache rules. Missing kernel or LSM
support refuses; no hash, label or native role quote is synthesized.

Result exact three fields are apiVersion, the exact request and
measurement. Measurement exact six fields are processBindingSha256, uid,
gid, cgroupSha256, securityLabelSha256 and executableSha256. The process
binding hashes the real PIDFD namespace PID vector, proc directory device and
inode, and process start ticks with the fixed
catchplate.responseV2.guestInspectorProcess/v1 + NUL domain and big-endian
integer framing. No descriptors, process memory, numeric target, keys, generic
verdict, release permission or persistent currentness claim are returned.

The router must still compare independently admitted measurement pins and its
original connection identity at every existing before-dispatch/before-response
consumer. A measurement is a bounded kernel observation, not a guarantee that
the process can never subsequently change.

## Fixed confinement and lifecycle

The child is single-threaded, UID/GID 64990, groups empty, nondumpable and
no_new_privs, with locked securebits. Only CAP_SYS_PTRACE remains effective,
permitted and in the bounding set; inheritable and ambient sets are empty.
The gate and router gain no capabilities. The capability is needed for real
cross-UID/nondumpable proc inspection; Linux and any applicable LSM must still
permit the reads. See the kernel interfaces for
[proc executable access](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
and [capability semantics](https://man7.org/linux/man-pages/man7/capabilities.7.html).

The x86-64 syscall allowlist admits bounded read-only proc/original access,
memory allocation without executable mappings, polling and kernel socket
inspection. Emission is limited to the two existing private endpoints via
descriptor-free sendto; sendmsg, filesystem writes, ptrace,
process_vm calls, process/thread creation, exec, namespace/mount operations,
socket creation/connect and privilege changes are absent. Source-fixed proc
paths derive only from retained kernel identities. This is an explicitly
privileged inspection TCB, not a claim that seccomp turns CAP_SYS_PTRACE into
a cryptographically target-scoped capability. No arbitrary memory-read RPC
exists. [Seccomp's syscall/argument boundary](https://man7.org/linux/man-pages/man2/seccomp.2.html)
does not authenticate process measurements.

The child sets SIGKILL parent-death behavior after the credential drop and
rechecks its actual parent: Linux clears that setting on credential changes.
The launcher must preserve its creating thread and actual child ownership.
[Parent-death semantics](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)
are not a substitute for the retained PIDFD and lifetime timer.

Only after confinement does FD 3 emit the exact initialized consistency frame
(apiVersion, channelNonce, bootstrapSha256). The parent must enable
PASSCRED/PASSPIDFD and compare actual final 64990 kernel sender identity with
its owned child PIDFD. The frame alone is not readiness or admission. Any
malformed request, identity/deadline mismatch, uncertain send, owner death or
channel failure exits nonzero and closes all retained descriptors; there is
no retry, error-verdict protocol, new allowance or automatic restart.

Remaining integration includes the actual measured executable/loader closure,
privileged parent launch and retained gate-lifetime factory, exact router
consumer joins, child cleanup/reaping, independently provisioned signed role
originals and real backend/quote/shadow owners. Builds, negative cases, kernel
confinement behavior, genuine guest startup and end-to-end acceptance have not
been executed by this source-only change.
