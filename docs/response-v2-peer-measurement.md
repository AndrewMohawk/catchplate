# Actual peer measurement and the guest inspector boundary

The custody transaction receiver now uses one private Linux measurement core in
`response_v2/custody/peer_measurement.rs`. Both initial authentication and every
packet, including the checks before response release, consume that core. The
existing UAPI probes use its same socket/PIDFD and security-label primitives.
This is source-only work. It has not been built or executed and does not yet
provide the privileged guest inspector or a running enclave cohort.

## What produces a measurement

`capture_connection` obtains actual `SO_PEERCRED`, rejects the wrong/zero UID
before process-file work, and obtains the connection's kernel `SO_PEERPIDFD`.
It does not use a numeric-PID-open fallback. `capture_packet` additionally
requires the actual received `SCM_PIDFD` and the retained connection measurement.
The receiver separately joins actual per-packet credentials before this call.

Both paths retain the existing stable-process checks around the real cgroup,
socket/current security labels and `/proc/<pid>/exe` reads. PIDFD namespace
identity, proc directory device/inode and process start ticks must agree before
and after measurement. A packet must still identify the originally admitted
process, UID/GID, cgroup, label and executable. Live-PIDFD checks remain required.
No caller can decode a wire object into the private `PeerMeasurement` type.

The existing executable cache is moved with its measurement implementation:
same bounds, two-second TTL and integrity-conditioned keys. Its key includes
stable process identity, exact executable file identity and an actual fs-verity
or IMA signal; no such signal means no cached executable measurement. Cache hits
repeat current-file and integrity checks. This neither adds an integrity signal
nor treats an ordinary file hash as provenance.

The host receiver's configured identity pins, per-packet credential checks,
configuration admission, operation deadlines and signed response protocol stay
separate and unchanged. Extracting the core does not grant additional privilege
or make a failing kernel/LSM interface optional.

## Why guest startup needs an additional owner

Dereferencing `/proc/<pid>/exe` is subject to a ptrace access check; possession of
a PIDFD alone does not grant that access. A distinct-UID, nondumpable native gate
therefore cannot simply be measured by an unprivileged router. See the
[Linux proc executable contract](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
and [ptrace access-check rules](https://man7.org/linux/man-pages/man2/ptrace.2.html).

The chosen follow-on is a deliberately small same-guest inspection owner, not
dumpability relaxation, a shared gate/router UID or inspection capability in
the serving processes. It must be independently pinned and confined, bind one
actual gate PIDFD at cold preparation, and use this same kernel-measurement core
for each admitted socket/packet original. An enclave quote over a submitted
executable hash does not establish which Unix process supplied that hash.

The inspector must accept only the actual accepted socket and connection/packet
PIDFD originals over a privately provisioned channel. No request may select an
arbitrary PID, path, executable descriptor or replacement target. Its bounded
response must bind the actual original frame digest, channel/session sequence,
configuration and original deadline. No memory, key, descriptor-return, generic
ptrace or generic success-verdict RPC belongs in that interface.

The minimum required inspection capability is an explicit additional TCB risk.
The follow-on launcher must drop unrelated capabilities and credentials, enforce
no-new-privileges and nondumpability, and install a syscall allowlist that excludes
execution, child creation, network connections, memory inspection, namespace/
mount operations and filesystem mutation. Seccomp cannot validate pathname
contents, so fixed-path construction remains in the trusted code. See the
[Linux seccomp contract](https://man7.org/linux/man-pages/man2/seccomp.2.html).

Current consumers require fresh per-packet measurements, so a startup-only
inspector is insufficient. One owner may last only for the original gate
lifetime and original admitted deadline, with no target replacement or authority
renewal. An absent/dead owner or unavailable kernel/security-label interface
must refuse. Independently authenticated release, actual confinement and kernel
behavior still require runtime evidence.

## Still to connect

The privileged inspector process, its closed IPC protocol, native parent launch
and lifetime ownership, actual router client, guest FD delivery and measured
packaging are not supplied by this extraction. Guest listener preparation and
activation have their own original-owner contract. Their implementation does
not by itself fix cross-UID process inspection or authorize the remaining
encrypted role-secret provisioning, backend and cohort startup.
