# Independent guest-time issuer runtime and supervision

This source adds an actual offline image producer and one-shot external issuer
launcher. It does not deploy an issuer, create keys, authorize a guest, or prove
the build/runtime lane has passed. The [issuer protocol](native-shadow-guest-time-issuer.md)
and its independently signed configuration are unchanged.

## Separate build artifacts

`native-shadow-time-issuer-runtime-artifact` exports
`/shadow-time-issuer-output/native-shadow-time-issuer-runtime.squashfs` and its
canonical `native-shadow-time-issuer-runtime.json` inventory. The separate
`native-shadow-time-issuer-supervisor-artifact` exports the static, bounded
`catchplate-native-shadow-time-issuer` binary. Neither is copied into the
claimant enclave image. No private key, policy, launch configuration, certificate
selection, or request is baked into either artifact.

The offline `package_native_shadow_time_runtime.py` producer uses the actual
admitted `Closure` copier, pinned Python 3.11 build image, hash-locked wheels and
admitted source manifest. It copies the exact interpreter/libpython/stdlib,
cryptography 50.0.0, cffi/pycparser, cbor2 5.9.0, both actual extension modules and
their loader-resolved immutable dependency closure. Its explicit application
inventory is `native_shadow_nitro_{profile,originals,verifier}.py`,
`native_shadow_time_{profile,originals,issuer}.py`, the package initializer and
the genuine `scripts.verify_nitro_tee` verifier. The only script entrypoint is
`/opt/catchplate/scripts/issue_native_shadow_guest_time.py`.

The image has no shells, installer, control-plane storage modules or arbitrary
scripts. `/proc` and the empty root0400 issuer-policy placeholder are only fixed
mount targets. The deferred build-only import check includes the actual lazy
Nitro/originals/time modules; it does not call issuance. Image, interpreter and
entrypoint hashes are emitted independently in the public manifest. That
manifest has `releaseAuthority: false`; installation still needs independent
artifact admission and the exact protected launch pins.

## Fixed caller and original owners

The no-arguments/no-environment supervisor uses the separately selected
`RuntimeAdmission::open_time_issuer()`. Old verifier launch labels, fixed
entrypoints and sealed-evidence FD5 behavior are unchanged. The new launch is
closed exact3 `catchplate.nativeShadowGuestTimeIssuerLaunch/v1`:
`apiVersion`, `runtimeImage` (the existing exact5 immutable-image pins), and
`issuerConfigurationSha256`.

The independent operator must deliver these original public files before the
one-shot launch, root:root0400, singly linked, canonical ASCII/no newline:

- `/etc/catchplate/native-shadow-time-issuer-launch.json` (at most 16 KiB).
- `/etc/catchplate/native-shadow-guest-time-issuer.json` (at most 512 KiB),
  matching the launch hash and the existing exact17 issuer contract.

Inherited FD4 is the actual 32-byte, final issuer UID/GID0600, unlinked,
four-seal signing-seed memfd. FD5 is the actual root-owned connected TCP stream,
not a listener or a path. Both slots are reserved before opening any public
original, so a missing slot cannot become an incidental later open. The parent
does not read seed bytes. The held seed identity/seals and socket identity,
cookie, flags and actual endpoint tuple survive the preparation. The tuple
must match the protected configuration's exact local IP/port and peer IP.

The parent captures the actual process/start/PIDFD/boot/time namespace and
checks the config's original <=30-second absolute BOOTTIME window. It arms the
existing independent CLOCK_BOOTTIME SIGKILL watchdog before image/mount work.
There is no disarm, relative renewal, service loop, accepted-socket loop, policy
fallback or automated relaunch. Separate external key/configuration delivery
and a root-created admitted TCP connection remain deployment prerequisites;
the launcher does not listen, connect, fetch or create authority.

The exact admitted image is copied into sealed immutable image custody and
mounted in a fresh private namespace. The real policy file is attached readonly
at the fixed issuer name; genuine readonly procfs supplies process/boot checks.
The shared source-fixed child trampoline uses actual clone3/PIDFD, not a
predicted process identity, maps config3/seed4/socket5, closes unrelated
inheritance and executes the pinned interpreter with only `-I -B` plus the fixed
issuer script. It drops groups/UID/GID/capabilities, disables dumps, fixes resource
limits/NNP and re-arms parent-death SIGKILL after the credential transition.

Only the explicit time profile adds seccomp permission for fixed FD5 socket
inspection/send/receive/shutdown and its nonblocking setup. It adds no
socket/connect/bind/listen/accept, arbitrary descriptor transfer, writable file,
new process or generic command capability. The old verifier filter keeps its
old syscall permissions. The issuer independently checks final originals,
verifies its signing seed against the independent time key and authenticates the
original C9 scope/configuration before issuing its challenge. The full
purpose-bound NSM evidence is verified before the anchor. Parent root custody is not that signature
verification and is never described as a TEE attestation.

## Completion and uncertainty

The issuer itself performs the unchanged one-challenge/one-evidence/one-anchor
TCP protocol. An anchor can reach the guest before parent cleanup; its signature
is strictly time evidence, not a process-reap or mount-retirement receipt.
The parent accepts no stdout data and exposes no result/secret DTO. Exit zero
requires the actual stdout EOF, owned child terminal observation, original
checks, positive exact PIDFD reap, successful private mount/workspace retirement
and actual child exit status zero. A failed/partial send or nonzero parent exit
does not revoke already transmitted evidence, manufacture cleanup, permit
retry, or renew either original lifetime. Failure uses the existing owned-child
stop/retirement path; the independent watchdog remains armed even during
cleanup. Parent death also kills the exact child through its retained original
parent-death association.

The authenticated NSM timestamp/bracket interval math, explicit independent
timestamp/rate trust assumptions, all-key/trust expiry checks and original guest
lifetime remain unchanged. Issuer arrival wall time is never the guest epoch
anchor. End-to-end deployment, key delivery, reproducible artifact verification
and runtime acceptance remain separate unexecuted work.
