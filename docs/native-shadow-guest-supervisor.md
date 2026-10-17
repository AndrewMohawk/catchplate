# Fixed native shadow guest parent and static image

Source implementation only. No build, kernel, Nitro, KMS, transport, custody-service or production acceptance has been performed by this batch. This parent launches the genuine [native key-admission guest](native-shadow-guest-admission.md), not the legacy `TrustedHostNoTee` service and not a dispatch/settlement driver.

## Exact parent entry and ownership

`catchplate-native-shadow-guest-supervisor` is a separate fixed root-only, single-threaded Linux amd64 executable. It accepts no arguments or environment. It opens the SAME root:root0400 protected `/etc/catchplate/native-shadow-guest-launch.json` (closed `nativeShadowGuestLaunch/v1`), retains its exact original, and independently runs the existing signed C9 configuration/delivery admission against its own PIDFD/start/boot/time-namespace. The child repeats that admission against its own genuine process and private parent connection. No process identity or ready DTO crosses exec.

Parent entry permits only stdio and the signed contiguous activation slots6..69. FD3/4/5 and every other inherited descriptor must be absent before opening configuration files. Each activation remains the exact independently signed directory/socket device/inode/mode/UID/GID, with duplicate names/identities refused. Credentials are retained and checked as originals but their contents are not read by this parent. The original guest performs its final-role credential acquisition.

The parent arms the original signed absolute CLOCK_BOOTTIME lifetime SIGKILL watchdog BEFORE image/loop/mount effects. It makes a private mount namespace, opens the fixed static custody image through the existing full-pinned sealed-image/readonly-loop/SquashFS owner, checks the exact policy/runtime/build artifacts, and copies the actual admitted static executable to a root:root0500 zero-link fully sealed memfd. This cold image selection is not epoch-dependent closure authorization; the guest still verifies the separate purpose-signed closure using its genuine independent trusted-time interval.

Only then does the parent create a private AF_UNIX SOCK_SEQPACKET pair and clone3(CLONE_PIDFD). The preallocated syscall-only child trampoline sets PDEATHSIG SIGKILL, checks actual getppid, maps the real private endpoint to FD3 and actual activation originals to6..69, replaces stdio with genuine `/dev/null`, resets signals/mask, and marks every unused FD close-on-exec. Fixed empty-environment execveat consumes the sealed executable; no argv, executable path or command RPC is accepted. The one fixed `0xA5` pipe byte is sent only after the parent checks the clone's actual PIDFD kernel PID, start/parent and waitid child ownership. It grants no authority or fresh time.

The root parent remains a finite launch/lifetime TCB, not an unprivileged serving worker. The child owns its actual namespace/NSM/closure/permanent role drop and capability clearing as before. Parent FD3 is only retained liveness: no ready, result, key, signing or service protocol exists. Live child status is not key admission. The parent never declares either succeeded. Parent SIGPIPE is ignored so a failed gate write reaches owned child cleanup; the trampoline restores default child signal dispositions. Abnormal external termination can still cause kernel process-exit teardown; this is not reported as an orderly reap or completed cleanup.

During supervision, launch/C9/runtime/image/executable/activation originals, same parent boot/process and same child PIDFD/start/parent are retained and rechecked. Child termination or any drift stops the owned child. A fixed250ms reserve narrows the signed lifetime for shutdown/SIGKILL/reap attempts; it is not a new cleanup window. Exact waitid(P_PIDFD) terminal evidence and reap precede releasing the image. Timeout or wait failure cannot stand for death: the process exits fail-closed with the original watchdog/PDEATHSIG still in force, without claiming resources retired. Readonly loop AUTOCLEAR/root-FD retirement is requested only after reap, but verified loop-device cleanup is not claimed. No descendant-wide settlement/reaper proof is produced. The standalone entry intentionally exits nonzero and emits nothing, even after normal lifetime retirement.

## Separate static runtime artifact

`native-shadow-custody-runtime-artifact` is an explicit Docker target; the existing `native-enclave` target does not silently select or copy it. `native-shadow-guest-supervisor-artifact` separately exports the static parent binary. The pinned Rust/musl build produces the fixed guest and parent; the digest-pinned Python build stage only runs the bounded producer and admitted Debian squashfs tool. Neither Python, its wheels, a loader, DSOs, nor the Python shadow-key helper enter the static custody image. ELF admission rejects PT_INTERP and DT_NEEDED; the real guest repeats its static executable check.

The independent build context must supply only `production-shadow-custody/{inputs.json,seccomp.bpf,runtime.json,build-recipe.json,provenance.json}`. `SHADOW_CUSTODY_INPUTS_SHA256` is the independent whole-inputs pin, never a runtime environment override. [Inputs schema](../schemas/native-shadow-custody-image-inputs.v1.schema.json) is exact6, canonical ASCII JSON plus one LF. Its source manifest digest must match the genuinely admitted source archive. Source-fixed Cargo.lock and the actual newly built binary come from that same pinned build, not public caller paths. The supplied four public originals are captured with bounds, exact full hashes and stable file metadata; no default policy/provenance is generated. Structural policy and independent authorization are still validated by the runtime owners, not inferred from build success.

Image inventory is exactly:

| Fixed path | Content/protection |
| --- | --- |
| `/usr/local/bin/catchplate-policy-shadow-custody-guest` | Actual static guest, root0555, <=64MiB |
| `/opt/catchplate/native-shadow-custody/seccomp.bpf` | Exact public policy, root0444, <=32KiB |
| `/opt/catchplate/native-shadow-custody/runtime.json` | Credential-free public role runtime config, root0444, <=4MiB |
| `/opt/catchplate/native-shadow-custody/Cargo.lock` | Admitted source lock, root0444, <=4MiB |
| `/opt/catchplate/native-shadow-custody/build-recipe.json` | Independently pinned public recipe, root0444, <=4MiB |
| `/opt/catchplate/native-shadow-custody/provenance.json` | Independently pinned public provenance original, root0444, <=4MiB |
| `/proc` | Empty root0555 mount target; real guest procfs comes from the guest owner |

The producer emits `native-shadow-custody-runtime.squashfs` and a public build inventory with exact image/executable/input/source/file hashes and `releaseAuthority:false`. No assignment, deployment authority, attestation, key set or signature is manufactured. Provenance must describe independently pinned pre-image inputs, not require its own resulting image hash; assign/sign the final closure only after the image exists. Install the image at `/opt/catchplate/native-shadow-custody-runtime.squashfs` through independent protected provisioning.

## Still required

The actual protected launch11, signed C9 delivery/activation originals, purpose-signed closure, independent full18 key inventory, encrypted local-key/KMS inputs, NSM device, time issuer and verifier original/profile/relay provisioning must already exist. No seed, verifier authority, bootstrap nonce, time anchor or signed boot/config is baked into this image. This source does not integrate an outer gate launcher or fabricate unknown activation resources. The distinct Python key-helper image and external verifier/time-issuer images remain separately pinned/provisioned.

Actual10 receipt/four proof service endpoints, dedicated fixed-peer inspection and genuine driver/reaper/settlement ownership remain separate implementation joins. This parent, child key admission, and static root neither substitute for them nor close whole native-shadow custody. First build and deployment must demonstrate real kernel syscall/loop/mount/procfs/NSM behavior, irreversible drop, independent issuer/verifier exchange, cleanup and the eventual full credential flow. Those acceptance results are unverified here.
