# External native shadow verifier runtime artifact

This is a separate offline runtime-image producer for the existing
[independent Nitro verifier](native-shadow-nitro-verifier.md), not a claimant
enclave service or a verifier launcher. No image build, import check, real quote,
provider contact, or deployment was executed for this source slice.

## Fixed producer and artifact

`scripts/package_native_shadow_verifier_runtime.py` runs only in the admitted
Linux/amd64 Python 3.11 build stage. The existing source archive/list/hash/mode
checks, digest-pinned Python image, hash-locked wheelhouse and pinned offline
Debian tools remain mandatory. The new Docker target is
`native-shadow-verifier-runtime-artifact` in
`data-plane/decision-gate-rs/Dockerfile.production`.

The build-only `native-python-runtime-build` stage supplies already admitted
inputs to separate broker and verifier branches. Its existing source-admission
ancestry still includes the Rust build; it does not become a new independent
source-trust mechanism. The verifier branch does not build or copy the broker
runtime, role-key runtime, shadow-key helper, claimant configuration, or keys.
The default final native-enclave target is unchanged and receives no verifier
artifact. Build tools, pip, shells and the full installed CP package graph are
not copied into the verifier root.

| Item | Fixed value |
| --- | --- |
| Artifact directory | `/shadow-verifier-output` |
| Image | `native-shadow-verifier-runtime.squashfs`, at most 512 MiB |
| Deployment image path | `/opt/serverware/native-shadow-verifier-runtime.squashfs` |
| Interpreter within image | `/usr/local/bin/python3.11` |
| Entrypoint within image | `/opt/serverware/scripts/verify_native_shadow_custody.py` |
| Invocation | Fixed interpreter with `-I -B` and the fixed entrypoint; no application arguments |
| Manifest | `native-shadow-verifier-runtime.json`, API `serverware.nativeShadowVerifierRuntimeBuild/v1` |

The manifest's `purpose` is `external-shadow-nitro-verifier-v1`. Its
`runtimeImage` contains exactly `profile`, `imagePath`, `imageSha256`,
`interpreterSha256`, and `entrypointSha256`; the profile is
`sealed-memfd-squashfs-v1`. It also records the original source-manifest hash,
epoch, image size, fixed paths, package versions, complete file hashes/sizes/modes
and mount targets. `releaseAuthority` is false: generated hashes are build
outputs, not independent deployment approval or evidence of successful loading.

## Actual dependency closure

The fixed entrypoint lazily invokes `native_shadow_nitro_verifier.run`, which
opens the real `native_shadow_nitro_originals.Originals` owner. These modules and
`native_shadow_nitro_profile` are copied individually with `serverware/__init__.py`.
The actual COSE/PKI verifier is the unchanged `scripts/verify_nitro_tee.py`, placed
in the isolated interpreter's `site-packages/scripts` namespace package. No
other script or CP/storage module is part of that namespace.

The package closure is the already locked `cryptography==50.0.0`, `cffi==2.1.0`,
`pycparser==3.0`, and `cbor2==5.9.0`, including their metadata and the admitted
CPython wheel's CFFI and CBOR extensions. No dependency is resolved or downloaded
by this producer. The [pinned CBOR package](https://github.com/agronholm/cbor2/blob/5.9.0/cbor2/__init__.py)
loads the top-level `_cbor2` extension; this producer requires that original
extension and refuses an absent or ambiguous layout instead of silently taking
the package's pure-Python fallback. The bounded copier retains Python stdlib (including the actual
lazy `select`, `ctypes`, time, procfs/FD and certificate-parsing dependencies),
libpython, and each copied ELF's recursive interpreter/DSO closure. It generates
a root-specific loader cache. Existing file/count/total bounds, no-symlink
checks, fixed timestamps, single-worker SquashFS creation and read-only modes
remain in force.

The deferred build-only import check names the actual lazy Originals module and
the Nitro module, not merely the entrypoint. It does not call `run`, read a seed,
verify evidence, or prove the supervisor's runtime behavior. A fresh reviewed
immutable dependency snapshot and actual post-freeze build/import/negative-path
verification remain required; this change does not repair or waive an old
snapshot mismatch.

## External launcher requirements

The purpose-only copier method `shadow_verifier_mount_targets()` accepts no
paths or content. It creates just these root-owned empty mount targets:

- `/proc`, a `0555` directory for genuine procfs.
- `/etc/serverware/native-shadow-nitro-verifier.json`, a zero-byte `0400` file
  recorded with its empty-content hash in the ordinary file inventory.

The empty configuration can never pass Originals' nonempty configuration check.
The actual external supervisor must admit the independently pinned complete
image, install it read-only, and bind the independently protected original
configuration at that exact name and genuine procfs before final identity drop.
It must pass the same configuration inode as read-only FD3. A generated policy,
copied caller DTO, or retained placeholder is not acceptable configuration.

FD4 is the separately provisioned exact 32-byte verifier seed and FD5 the
bounded original evidence, each in its own fully sealed final-UID/GID-owned
`0600` memfd. No seed, trust policy, authorization, PCR allowlist or evidence is
baked into this artifact. The dedicated final identity, empty groups/zero
capabilities, nondumpability, no-new-privileges, genuine procfs/PIDFD originals,
original external boot/time-namespace/absolute deadline, bounded result capture,
and actual child stop/reap remain launcher/owner obligations. The image neither
chooses that identity nor resets any allowance.

No NSM device or network contact is required by this external verifier's fixed
evidence-verification operation. Packaging does not claim syscall confinement,
secret-memory zeroization, or a prohibition on self-exec by the admitted Python
TCB. The [root owner](native-shadow-verifier-root.md) and
[fixed supervisor](native-shadow-verifier-supervisor.md) now connect those
originals to a confined child and terminal-before-output handoff in source.
The supervisor has its own separate static artifact target, never part of the
claimant image. Actual artifact construction and immutable installation,
external service/result transport, independent authority provisioning, and
positive/negative end-to-end verification are still needed before native
custody admission or pilot acceptance can be claimed.
