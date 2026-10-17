# Independent native Setup issuer installation

This source supplies callable one-shot hardware-verifier, proxy-verifier and
final-authority deployments for the existing native Setup flow. It does not
generate keys, approve a release, install anything, contact a provider, or
establish runtime acceptance. No build or invocation accompanied this change.
The result remains `enclave-hardware-and-proxy-only`; the trusted-host-local CA
association is not measured-host evidence and does not confer `proxyReady` or
general production readiness. Protected Setup consumers still verify each
signature, complete original chain, current policy, approval and original expiry.

## Separate fixed artifacts

| Docker artifact target | Independent role | Installed one-shot | Raw sealed-FD entry |
| --- | --- | --- | --- |
| `native-setup-hardware-artifact` | `hardware-verifier` | `catchplate-setup-native-hardware` | `catchplate-native-setup-hardware` |
| `native-setup-proxy-artifact` | `proxy-verifier` | `catchplate-setup-native-proxy` | `catchplate-native-setup-proxy` |
| `native-setup-final-artifact` | `final-authority` | `catchplate-setup-native-final` | `catchplate-native-setup-final` |

Each scratch artifact is a filesystem installation root, not a runnable Docker
container. Its two static binaries are under `/usr/local/libexec`; the fixed
SquashFS is under `/opt/catchplate`, its recorded build inventory under
`/usr/share/catchplate`, and the corresponding unit/tmpfiles definitions under
`/usr/lib/systemd/system` and `/usr/lib/tmpfiles.d`. No artifact contains any
policy, request, private key, generated authority or activation permission.

The operator admits an exact source/archive, locked wheel/deb cache and resulting
release artifacts through the existing offline production build process. The
`native-setup-issuers-runtime` build stage produces all three roots; each artifact
exports only its selected root and fixed entrypoints. Install the selected
artifact paths as root-owned, preserving file modes, onto its separately
administered Linux x86-64 authority host. Admission of the artifact and its pins
is an independent operator responsibility, not evidence supplied by this image.
These artifacts must not be copied into the claimant/enclave, gate or ordinary
pilot service images. Do not co-locate the three independently trusted provider
roles or give their private keys to the claimant/control-plane operator.

The host needs real procfs, loop/SquashFS support, mount namespaces, `clone3`
with `CLONE_PIDFD`, PIDFD wait/reap, `CLOCK_BOOTTIME` POSIX timers and x86-64
seccomp. The root supervisor owns mount/drop operations; the actual Python
issuer runs under its separately assigned nonroot UID/GID with empty groups,
capabilities and environment, NNP, nondumpability, core zero and fixed limits.
It has no network/clone/namespace/descriptor-duplication syscall authority.
The initial interpreter is pinned and entered through the retained `execveat`
FD. This is not a broader claim that every possible Python self-exec has been
formally ruled out. The original child filter and all old purposes stay intact.

## Independently provisioned public and private originals

For the selected role, let `stem` be exactly one of:

- `setup-native-hardware-verifier`
- `setup-native-proxy-verifier`
- `setup-native-final-authority`

Provision `/etc/catchplate` under root-owned non-group/world-writable ancestors.
All four files below must be regular, singly linked, no symlinks, root:root0400:

| File under `/etc/catchplate` | Original |
| --- | --- |
| `<stem>-launch.json` | Canonical ASCII closed launch4 below, no LF, at most16KiB |
| `<stem>.json` | Existing independent-verifier configuration9, no LF, at most4MiB |
| `<stem>.seed` | Externally provisioned raw32-byte Ed25519 seed; never PEM, environment, argv or browser upload |
| `<stem>-request.json` | Exact existing canonical public producer request, no LF, at most4MiB |

Launch4 is `{apiVersion,role,runtimeImage,issuerConfigurationSha256}` with
`apiVersion: catchplate.setupNativeIndependentIssuerLaunch/v1` and the exact role
from the table. `runtimeImage` is the existing closed5
`{profile,imagePath,imageSha256,interpreterSha256,entrypointSha256}` from the
independently admitted build manifest; profile is `sealed-memfd-squashfs-v1`.
The image path must be `/opt/catchplate/<stem>-runtime.squashfs`. The fixed
entrypoints are respectively `verify_native_setup_hardware.py`,
`verify_native_setup_proxy.py`, `issue_native_setup_final.py` under the image's
`/opt/catchplate/scripts`. All SHA values use canonical nonzero `sha256:` form.
`issuerConfigurationSha256` binds the exact actual `<stem>.json` original.

Configuration9 remains the existing
`catchplate.setupNativeIndependentVerifierConfiguration/v1`:
`{apiVersion,role,uid,gid,operation,authorityRootPublicKeyPem,authorityConfigurationOriginal,authorityConfigurationSha256,controlPlaneConfigurationDigest}`.
The source verifies the cold root's full signed authority configuration and
the separately selected role key/provider. The provisioned seed's public key
must equal that independently authorized role key. No local file ownership,
build manifest, supplied request or seed creates authority. Hardware, proxy and
final keys remain distinct from each other, the configuration root, host CA
installation key, workload/enrollment keys, collector and control-plane keys.

`operation` remains exact5 `{bootIdBase64url,timeNamespaceDevice,timeNamespaceInode,issuedAtBoottimeNs,deadlineBoottimeNs}`.
It must identify the actual independent host's original boot/time namespace,
with a currently live positive decimal BOOTTIME interval no longer than30s.
The service never generates these pins or renews that interval. A separately
authorized provisioner must deliver the complete originals early enough for
the entire image preparation, verification, retirement and output to finish.
Rebooted, expired, replaced or mismatched originals refuse. UID/GID are actual
nonroot dedicated identities, distinct from claimant/reserved/CP identities.

Hardware/proxy request11 is the exact existing input9 plus
`attempt_original,evidence_original`. Input9 consists of `actor_id`,
`control_plane_configuration_digest`, `credential_policy`, `maximum_attempt_nanos`,
`association_original`, `runtime_original`, `enrollment_original`,
`installation_original`, `scope_original`. Final request6 is `actor_id`,
`control_plane_configuration_digest`, `credential_policy`, `maximum_final_nanos`,
`hardware_original`, `challenge_original`. These are the retained public Setup
originals, not a user-provided success status. Signatures, quote/PCR/nonce,
enrollment, host-local readback and response originals are reverified by the
unchanged actual producers before they can use the seed.

## Actual one-shot operation and recovery boundary

Apply the selected tmpfiles definition to create only
`/var/lib/catchplate/<stem>` root:root0700; it does not create inputs or keys.
After independent provisioning and unit installation, the operator explicitly
starts the matching `catchplate-setup-native-{hardware,proxy,final}.service`.
There is no enable-on-boot or restart policy. The installed binary accepts no
arguments and reads only its source-fixed files. Neither this instruction nor
a prepared unit means that installation/provisioning/invocation has occurred.

The runner admits launch/config originals, arms the actual absolute BOOTTIME
SIGKILL watchdog **before** reading private/public inputs or preparing mounts,
then retains the actual protected input files. It copies the raw seed and
request into distinct final-role0600 zero-link memfds with all four seals.
Root staging memory is zeroized before clone; the confined child receives
configuration3, seed4, request5, and a private stdout pipe. No signing primitive
is available in the root runner.

Before clone/issuer contact, the runner creates `intent.json` with O_EXCL,
fsyncs it and its directory, and checks exact readback. Intent7 binds the role,
actual launch/config/request SHA values and original BOOTTIME bounds under
`catchplate.setupNativeInstalledIssuerAttempt/v1`. A partial intent also fences
the attempt. It is never removed or retried automatically.

Only after the actual child exits, its same PIDFD/start/parent identity is
checked, terminal evidence is obtained, it is reaped, mounts retire, and status0
is confirmed may the runner create `result.json` root0400 with the exact
canonical no-LF public envelope2 (at most16KiB). It fsyncs/readbacks the file
and directory while retaining and rechecking the same public configuration,
process/time and input originals. The result has not been rewritten, wrapped
as success or promoted into another receipt purpose.

An existing intent causes a later start to refuse, even if no result exists.
Failure, timeout, lost systemd status, partial result or crash is **unknown**,
not proof of no signing. Recover only by reading the retained exact public
result and feeding it to the existing protected Setup consumer, which performs
its independent authority/currentness/expiry checks. Do not remove an intent,
refresh the deadline, issue again or infer success from an inactive unit. A new
attempt requires independent reconciliation/authorization; this runner does not
implement or authorize that operation. Ordinary file visibility alone is not
an authenticated acceptance or durable effect guarantee; consumers require the
full genuine signed original, and operator success also requires definite exit0.

The lower-level `catchplate-native-setup-*` binaries instead require actual
inherited sealed FD4/FD5 and write-only FIFO FD1, accept no args, and retain the
same fixed launch/config originals. They emit only after actual terminal/reap
and mount retirement. Their caller owns its own durable precontact fence and
output storage. These entrypoints cannot select each other's roles from a
descriptor, environment value, request field or optional profile.

## Offline closure and unperformed acceptance

`package_native_setup_issuers_runtime.py` reuses the bounded immutable copier,
digest-pinned Python image, hash-locked cryptography50.0.0/cffi2.1.0/
pycparser3.0/cbor2 5.9.0 and pinned native Debian tools. A bounded build-only AST
walk follows module-scope imports of fixed producer roots; explicit actual
lazy-call roots include the buffered capture/receipt, configuration and work
accounting validators. It records each admitted module/file, including the
real `catchplate_agent_trust` package and original `pyproject.toml` identity.
The existing enrollment-clock code imports shared pure proof/transition data
modules; those import dependencies are recorded, not replaced with fake clock
or authority modules. CP application/server/store/database modules and unknown
third-party packages refuse admission. Uncalled effect-factory lazy imports
are not pulled into the image. No unrestricted source-tree copy is used.

Each root has only its fixed script entrypoint, zero-byte non-authority named
configuration mount target and empty `/proc` target. The supervisor binds the
real held configuration and genuine readonly procfs; empty placeholders cannot
pass the existing Originals admission. Reproducible SquashFS and a deferred
isolated import probe are build definitions, **not performed build evidence**.
The exact source inventory, locked dependency closure, static binaries, seccomp
compatibility, kernel/mount behavior and genuine issuer→Setup path still need
the final connected build/runtime acceptance gate. Keys, independent hosts,
protected configuration/requests and release pins remain deployment inputs;
none were created or provisioned in this source batch.
