# Independent generation-origin issuer runtime

This is the source-connected immutable image and one-shot retained-FD launcher
for the independent [generation-origin protocol](../schemas/native-generation-origin.v1.schema.json).
It does not deploy an issuer, generate a key, authorize a generation or establish
that a build or runtime acceptance gate has passed. The signed origin remains
provenance from the genuine installed gate, not Fleet load evidence, current
spool-head authority, readiness, or permission to perform a storage effect.

## Separate artifacts and caller

The production Dockerfile has two independently selected output targets:

- `native-generation-origin-issuer-supervisor-artifact`: the static, at most
  64 MiB `catchplate-native-generation-origin-issuer` executable.
- `native-generation-origin-issuer-runtime-artifact`:
  `/generation-origin-issuer-output/native-generation-origin-issuer-runtime.squashfs`
  and its canonical `native-generation-origin-issuer-runtime.json` inventory.

Neither target is copied into the claimant image. The existing time issuer and
external verifier keep their original closed launch, configuration, entrypoint
and protocol selection. No generic executable or signing-purpose selector is
added. The new binary calls `run_origin_issuer`, which selects only
`RuntimeAdmission::open_origin_issuer` and its actual retained public originals.

The offline `package_native_generation_origin_runtime.py` producer uses the
existing admitted `Closure` copier, digest-pinned Python 3.11 build stage,
hash-locked wheels, pinned build tools and admitted source manifest. It includes
the exact interpreter/libpython/stdlib, cryptography 50.0.0, cffi/pycparser,
cbor2 5.9.0, both actual native extensions and their loader-resolved libraries.
The fixed application inventory is the package initializer,
`native_shadow_nitro_{profile,originals,verifier}.py`,
`native_shadow_time_profile.py` (only the independent key-validity grammar),
`native_generation_origin_{profile,originals,issuer}.py`, and the genuine
`scripts.verify_nitro_tee` implementation. The sole entrypoint is
`/opt/catchplate/scripts/issue_native_generation_origin.py`.

No time-issuer executable, general signing CLI, control-plane store module,
key, policy, request or issuer configuration is installed in this image.
The deferred build recipe imports the actual fixed modules without running
issuance. It produces a bounded reproducible SquashFS and exact file inventory,
image/interpreter/entrypoint hashes, package versions and source-manifest hash.
Its manifest is `catchplate.nativeGenerationOriginIssuerRuntimeBuild/v1`,
purpose `independent-native-generation-origin-issuer-v1`, `releaseAuthority:false`.
These outputs are not an artifact-admission signature.

## Cold admission and retained descriptors

An independent operator must supply root:root0400, singly linked originals,
canonical ASCII with no trailing newline:

- `/etc/catchplate/native-generation-origin-issuer-launch.json`, at most 16 KiB,
  exact3 `catchplate.nativeGenerationOriginIssuerLaunch/v1`: `apiVersion`,
  `runtimeImage`, `issuerConfigurationSha256`. The paired
  [launch schema](../schemas/native-generation-origin-issuer-launch.v1.schema.json)
  fixes all five image fields and the only allowed image path,
  `/opt/catchplate/native-generation-origin-issuer-runtime.squashfs`.
- `/etc/catchplate/native-generation-origin-issuer.json`, at most 512 KiB,
  with the unchanged exact11 issuer configuration and independently signed
  authorization. Its complete bytes must match the launch hash.

The supervisor accepts no arguments or environment. Before opening policy or
any image it takes the actual inherited seed FD4 and TCP FD5. FD4 must be a
32-byte, unlinked, four-seal memfd, mode0600 and owned by the exact final issuer
UID/GID. The parent never reads seed bytes or derives a key. FD5 must be the
actual root-owned connected TCP stream, not a listener or file path. It retains
the socket identity, cookie, flags and exact local/peer tuple and compares that
tuple with the protected configuration. It does not accept, connect or resolve
a network endpoint. Independent key delivery and provision of this exact
connected socket remain deployment inputs, not effects claimed by this patch.

The actual parent/start/PIDFD/boot/time namespace and original absolute
BOOTTIME interval are retained; the interval must be positive and at most
30 seconds. The existing CLOCK_BOOTTIME watchdog is armed before image or
mount work, from this same admission. No arrival-based renewal, retry loop,
relative replacement deadline, fallback policy or caller-selected key exists.

The full pinned image is copied to sealed immutable custody and readonly
SquashFS. A fresh private namespace mounts the actual held configuration at
the fixed empty image target, alongside genuine readonly procfs. The actual
clone3/PIDFD child is retained before release. The fixed child trampoline maps
config3/seed4/socket5, closes other inheritance, drops groups/UID/GID/capabilities,
sets NNP/resource limits/no-dumps, and retains parent-death SIGKILL across the
credential transition. It executes the pinned interpreter with only `-I -B`
and the fixed origin entrypoint. The new explicit profile admits only the same
fixed FD5 inspection/send/receive/shutdown primitives needed by its protocol;
it admits no socket/connect/bind/listen/accept, descriptor transfer, writable
file, new process or generic MAC/sign API. The old time and verifier profiles
do not accept the new profile's policy or entrypoint.

The child independently rechecks actual originals, seed/public-key equality,
the distinct issuer authorization/root and origin key, measured holder and
target pins, actual Nitro chain/PCR/binding/nonce evidence and revocation/expiry.
Its challenge, evidence and origin retain the original protocol's purpose
domains, 2 MiB complete-frame ceiling and one-shot state. The issuer's own
trusted wall clock supplies issuer freshness, never guest epoch correlation.
The returned generation and baseline come from the genuine retained installed
owner; no local configuration or packaging step manufactures that observation.

## Completion, uncertainty and remaining deployment work

The signed origin is emitted on FD5; stdout is required to reach EOF with no
data. It may reach its recipient before parent cleanup. It is not a child-reap
or mount-retirement receipt. Supervisor exit zero separately requires actual
owned-child terminal observation, original checks, exact PIDFD reap, successful
private mount/workspace retirement and child exit status zero. Failure invokes
the retained-child stop/retire path under the same armed watchdog. Partial
output, nonzero exit or unknown cleanup neither retracts transmitted evidence
nor permits automatic issuance replay or a renewed lifetime.

Independent artifact admission/installation, root/config/key provisioning,
accepted transport ownership, trusted issuer time and the actual gate/relay
connection remain required deployment work. No authority signing, build,
container, parser, runtime or end-to-end test was executed for this source
batch. Later ledger event families remain outside this launcher change.
