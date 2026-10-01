> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Native pilot build and launch preparation

This is an executable **build** entrypoint, not a launch/readiness command. It
assembles the real control-plane/gate images and the native guest/cohort
artifacts from one clean committed source snapshot. It does not create keys,
sign grants, install files, start services, contact providers, or replace any
independent authority with a local manifest. No build or runtime acceptance was
performed when this source was authored.

## Current engineering assembly

The `.421` [approval provider](native-pilot-approval-provider.md) is now in the
supervisor source roster and fixed entrypoint grammar. Frozen `bb54b76a` passes
107 focused source/transport/package controls, but this turn did not rebuild
runtime artifacts. The exports below therefore remain historical. Next is one
matching-source export of all three runtimes; the unpublished dependency candidate
still cannot produce a strict approved release package.

The `.415` [fixed lifecycle caller](native-pilot-lifecycle.md#fixed-executable-caller-415)
refreshes **only the supervisor** from exact source
`508ea68e8c7b500c4eae818e1260c1fcabe7e2e6`. Its 95 focused checks pass in
3.399 seconds, alongside twelve-file syntax/both Make inventories and five
actual imports; no errors, skips or corrective reruns occurred.

| Runtime | Frozen source | Materialized entries | Exact source files | Build / source observation |
| --- | --- | ---: | ---: | --- |
| Supervisor | `508ea68e` | 6,227 | 1,387 | Passed |
| Conductor, historical | `90e10cbb` | 6,206 | 1,373 | Passed at that snapshot |
| Authority, historical | `90e10cbb` | 6,216 | 1,379 | Passed at that snapshot |

The supervisor build and observer both exited **0**: **24.995891030 seconds**
for the build and **34.507501628 seconds** for observation, **62.244210958 seconds**
overall. The raw archive is **170,777,088 bytes**. Exact source files comprise
1,374 in `/app`, six in `/authority` and seven in `/supervisor`; the observed
source-manifest SHA-256 is
`821b86e647d2492b7c1f6d36456bd186257b59a54c497efce4ce976c085a1c37`.
Archive hash from the retained build receipt, not a repeated TAR hash:
`a96631dd6aae995f617a6c8e2b4c69380a3a6edd3c047a92f1a62024d3719fed`.
The durable evidence destination is
`codex-offload/serverware/engineering-builds/508ea68e-lifecycle-cli-hLUp5a/`
under the operator's home directory; preservation is part of the result handoff.

This export includes the fixed lifecycle caller and installer commands, but
does not provision their independent decision provider. It uses the unchanged
unpublished dependency candidate and remains `production_release_eligible=false`:
no strict inventory/package, installed runtime or live application flow was
produced. No native compilation, conductor/authority rebuild, cloud action or
paid test was repeated. The historical conductor/authority exports are **not**
matching-source approved packages for this supervisor. Their `.414` evidence
remains at `90e10cbb-connected-lifecycle-FdUpzn/`; `.413` evidence remains at
`fc466a0c-genesis-rendezvous-omGm4r/` under the same engineering-builds directory.

The `.392` source adds a separate
[commissioning supervisor package and executable](native-pilot-supervisor-executable.md).
It preserves the conductor/authority layouts and requires three independent
inventories plus real late approvals. Its `bd69e925` engineering export built and
materialized; the corrected read-only observer verified 1,310 source files.
[Exact evidence and boundaries](native-pilot-supervisor-executable.md#engineering-artifact-result).
The older results below are not evidence for the current supervisor source.

Earlier local results as of **2026-09-30 18:23 UTC**:

| Artifacts | Frozen source | Verified assembly result |
| --- | --- | --- |
| Control-plane and gate images | `04cf155a` | Both built; glibc 9m25s, static musl 11m03s; image/no-shell report passed. |
| Seccomp operator tool | `04cf155a` | Raw export, ELF readback and caller-owned staging passed, 4 entries. |
| Workload sidecar | `facdb895` | Corrected raw export, exact three-file/source readback and caller-owned staging passed, 8 entries. |
| Python conductor runtime | `7193b2a1` | Raw export and complete caller-owned staging passed, 6,060 entries. |
| Python authority runtime | `7193b2a1` | Raw export and complete caller-owned staging passed, 6,068 entries. |

These used the same unpublished dependency candidate in isolated engineering
checkouts. Every build retains `production_release_eligible=false`; raw exports
and materialized trees are not strict-source packages, approved installations
or pilot acceptance. The later Python-only revision closes inherited directory
and timezone-link layout defects; it does not change or restart the native
compilation. Full native guest assembly still requires approved public inputs.
No broad test suite, service deployment, signing or paid cloud operation ran.

Subsequent source adds startup-window issuance, protected bootstrap installation,
late-runtime closure authorization and the complete commissioning job graph.
Those changes are not included in the builds above. The new supervisor package
does not close remaining cleanup, provisioning and connected execution gaps.
Retain these older build results rather than rebuilding them for status.

Exact logs/reports, provenance and copy-verified hashes are retained under
`/home/catchplate/codex-offload/serverware/engineering-builds/`:
`04cf155a-native-images-jg1ez3`, `7193b2a1-python-jg1ez3`, and
`facdb895-native-tools-jg1ez3`. Each contains `RESULT.md` and `SHA256SUMS`, with
earlier failed attempts kept separately. Extracted staging remains private
scratch; no runtime was installed or started.

## Existing build owners, explicit profile

`scripts/build_native_pilot_artifacts.py` calls the existing
`build_production_images.py` source/archive, dependency-cache, private-context,
image and artifact build owners. The Docker targets use their existing pinned
base images, locked offline wheels/Cargo vendor, and `--network=none` build
steps. No dependency fetch is invoked. The build host/operator must provision
the exact base images and builder/cache beforehand; `--network=none` is not a
claim that an independently configured BuildKit daemon cannot access a registry.

The fixed selection includes native startup configuration/v22 with its separately
pinned [native workload trust grant](native-workload-trust-authorization.md),
and the ten-endpoint cohort configuration/v7 paired with
the one actual measured driver bootstrap configuration/v4,
bridge launch/v5, production RPC runtime/v9, spool services/v3, and ordinary
five-service launch/v6. Only DRS, CurrentSignatureAuthority and Cleanup select
ordinary effects runtime/v8 and `--guest-c9-effects-inspected`; the other two
ordinary services preserve their existing generation profile. These are the
required [ordinary-request effects](native-active-effects.md), not an optional
replacement for them. The original lifetime, whole-frame and descriptor
ceilings do not change.

The aggregate `native-pilot-artifacts` Docker target exports only:

- The actual static custody guest, cohort parent, guest supervisor and shadow
  worker, at their existing installation paths under `native-install/`.
- The existing six-file public guest SquashFS and its exact build inventory.

The real control-plane image contains the source-backed portal/API and actual
Python parent/resource owners. The real gate image contains the native entry,
gate, all five ordinary custody service executables, and their actual dynamic
runtime dependencies. It also carries the actual proof client and the separately
built static native response verifier needed by the collector. The command
records all eight ELF digests from
the built image using the existing **stopped** container export owner; no image
entrypoint runs. An ordinary service binary alone is not a complete host runtime.
Use the admitted image/closure and existing fs-verity installation conventions,
not an unverified copy of one ELF into an arbitrary host library environment.
The [collector's fixed configuration](native-pilot-request-collection.md) can bind
the recorded client/verifier bytes after independent artifact admission; hashes
in this local build report do not establish that admission by themselves.

## Workload sidecar artifact and unit-helper join

The fixed `workload-sidecar` command builds the existing static-musl
`native-workload-sidecar-artifact` target without public guest inputs, keys or
workload configuration. This is a separate workload-side export, not part of
the enclave or the Python conductor rootfs. The full gate build already
compiles this executable, but does not copy it into its final image.

From strict clean-source and reviewed dependency prerequisites:

```sh
python3 -B scripts/build_native_pilot_artifacts.py workload-sidecar \
  --out /srv/catchplate-fast/tmp/NEW-SIDECAR-OUTPUT
```

The new output contains `attempt.json`, exactly three files under `artifacts/`,
and `workload-sidecar.json` only after successful build and inventory:

| Exported path beneath `artifacts/` | Mode | Consumer |
| --- | --- | --- |
| `usr/local/libexec/serverware-workload-sidecar` | 0555 | Fixed workload service executable |
| `usr/share/serverware/install_workload_sidecar_unit.py` | 0444 | Offline unit-file output helper |
| `usr/share/serverware/native-workload-sidecar.v1.schema.json` | 0444 | Existing fourteen-field cold configuration contract |

The existing Docker owner retains its no-interpreter/no-needed-library ELF and
64 MiB executable checks. The post-export inventory refuses extra entries,
symlinks, regular hardlinks, wrong file modes and changed originals. It records
the actual Linux/amd64 executable digest and requires the helper/schema bytes
to match the captured source manifest. The helper is not imported or executed.
The fixed per-RUN build bounds and strict source/cache owner are unchanged;
this command has no dirty-tree option. Partial output is retained on failure.

After independent artifact admission and protected installation at those exact
paths, the [existing unit helper](native-workload-sidecar.md#fixed-artifact-and-offline-unit-preparation)
consumes separately provisioned configuration, its independent pin, and an
already admitted workload network namespace. It emits a unit only; it does not
install/start/enable it or provision credentials, a namespace or egress rules.
The build report likewise keeps release authority, live readiness, launch and
execution acceptance false. A built executable does not prove usable traffic.

## Conductor runtime package

The separate `native-pilot-conductor-artifact` target in the top-level
`Dockerfile.production` supplies the Python operator's filesystem. It combines
the existing pinned Python/libpython/stdlib/vendor artifact, the pinned
distroless base's system libraries, verified `serverware` sources, the conductor
script and its fixed isolated bootstrap. The default control-plane image stage
remains unchanged. This does not include native service executables, protected
configuration, keys, resource mounts or an independent authority coordinator.

After provisioning the same strict clean-source/dependency build prerequisites,
the explicit build command is:

```sh
make build-native-pilot-conductor-runtime \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/pilot-conductor-runtime
```

The output must be a new absolute directory. Inspect filesystem capacity first;
the exported rootfs plus archive can exceed 1 GiB. As with the other commands,
the build is offline at each RUN step, source/cache admission is mandatory,
and the existing 8-CPU/24-GiB/no-swap limits apply per RUN rather than in aggregate.
No independent guest build inputs are needed for this Python-only target.

The resulting layout is:

```text
attempt.json                    source and bounded-build selection
raw-rootfs.tar                  retained original Docker export
artifacts/                      actual exported operator rootfs
package/runtime-rootfs.tar      deterministic, uncompressed portable rootfs
package/package.json            unsigned inventory, source and archive hashes
conductor-runtime.json          successful local build/package report
```

All four fixed prerequisite commands now export a raw tar into the new private
attempt directory, then materialize it with bounded build-only tooling. Files
are created exclusively, directory modes are applied after descendants, and
runtime symlinks are created last without being traversed. Duplicate/traversing
paths, hardlinks, special files and set-id modes are refused. This preserves
protected `0555` directories without privileged local export. Staging ownership
is not installed root ownership, and raw export/staging never supplies source
admission. Strict source and role-specific inventory/package checks run afterward;
failures retain the original tar and partial staging.

The first actual staging check of the earlier `c972f02b` conductor TAR stopped
before destination creation on inherited `/var/local` mode `02775`. The pilot
image now stages that unused directory explicitly as root-owned `0755`; the
authority target inherits the correction, and the default control-plane image
is unchanged. Corrected `04cf155a` raw exports built, but staging then refused
one dangling base link: `usr/share/zoneinfo/localtime` points to absent
`/etc/localtime`. A bounded pass over all 408 links found no other resolution
failures. The pilot layout now supplies that target as a fixed link to the
genuine 114-byte `usr/share/zoneinfo/Etc/UTC` file already in the pinned image,
not host timezone data. Set-id and logical-root link checks remain unchanged.
Both corrected `7193b2a1` exports and their materializations subsequently
succeeded, observed complete by `2026-09-30T18:10:57.721Z`. This checks actual
build-output staging, not strict-source package admission or runtime execution.

The sidecar's original file-level Docker `--chmod=0444` also created unusable
implicit data directories. Its dedicated staged tree now supplies traversable
`0555` directories explicitly, with `0555` executable and `0444` companions.
The corrected `facdb895` export passed exact file/mode/source readback. Both it
and the existing `04cf155a` operator export passed bounded caller-owned
materialization by `2026-09-30T18:23:03.606Z`; their strict commands now use that
same TAR staging path before their existing role-specific inventory checks.

The inventory bounds tree depth, path length, entry count, per-file bytes and
aggregate bytes. It hashes stable regular files, refuses special files and
regular hardlinks, and resolves admitted distribution symlinks only inside the
inventoried rootfs namespace. An absolute link names that runtime root, never
the build host. Packaged application/script content must match the source
manifest. The tar uses sorted paths, root ownership and the source epoch;
the packager rechecks the inventory and copied bytes before writing completion
metadata. A failed attempt leaves its exact partial output for reconciliation,
not automatic deletion, repair or retry.

Within a separately admitted and provisioned execution root, the fixed command
is:

```text
/runtime/python/bin/python3 -I -B /app/scripts/native_pilot_runtime_entrypoint.py --run-native-pilot
```

Do **not** run this against a merely extracted build directory: the operator
still needs its genuine protected installation, root process/environment,
native executables, kernel/resource setup, independent authorities and exclusive
machine pipes. The bootstrap uses only fixed packaged import roots; it accepts
no module/path selector. The build does not install, mount, chroot into or launch
the operator. Its local archive hash is a measurement, not independent approval,
a dynamic-loader closure proof, a successful pilot or production release evidence.
The engineering raw export below has built this target; the strict package and
installed runtime remain unexecuted.

## Authority coordinator runtime package

The separate `native-pilot-authority-artifact` target reuses the exact pinned
conductor rootfs, Python/vendor closure and source manifest. It adds only the
fixed authority bootstrap, authority coordinator, runtime-inventory helper and
`scripts.authority.native_pilot_authority_io` under `/authority/app/scripts`.
It does not add files to the conductor's exact `/app/scripts` directory or
change the conductor command, inventory schema or approval requirements.

From the same strict clean-source/cache prerequisites, request a new output:

```sh
make build-native-pilot-authority-runtime \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/pilot-authority-runtime
```

This uses the same private build context, offline RUN steps and fixed per-RUN
8-CPU/24-GiB/no-swap profile, not an aggregate resource limit. It requires no
guest inputs or keys. The output contains `attempt.json`, `artifacts/`,
`package/runtime-rootfs.tar`, `package/package.json` and
`authority-runtime.json`. The separate `serverware.nativePilotAuthorityRuntime/v1`
inventory binds the complete conductor sources plus the four exact authority
script originals, retaining the existing bounded file/link/hash checks. Its
`serverware.nativePilotAuthorityPackage/v1` archive is unsigned and uses the
same sorted records, normalized root ownership, source epoch and exact readback.

The installed authority command has this fixed prefix:

```text
/runtime/python/bin/python3 -I -B /authority/app/scripts/native_pilot_authority_runtime_entrypoint.py --run-native-pilot
```

Its only additional arguments, in order, are `--runtime-inventory-fd FD`,
`--runtime-inventory-sha256 SHA256`, then repeated `--authority-key PURPOSE=FD`
for the exact source-selected `KEY_PURPOSES`. The coordinator itself validates
all purpose names and genuine protected descriptors. The inventory FD must
still hold the independently approved **conductor** inventory for the same
installed source; the authority inventory is not accepted in its place and
is never projected into conductor approval. The bootstrap admits no alternate
script, module, executable or import path.

Packaging does not provision that inventory, the sealed key FDs, independent
supervisor approval channel, protected job originals, native executables or
resource environment. No key, signature, approval, installation or live pilot
is produced. The engineering raw export below has built this target, not this
strict package or its execution environment. The actual process/signing workflow
remains separately authorized operator work.

## Operator commands

Before a live driver can start, an independently authorized provisioner uses
the [window issuer](native-pilot-window-authority.md) and
[fixed bootstrap installer](native-pilot-bootstrap-installation.md). The latter
requires the actual admitted supervisor executable and cold delivery original;
it publishes configuration/window first and control last. It does not launch the
driver or choose a new window. After real observation and C9 delivery, the
[late-runtime closure issuer](native-pilot-closure-authority.md) supplies the
existing v2 authorization for independent bridge-launch preparation. These are
separate trusted provisioner operations, not steps performed by the build tool.

The separate [authority commands](native-pilot-authority-commands.md) produce
cohort, driver, delivery and ordinary-service originals from explicitly approved
input and already provisioned keys. Their fixed public/precreation installers
are not part of artifact building. Their calls are connected by the authority
coordinator; independent supervisor approval and provisioning remain separate.
They do not approve the builder or enter the conductor runtime package.

For the full pilot commands below, use a clean committed checkout;
dirty/untracked source has no override. Check
the build filesystem and available space first, for example `findmnt -T` and
`df -h` against the NVMe workspace. Keep bulk output off root-backed `/tmp`.
Each output directory must be new, absolute, and under an existing non-symlink
parent; the tool never overwrites, cleans, repairs, or automatically retries it.

```sh
make prepare-native-pilot-build \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/pilot-build-preparation
```

This writes `preparation.json` with the exact source-manifest SHA and fixed
profiles/prerequisites. It invokes no Docker command. Preparation must precede
independent production of the guest public build inputs; it does **not** author
those inputs itself.

The independently supplied input directory must contain `inputs.json`,
`seccomp.bpf`, `runtime.json`, `build-recipe.json`, and `provenance.json`.
`inputs.json` is the existing canonical ASCII plus exactly one LF
`serverware.nativeShadowCustodyImageInputs/v1` document. Its source pin must
equal `preparation.json`'s `source.source_manifest_digest`; its four other pins
must bind the exact public originals. Both the outer copier and custody packager
require that same byte format; neither normalizes the supplied original. Its
independent full-manifest digest includes the terminal LF. Obtain the **full manifest SHA** from the
independent author, rather than treating a locally calculated hash as authority.
No launch, C9 delivery, policy secret, seed or credential belongs in this public
build directory. Only these five bounded files enter the private Docker context.

For the selected measured-bootstrap/late-runtime profile, the public
`runtime.json` is a fixed bootstrap document, not the eventual operational
runtime or C9 configuration. Produce that exact existing profile with:

```sh
python3 -B scripts/export_native_shadow_bootstrap_runtime.py \
  --out /srv/catchplate-fast/tmp/pilot-bootstrap-runtime
```

Use the resulting `runtime.json` as `--runtime` below. Its two source-fixed
fields select `serverware.nativeShadowDriverBootstrapRuntime/v1` and
`measure-final-driver-before-operational-admission`; the existing guest parser
requires those exact values. The original is canonical ASCII without a terminal
LF, unlike `inputs.json`. This avoids embedding the later image-bound runtime
into its own bootstrap image. The operational runtime, C9 bindings and signed
admissions still come from their actual independent owners after measurement.
The producer supplies no credentials, policy, signature or deployment approval;
its measured digest still needs the same independent input-manifest admission.

The seccomp input comes from an independently selected policy, not a generated
permissive default. The separate offline exporter checks the existing policy
type, recompiles its rules, verifies every claimed policy/stream/semantics hash,
and writes only the matching raw BPF bytes. After building the operator tool as
described below, invoke its actual exported path:

```sh
/srv/catchplate-fast/tmp/pilot-operator-tools/artifacts/usr/local/bin/serverware-export-custody-seccomp \
  --policy /srv/operator-guest-originals/seccomp-policy.json \
  --output /srv/operator-guest-originals/seccomp.bpf
```

Both paths must be absolute and symlink-free; the output must not exist. The
input is the existing `StructurallyVerifiedCustodySeccompPolicy` document, not a
signed closure, arbitrary BPF or new policy format. Structural validation and
reported hashes do not authenticate its author or grant permission to use it.
The exporter never changes the supplied policy, installs a filter or starts a
guest. The runtime will still enforce its independent admission checks.

Build/export this operator executable separately from a clean source snapshot
and the reviewed dependency cache:

```sh
make build-native-pilot-operator-tools \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/pilot-operator-tools
```

This invokes `scripts/build_native_pilot_artifacts.py operator-tools --out` with
the explicit new output directory. It uses strict clean-source metadata, the
unchanged verified dependency cache and a private source context. The target is
fixed to `native-pilot-operator-artifact`, with no guest inputs or caller-selected
target, policy, dependency pins or resource overrides. The existing
`native-pilot-bounded-8cpu-24g-per-step/v1` profile caps each Linux RUN step at
8 CPUs and 24 GiB with no swap; these are not aggregate limits across concurrent
stages. An unsupported resource capability fails without an unbounded fallback.

The sole executable is exported to
`pilot-operator-tools/artifacts/usr/local/bin/serverware-export-custody-seccomp`
under the selected output parent. `attempt.json` records the source and resource
profile; `operator-tools.json` is written only after the exact export inventory,
ELF header, mode, size and actual file hash checks succeed. These are unsigned
build observations, not readiness, execution or independent admission evidence.
This command has not been run as part of this source change.

The exporter is produced by the existing pinned Debian/glibc build. Run it on a
compatible Linux/amd64 operator host; this single executable export is not a
complete runtime closure. It is excluded from the default gate and measured
guest images. Producing `seccomp.bpf` does not depend on first building the image
that embeds it. Build-recipe and provenance originals still come from the
independent build owner; neither exporter manufactures them.

To package operator-owned originals against that exact clean-source preparation:

```sh
python3 -B scripts/build_native_pilot_artifacts.py public-inputs \
  --preparation /srv/catchplate-fast/tmp/pilot-build-preparation/preparation.json \
  --seccomp /srv/operator-guest-originals/seccomp.bpf \
  --runtime /srv/operator-guest-originals/runtime.json \
  --build-recipe /srv/operator-guest-originals/build-recipe.json \
  --provenance /srv/operator-guest-originals/provenance.json \
  --out /srv/catchplate-fast/tmp/pilot-public-inputs
```

All supplied originals must be bounded regular files at absolute non-symlink
paths. The command copies them unchanged, checks the existing seccomp instruction
alignment, and writes only the five expected files into a new directory. It
creates the existing canonical ASCII plus one-LF `inputs.json` from their exact
raw hashes and the preparation's source pin. It does not synthesize or approve
seccomp/runtime/policy/provenance, contact Docker, or generate keys/signatures.
`measuredPublicInputsSha256` hashes the complete written manifest including LF;
`independentPinAuthenticated:false` is explicit. Independently authenticate that
exact pin before supplying it to the build command. A local hash alone is not
approval. Existing outputs are refused; partial failure outputs are not repaired
or automatically retried.

```sh
make build-native-pilot-artifacts \
  NATIVE_PILOT_OUTPUT=/srv/catchplate-fast/tmp/pilot-built-artifacts \
  NATIVE_PILOT_PREPARATION=/srv/catchplate-fast/tmp/pilot-build-preparation/preparation.json \
  NATIVE_PILOT_PUBLIC_INPUTS=/srv/serverware-public-guest-build \
  NATIVE_PILOT_PUBLIC_INPUTS_SHA256=sha256:INDEPENDENTLY_SUPPLIED_MANIFEST_DIGEST
```

The literal placeholder is intentionally invalid. This operation, when the
operator chooses to run it, performs real offline image/artifact builds; it is
not part of source-only preparation. It rechecks the exact preparation against
the current clean snapshot, validates the existing offline dependency cache,
copies source and pinned public inputs into one private build context, builds
the two images and the aggregate export, then records real output hashes.
Private build context storage uses `TMPDIR` or the NVMe scratch directory.

Docker image and artifact build output streams directly to the command's
stderr, so the caller can retain or tee diagnostics as they arrive; stdout stays
available for the structured CLI result. A failed build reports its command and
exit code without embedding the already-streamed compiler output in an error
JSON field. Metadata, dependency verification, hashing and image inspection
keep their captured-output behavior. No automatic retry is introduced.

The two Rust build stages use a dependency-free runner compiled by the pinned
`rustc`. It runs the same `cargo build` selections with JSON diagnostics and
unchanged lint/check flags. To prevent repeated compiler warnings from consuming
BuildKit's step log allowance, each invocation displays at most eight warning
summaries of 200 characters and a final warning count. Non-warning diagnostics
retain their full rendered text, including child notes; malformed or unknown
records pass through unchanged. Cargo stderr remains live and unfiltered, and
Cargo's exit status still gates every subsequent packaging check. This bounds
compiler-warning display, not arbitrary tool output or the daemon's log cap;
it does not suppress compiler checks or claim warning-free/accepted builds.

The runner also uses the pinned Cargo 1.88 `--keep-going` option to continue
building the remaining selected targets whose dependencies can still build
after another target fails. Failed dependencies still block their dependants;
this does not add targets or retry failures. Any compilation failure retains a
nonzero exit status and blocks subsequent packaging.

Only complete assembly creates `artifacts.json` with `artifactBuildComplete:true`.
It always has `releaseAuthority:false`, `liveReady:false`,
`launchPrepared:false`, and `executionAccepted:false`. `attempt.json` and
partial build outputs survive a failure; their existence is not completion.
The local image tags are source-specific conveniences; record and admit the
actual image IDs/digests before any deployment. This manifest is unsigned build
data, not a reproducibility proof or an artifact-admission signature.

## Strict pilot build resource profile

The fixed pilot assembler selects
`native-pilot-bounded-8cpu-24g-per-step/v1` for both service image builds and the
`native-pilot-artifacts` export. It requests eight CPU equivalents, 24 GiB of
memory and no swap per Linux RUN step using the four resource arguments shown
below. Preparation, attempt and completed artifact metadata record the profile
and `aggregate_limit:false`. Concurrent steps, cache/export work and the builder
daemon are not covered by an aggregate limit.

This selection requires the unchanged clean `production-commit` source identity;
it does not enable dirty source or change dependency/public-input admission.
Unsupported builder resource capabilities must fail the build without a retry
that removes the limits. The ordinary image/artifact CLI defaults are unchanged.
The strict pilot resource connection is source implementation, not a completed
strict pilot build. Regenerate preparation after any source or reviewed-pin
commit before obtaining admission of source-bound public inputs.

## Separate engineering-only image build resource profile

The existing two-image dirty-tree builder has a separate explicit fixed resource
selection. The full pilot command and strict artifact packages still require
their clean-source profile. A separate raw-export exception is described below:

```sh
python3 -B scripts/build_production_images.py \
  --development-dirty-tree --engineering-bounded-build \
  --out /srv/catchplate-fast/tmp/engineering-images-build.json
```

`--engineering-bounded-build` requires `--development-dirty-tree`. It adds
exactly these options to both existing `docker build`
commands; it exposes no arbitrary builder arguments:

```text
--resource memory=24g --resource memory-swap=24g
--resource cpu-period=100000 --resource cpu-quota=800000
```

This requests 24 GiB memory and an equal total memory-plus-swap ceiling, with
eight CPU equivalents, **per Linux RUN step**. A BuildKit daemon supporting
`exec.meta.linux.resources` is required. These are not whole-build limits:
BuildKit may execute steps concurrently, while cache/export and daemon work
remain outside this per-step profile. Shared steps requested concurrently with
different limits can receive the more permissive limits. See the
[official Docker resource documentation](https://docs.docker.com/reference/cli/docker/buildx/build/#resource).
Unsupported resource flags/capabilities must stop the build; do not remove the
limits as an automatic fallback or create an ad-hoc privileged builder.

The two image commands remain sequential. This preparation profile was selected
for the 96-CPU host with roughly 268 GiB available memory at planning time;
those observations are not reservations. Recheck current load, available memory
and NVMe/Docker capacity before running it. No global Docker configuration,
privileged entitlement or alternative architecture is introduced.

Within the gate image, a shared `source-preparation` stage verifies the complete
source archive, file hashes/modes and locked vendor bytes before any consumer
uses them. The main glibc build, static Alpine launcher build and Python runtime
packaging consume that prepared source independently. They no longer serialize
behind the main Rust compilation merely to copy source files. Final image
assembly still requires every selected binary and runtime output; this changes
build scheduling, not acceptance checks. Concurrent steps retain separate
resource limits, not an aggregate eight-CPU/24-GiB reservation.

The glibc and musl compiler stages now start from their same exact pinned bases
and copy only verified Rust inputs, schemas, the diagnostic wrapper and required
runtime assets. The musl stage retains its exact offline APK/vendor verification.
Neither compiler inherits the full documentation/control-plane tree or unrelated
Python dependency cache. Full source-archive, content and mode verification still
precedes those copies; Python packaging and provenance keep their original full
source owner. No source file is dropped from release capture or authentication.

This separates compilation cache inputs from unrelated repository changes; it
does not promise a cache hit or a measured speedup. Matching compiler inputs and
the fixed engineering `SOURCE_DATE_EPOCH=0` can reuse existing layers. Strict
production still derives its epoch from the authenticated source commit, and a
changed epoch invalidates compilation layers, as documented in
[Docker's cache rules](https://docs.docker.com/build/cache/invalidation/).
No shared compiler cache mount, new dependency, networked build step or relaxed
production identity is introduced. This change is not part of the frozen
engineering attempt 16 source and does not trigger its restart.

The result's existing `metadata` object records
`build_resource_profile.name=engineering-bounded-8cpu-24g-per-step/v1`, the exact
resource arguments, required capability and non-aggregate scope. Source identity
remains `development-dirty-tree`, with no authenticated source commit and all
production-release eligibility false. Default production and artifact commands
remain unchanged. The existing dependency-cache verification and private
source-context copying still apply: this flag neither installs candidate pins
nor publishes or approves an unpublished dependency snapshot. Separately
authorized engineering staging may use proposed bytes in an isolated checkout;
independent review/publication, reviewed-pin commitment and the clean-source
production build/admission remain separate requirements. A successful local
build is not live readiness or production acceptance.

### Engineering-only raw prerequisite exports

Exactly four fixed Dockerfile/target pairs support the paired engineering
flags. They need no independently approved public guest inputs:

| Dockerfile | Target |
| --- | --- |
| `Dockerfile.production` | `native-pilot-conductor-artifact` |
| `Dockerfile.production` | `native-pilot-authority-artifact` |
| `data-plane/decision-gate-rs/Dockerfile.production` | `native-pilot-operator-artifact` |
| `data-plane/decision-gate-rs/Dockerfile.production` | `native-workload-sidecar-artifact` |

The operator export supplies the existing seccomp exporter, and the sidecar
export supplies the three workload-side files above. No native guest bundle,
independent Setup issuer or other artifact target is added to this exception.
From an isolated engineering checkout with explicitly staged candidate
dependency inputs:

```sh
SOURCE_DATE_EPOCH=0 python3 -B scripts/build_production_images.py \
  --development-dirty-tree --engineering-bounded-build \
  --dockerfile Dockerfile.production \
  --target native-pilot-conductor-artifact \
  --output type=tar,dest=/srv/catchplate-fast/tmp/EXISTING-JOB/conductor-rootfs.tar \
  --network none --platform linux/amd64
```

Use `native-pilot-authority-artifact` with a different fresh output for the
authority bytes. For the workload sidecar, select its exact Dockerfile pair:

```sh
SOURCE_DATE_EPOCH=0 python3 -B scripts/build_production_images.py \
  --development-dirty-tree --engineering-bounded-build \
  --dockerfile data-plane/decision-gate-rs/Dockerfile.production \
  --target native-workload-sidecar-artifact \
  --output type=tar,dest=/srv/catchplate-fast/tmp/EXISTING-JOB/workload-sidecar.tar \
  --network none --platform linux/amd64
```

Use `native-pilot-operator-artifact` in that same gate Dockerfile with a separate
new output for the operator tool. This tool is dynamically linked and still
requires its documented compatible runtime; raw export does not create a
standalone runtime closure. Wrong Dockerfile/target pairs, unpaired engineering
flags and supplied guest inputs fail closed.

The exact absolute destination must not exist, and its private
task-owned parent must already exist without symlink traversal. The builder
reserves the new tar file exclusively at `0600`; partial output remains after
failure. No automatic repair/retry is provided.

[Docker's tar exporter](https://docs.docker.com/build/exporters/local-tar/)
bundles the same root filesystem instead of writing each child into a local
directory. This avoids the observed unprivileged local-export failure inside
the runtime's protected `0555` directories, without changing their final modes.
The same engineering targets also accept `type=local,dest=...` with a fresh
directory, but exporting this protected tree that way requires a suitably
privileged build client. No automatic elevation or permission relaxation occurs.

All four targets retain source-context/cache verification, network-disabled build
steps and the same fixed per-step resources. Their output explicitly reports
`identity_mode=development-dirty-tree`, `production_release_eligible=false` and
`raw_artifact_export_only=true`. These raw archives/trees are not strict inventories or
packages and must not be passed to runtime admission or installed as an approved
pilot. The strict inventory/package tools still reject this engineering source
identity. Canonical reviewed dependency pins remain unchanged.

Both corrected engineering tar exports completed from frozen source `c972f02b`, using the
unchanged `v3-candidate-cba01916` in an isolated checkout. The conductor and
authority wrappers exited zero, both observed complete by
`2026-09-30T17:37:44Z`; their reports retain all three non-release/raw-only flags
above. The first local-export attempt at `7582114d` completed assembly but failed
on the protected directory mode; that partial attempt remains separate evidence.
The first tar pair at `9939bf1e` exposed an implicit COPY destination with mode
`0755` instead of `0555`. Copying an explicit staged directory fixes that defect;
targeted readback of the corrected pair confirms the authority directory modes,
four exact authority scripts, unchanged two-script conductor layout and common
engineering source manifest. This is not whole-runtime or pilot acceptance.
No runtime extraction, installation, execution, signing or cloud operation ran.

## Live preparation remains with the genuine owners

The latest consolidated engineering attempt (16) successfully built both images
from source `172f6b4e42f552ced2aacdb582791e80d28dfc62`, including the native trust
and retained-publication recovery batch. It used the unchanged unpublished
`v3-candidate-cba01916` dependencies in an isolated engineering checkout. All
five previously pinned base images had to be restored at their exact Linux/amd64
digests before the sole build invocation; no base or dependency pin changed.

Session `55371` ran from `2026-09-30T13:40:45.948312895Z` to
`2026-09-30T13:53:29.136143417Z` and exited 0. Glibc completed in 9m26s followed
by the build-internal ledger initialization; static musl completed in 10m47s.
The broker, role-key provisioner and shadow-key delivery Python packages also
completed. Actual worker observations confirm the same per-RUN 8-CPU, 24-GiB,
no-swap bounds, not an aggregate build limit.

- Control: `sha256:3d4a50b5714d53454409975cfd017cd2de2899afb89d44ea4c43b96ab84d5735`
- Gate: `sha256:3c9b2f2fa56d727c293534e88ad911ce503cefd118f7c48803b42d123eb6d2b3`

The final report records `ok:true`, `no_shell.ok:true`,
`identity_mode:development-dirty-tree` and `production_release_eligible:false`.
Original outputs, invocation, cache restoration, resource observations and the
bounded result summary are retained with verified hashes under
`codex-offload/serverware/engineering-builds/172f6b4e-uessyy`. The report SHA-256
is `bdf6db64b432b4f29d51b40ae6abfb85143561a87eb287eb787ba9e9cb30f366`.
Stopped-container packaging checks are not project tests or a deployed pilot.
The later `b6087f5d` compiler-input isolation is not included in this result and
has not been built or benchmarked. No further build is implied by a status update.

The preceding engineering attempt (15) used the pushed single-bridge
source `d865eeb80f4ce72cd5b73fab0ca2472b939d451e` and the same unchanged
unpublished candidate in an isolated checkout. Session `49282` ran from
`2026-09-30T12:59:42.075602505Z` to `2026-09-30T13:06:02.035699165Z`, exiting 1.
The control image completed as
`sha256:a7cc2c0143fdb75c90b658c58d4c59c50810b9ea338b984a3cf2825e5ee10580`.
The gate's glibc build exited 101 with one unique `E0412`: the new driver-binding
module lacked the `ExpectedPeerCredentialV3` import. That error appeared in
12 target diagnostics; its import is now corrected in source. The concurrent
musl step was canceled, not successful. There is no completed gate image or
final two-image report for that attempt. The correction was subsequently
compiled successfully in attempt 16.

The full log, exact command/source selection, diagnostic index and worker-limit
observations are retained under
`codex-offload/serverware/engineering-builds/d865eeb8-suhpli` with a verified
`SHA256SUMS` manifest. Both sampled Rust workers had the selected 8-CPU,
24-GiB, no-swap limits; those limits remain per RUN, not aggregate. No broad
test suite, pilot launch, cloud provisioning or automatic retry ran. Attempt 16
followed the connected implementation batch, not each individual edit.

Engineering attempt 14 built both images successfully from exact source
`253730f074040392fbf0d50a1c4924b620a9c341`, using the unchanged, unpublished
`v3-candidate-cba01916` dependencies in an isolated dirty-tree checkout. Job
`TvtSws`, session `75570`, exited 0 at `2026-09-30T12:18:38.961286509Z`.
The glibc compilation completed in 9m29s and the actual ledger initialization
completed; static Alpine/musl compilation completed in 10m48s. All three fixed
Python runtime packages completed: broker, role-key provisioner and shadow-key
delivery.

The resulting local engineering image IDs are:

- Control: `sha256:7fbf263162b76400db42050c46bdf620f0131a98c92095bd8f9bd778360798df`
- Gate: `sha256:0ffaa7a3d91faf6ddb50ffea443d7f424675ed6ad45bc663e047b83773c3aa52`

Retained `build.log`, original `images-build.json` and concise
`build-summary.json` are under
`codex-offload/serverware/engineering-builds/253730f0-tvtsws`.
The final `serverware.productionImagesBuild/v2` report records
`identity_mode:development-dirty-tree`, `ok:true`, `no_shell.ok:true` and
`production_release_eligible:false`. The existing stopped-container ELF and
no-shell checks passed; they are not a project test suite or live pilot evidence.
Prior attempt 13's failed diagnostics remain separately retained under
`codex-offload/serverware/engineering-builds/de80246e-h5r8bz`.

These source-built images are not an assembled, deployed or testable native
pilot. Remaining artifact assembly, independently admitted public inputs,
provisioning and connected pilot acceptance are still required. Broad tests
remain deferred. Canonical reviewed dependency pins, independent admission
requirements and the nonrelease boundary are unchanged; production acceptance
remains **0/6 verified**.

The source-fixed prerequisite list points at the actual conductor command:

```sh
python3 -B scripts/run_native_pilot.py --run-native-pilot
```

This is a privileged live launch, not another build/preparation command. It must
be started by a separately operated coordinator with exclusive machine pipes
for stdin/stdout, real root credentials, protected source/runtime and the
independently provisioned services and originals below. An interactive terminal,
regular-file redirection or an invented reply cannot substitute for that setup.
The build script never invokes this command.

The conductor calls `NativePilotLaunch.start`, then `start_endpoints`,
`prepare_resources`, `prepare_bridge_connections`, `prepare_operational_inputs`
and `release`. Those retain the real `DriverBootstrap`, endpoint-only
`ParkedProofCohort.start_for_driver`, `FiveServiceLaunch.start_effects`, business,
spool, endpoint-listener, bridge-resource and operational-input owners. It does
not reconstruct private owners from JSON or load independent signing keys.

The coordinator must implement eleven one-shot phases in exactly this order:
`bootstrap-admission`, `endpoint-precreation`, `endpoint-inputs`,
`endpoint-deliveries`, `service-originals`, `bridge-runtime`, `bridge-delivery`, `release`,
`constructed-admission`, `generation-origin`, `shutdown`. Requests use
`serverware.nativePilotOperatorRequest/v1` with `sequence`, `phase`, public
`payload` and decimal-string `deadlineBoottimeNs`; replies use
`serverware.nativePilotOperatorReply/v1` with the same sequence/phase,
`requestSha256` of the exact canonical request excluding LF, and phase-specific
`inputs`. Frames are canonical ASCII JSON plus one LF, bounded to 32 MiB each
and 128 MiB total in both directions. The retained owners still validate every
supplied original; pipe framing is not authorization.

The first nine exchanges use the minimum actual original startup deadline.
The final two use the minimum actual lifetime minus the maximum original
driver/production cleanup reserve; the generation-origin relay is clipped to
that same bound. There are no renewed human pauses, heartbeats or retries.
`generation-origin` accepts only the request to observe the installed generation,
not an uploaded success verdict. `shutdown` supplies the actual origin handoff
and accepts exactly `{"action":"stop"}`. The original bounded interval can be
used for external pilot work before stop; neither the handoff nor the command
claims that testing passed. Final bounded status goes to stderr, while stdout
remains solely the phase protocol. Cleanup uncertainty retains the actual owner
graph rather than retrying or claiming retirement.

The separate [coordinator process owner](native-pilot-coordinator.md) verifies
the installed runtime inventory, launches the fixed conductor and relays its
exact requests to an independently operated supervisor. It owns the actual
process/pipes; it does not make approval decisions or provide signing keys.

The seccomp operator and native guest targets remain distinct from the separate
[conductor runtime package](#conductor-runtime-package). None implements the
remaining independent authority automation. Protected installation, independently
provisioned services and connected pilot acceptance remain open prerequisites,
not local build outputs.

The [live composition](native-pilot-launch.md) uses an explicit endpoint-only
cohort bound to the retained measured driver, with separate genuine cleanup
owners. The existing fixed-eleven cohort owns a different parked bridge and is
not combined with `DriverBootstrap`. Configuration/v7 and its signed precreation
are supplied after the real driver observation exists, under the unchanged
startup deadline. Existing fixed-eleven behavior and peer checks stay unchanged.
This source connection is not a tested launch or a testable pilot.

An independently authorized operator must supply and retain the protected
cohort/ordinary/driver configurations, current signed histories and assignments,
exact public runtime/image pins, real resource descriptors, separately assigned
key custody, trust/revocation/checkpoints, time and external verifier owners,
and protected control-plane/OIDC/WebAuthn configuration. Actual post-create
PIDFD/start/executable observations and post-drop driver/peer measurements must
exist **before** the independent next-stage signatures. Static installation
files cannot predetermine those identities or renew their deadlines.

The actual `FiveServiceLaunch.release_endpoint_cohort` checks the complete ordinary
five-service listening state, the same measured driver and exact effects-selected
grants before one-shot endpoint release and driver continuation. Keep every resource/process owner alive through the original
serving interval and its real terminal/reap cleanup. Do not replace this caller
with shell background processes, numeric PID lists, a generated Compose file,
or a new generic launcher. The [existing effects guide](native-shadow-effects-cohort.md)
and [driver lifecycle](native-shadow-driver-lifecycle.md) describe those owners.

## Independent issuers are separate installations

No Setup hardware/proxy/final issuer, time issuer, generation-origin issuer or
external verifier is copied into the claimant bundle. The existing artifact
build CLI now admits their fixed-purpose targets explicitly. For example,
after that target is present in the admitted source:

```sh
python3 scripts/build_production_images.py --network=none --platform linux/amd64 \
  --dockerfile data-plane/decision-gate-rs/Dockerfile.production \
  --target native-setup-hardware-artifact \
  --output type=local,dest=/srv/catchplate-fast/tmp/independent-setup-hardware
```

Proxy/final use `native-setup-proxy-artifact` and `native-setup-final-artifact`.
Their separately installed protected adapters/supervisors retain the actual
configuration/seed/request FDs and original lifetime. The existing time/origin
and external-verifier supervisor/runtime targets are likewise separately
allowlisted. This build connection creates no policy, key, signed provisioning
approval, live authority or credential delivery. Independent installation and
the connected build/runtime pilot gate remain required.
