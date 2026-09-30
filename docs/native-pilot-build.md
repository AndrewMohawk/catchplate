> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Native pilot build and launch preparation

This is an executable **build** entrypoint, not a launch/readiness command. It
assembles the real control-plane/gate images and the native guest/cohort
artifacts from one clean committed source snapshot. It does not create keys,
sign grants, install files, start services, contact providers, or replace any
independent authority with a local manifest. No build or runtime acceptance was
performed when this source was authored.

## Existing build owners, explicit profile

`scripts/build_native_pilot_artifacts.py` calls the existing
`build_production_images.py` source/archive, dependency-cache, private-context,
image and artifact build owners. The Docker targets use their existing pinned
base images, locked offline wheels/Cargo vendor, and `--network=none` build
steps. No dependency fetch is invoked. The build host/operator must provision
the exact base images and builder/cache beforehand; `--network=none` is not a
claim that an independently configured BuildKit daemon cannot access a registry.

The fixed selection is the actual eleven-child cohort configuration/v6,
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

## Operator commands

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

## Separate engineering-only image build resource profile

The existing two-image dirty-tree builder has an explicit fixed resource
selection. It does not apply to the full pilot command or any artifact export:

```sh
python3 -B scripts/build_production_images.py \
  --development-dirty-tree --engineering-bounded-build \
  --out /srv/catchplate-fast/tmp/engineering-images-build.json
```

`--engineering-bounded-build` requires `--development-dirty-tree` and refuses
artifact mode. It adds exactly these options to both existing `docker build`
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

## Live preparation remains with the genuine owners

Engineering attempt 7 on 2026-09-30 used source `269ad88f` and the unchanged,
unpublished `v3-candidate-cba01916` dependencies in an isolated dirty-tree
checkout. It built the nonrelease Linux/amd64 control image
`sha256:3081c142885e57060cbe2f5a6c13c8fe3fed0c9e1d62c41fbc67898192620ec4`.
The main glibc Cargo build completed successfully in 9m03s, and the actual custody
ledger initializer ran. The runner reduced 30,170 compiler warnings to eight
bounded summaries and a count without clipping. This attempt predates the
runner's `--keep-going` change.

Assembly then stopped with exit 127 (`tar: not found`) immediately after the
verified Debian packages were extracted onto the pinned Python image's root.
The base contains tar and a merged-`/usr` layout; the liblzo archive contains a
real `lib` directory. A loader-path collision is the supported diagnosis, not
an independently reproduced failure. The next build stages both verified
packages separately and installs only `mksquashfs`, the real liblzo library and
its SONAME link under `/usr`, preserving the base's directory symlinks. No
package hashes, base pins, offline constraints or dependency checks change.
One disposable, network-disabled probe of that corrected installation in the
exact pinned base passed: both package hashes matched, tar and mksquashfs
launched, shared libraries resolved and `/lib` links remained unchanged. This
checked only the packaging blocker, not project behavior or full image assembly.
The static Alpine launcher Cargo build was not reached in attempt 7.
Retained evidence is under
`codex-offload/serverware/engineering-builds/269ad88f-pfw5lv`.
There is no gate image, complete two-image report, project test result,
service deployment or pilot acceptance from this attempt. Canonical reviewed
dependency pins and the nonrelease boundary remain unchanged.

Earlier attempts stopped at 18 library errors, then 95 distinct diagnostics
across 53 files, then 32 distinct diagnostics across 19 files, then five errors,
then one filesystem-comparison type error in attempt 6.
Attempt 5 stopped before Rust when BuildKit could not materialize a pinned base;
all five exact base-image references were subsequently found missing and restored
without changing their digests. Their removal cause is unproven; separate
failure and recovery evidence is retained under
`codex-offload/serverware/engineering-builds/abdca80f-ouzbia`.
Attempt 6's actual RUN-worker limits were
`cpu.max=800000 100000`, `memory.max=25769803776` and `memory.swap.max=0`;
these observations are not aggregate limits across concurrent workers.

The source-fixed prerequisite list points at the actual existing callers:
`ParkedProofCohort.start`, `FiveServiceLaunch.start_effects`,
`GenerationInputs.prepare`, `SpoolInputs.prepare`, `DriverBootstrap.start`,
and `OperationalInputs.prepare_outgoing`. These require genuine privileged
owners and separately provisioned originals; this build script does not call
them and does not serialize fake substitutes for their private types.

An independently authorized operator must supply and retain the protected
cohort/ordinary/driver configurations, current signed histories and assignments,
exact public runtime/image pins, real resource descriptors, separately assigned
key custody, trust/revocation/checkpoints, time and external verifier owners,
and protected control-plane/OIDC/WebAuthn configuration. Actual post-create
PIDFD/start/executable observations and post-drop driver/peer measurements must
exist **before** the independent next-stage signatures. Static installation
files cannot predetermine those identities or renew their deadlines.

The actual `FiveServiceLaunch.release_proof_cohort` checks the complete ordinary
five-service listening state and exact effects-selected grants before one-shot
native release. Keep every resource/process owner alive through the original
serving interval and its real terminal/reap cleanup. Do not replace this caller
with shell background processes, numeric PID lists, a generated Compose file,
or a new generic launcher. The paired [eleven-child guide](native-shadow-effects-cohort.md)
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
