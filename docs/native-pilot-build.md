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

The fixed selection is the ten-endpoint cohort configuration/v7 paired with
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
and writes only the matching raw BPF bytes:

```sh
serverware-export-custody-seccomp \
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
python3 -B scripts/build_production_images.py \
  --dockerfile data-plane/decision-gate-rs/Dockerfile.production \
  --target native-pilot-operator-artifact --network none \
  --output type=local,dest=/srv/catchplate-fast/tmp/pilot-operator-tools
```

The export contains `usr/local/bin/serverware-export-custody-seccomp`, produced
by the existing pinned Debian/glibc build. Run it on a compatible Linux/amd64
operator host; this single executable export is not a complete runtime closure.
It is excluded from the default gate and measured guest images. This build does
not need public guest inputs, so producing `seccomp.bpf` does not depend on first
building the image that embeds it. Build-recipe and provenance originals still
come from the independent build owner; neither exporter manufactures them.

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
selection. This engineering flag is unavailable to the full pilot command and
artifact exports; their fixed pilot selection is described above:

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

The source-fixed prerequisite list points at the actual existing callers:
`NativePilotLaunch.start`, `ParkedProofCohort.start_for_driver`,
`FiveServiceLaunch.start_effects`,
`BusinessResources.prepare_commitment(five).commitment_inputs()`,
`SpoolInputs.prepare`, `DriverBootstrap.start`,
and `OperationalInputs.prepare_outgoing`. These require genuine privileged
owners and separately provisioned originals; this build script does not call
them and does not serialize fake substitutes for their private types.

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
