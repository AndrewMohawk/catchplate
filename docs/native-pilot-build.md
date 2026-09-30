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

Use a clean committed checkout. Dirty/untracked source has no override. Check
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
`inputs.json` is the existing canonical no-newline
`serverware.nativeShadowCustodyImageInputs/v1` document. Its source pin must
equal `preparation.json`'s `source.source_manifest_digest`; its four other pins
must bind the exact public originals. Obtain the **full manifest SHA** from the
independent author, rather than treating a locally calculated hash as authority.
No launch, C9 delivery, policy secret, seed or credential belongs in this public
build directory. Only these five bounded files enter the private Docker context.

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

Only complete assembly creates `artifacts.json` with `artifactBuildComplete:true`.
It always has `releaseAuthority:false`, `liveReady:false`,
`launchPrepared:false`, and `executionAccepted:false`. `attempt.json` and
partial build outputs survive a failure; their existence is not completion.
The local image tags are source-specific conveniences; record and admit the
actual image IDs/digests before any deployment. This manifest is unsigned build
data, not a reproducibility proof or an artifact-admission signature.

## Live preparation remains with the genuine owners

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
