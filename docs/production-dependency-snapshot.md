> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Preparing an unpublished dependency snapshot

`production-dependencies/prepare_snapshot.py` prepares an unpublished candidate
from the exact committed Python and Rust locks. It creates the Python wheelhouse
and checks offline installation. With `--refresh-rust`, it also creates a new
locked Cargo vendor archive; without that flag, Rust inputs must be unchanged
and the existing reviewed archive is carried forward. Broker packaging tools
and musl inputs always retain their reviewed hashes. The producer never
publishes a snapshot, changes the checkout's reviewed manifests, or grants release
authority. Its result is local engineering evidence awaiting dependency-owner
review.

The current lock pins `cryptography==50.0.0`; the Python manifest still refers
to the old lock and archive. The committed Cargo inputs also differ from the
reviewed Rust manifest, so the current source requires `--refresh-rust` and a
new reviewed vendor archive before an offline build. The v2 snapshot identity reserves the additional
broker packaging inputs; it is not evidence that a v2 snapshot exists. Updating
the identity or manifest without producing and reviewing new wheel bytes does
not resolve the handoff requirement.

## Current candidate evidence

Candidate `serverware-production-dependencies-linux-amd64-v3-candidate-cba01916`
was prepared successfully from source commit
`cba01916ef4353e92fa5c3ee56396eab1c6a5951`: **245 Rust crates and 31 Python
wheels**. It remains **unpublished and unreviewed**; canonical reviewed dependency
pins are unchanged.

| Artifact, relative to the candidate | Bytes | SHA-256 |
| --- | ---: | --- |
| `snapshot/cache/cargo-vendor.tar.gz` | 38,696,173 | `46f1084925158fae9eb240aac23451892a494e900b144d536dc75297ba5eaea0` |
| `snapshot/cache/python-wheelhouse-linux-amd64.tar.gz` | 19,032,896 | `5769273bdb18eec0b83768eb04e25decf018ef2cd9187126ee5f98a013fb6406` |

`candidate-report.json` has SHA-256
`38b4ea78b2ab07faa68e3193087d33072998bddb9dd404e9b5fd9e6fe6f37a00`.
The retained layout includes the three proposed manifests under `snapshot/`,
six artifacts under `snapshot/cache/`, captured `requirements.lock` and
`data-plane/decision-gate-rs/{Cargo.toml,Cargo.lock}`, and bounded phase
invocations, logs, and complete inventories under `work/`.

Rust crate checksums match the original lock; every selected file matches its
locked archive, and actual vendor files equal the selected map plus generated
checksum manifests. The pinned Cargo invocation owns selection; 737 omitted
archive filenames are recorded, not independently approved. Python wheel hashes
and inventory match the original lock. Deterministic packaging and offline
Python installation (31 packages, no network, `pip check`) were intrinsic
preparation checks, **not a project test suite or production acceptance**.

This candidate may be staged for an engineering-only build in an isolated dirty
worktree. Such staging never authorizes a production build, publication, or
reviewed-pin installation; those still require the dependency-owner handoff.

A later engineering build may reuse these exact candidate bytes after the
reviewed Dockerfile changes for bounded Cargo diagnostics and staged offline
Debian-package installation. The latter preserves the base's merged-`/usr`
layout and installs only the already-pinned build tool and liblzo files; it does
not introduce a new package or dependency source. The hashes of
`requirements.lock`, `Cargo.toml`, `Cargo.lock`, and all six cache artifacts,
the pinned base images, and the dependency-verification steps must remain
unchanged; existing manifest and archive checks still apply. Preserve the
original candidate, report, and proposed manifests unchanged. Record the exact
Dockerfile drift (including installation semantics, not just logging) and its
review in **new build evidence**, and capture the new
build source identity. The report's eleven captured inputs remain preparation
provenance, not a claim that the later source is identical. This requires no
candidate regeneration or rebinding and grants no production approval.

## Preconditions

Freeze a clean commit containing the producer and its reviewed changes first.
The producer records and rechecks the full commit/tree identity, source input
bytes, and its own code. Its pinned Python image must match the production
`python-deps` Dockerfile stage and must already be available as Linux/amd64.
Rust refresh additionally requires the exact pinned Rust build image from the
data-plane Dockerfile to be present locally. Neither producer pulls images. Run
as an unprivileged operator on an approved preparation host with Docker access.
This tool does not provision the restricted Coder controller or give a workload
a host Docker socket.

Use a new candidate directory on NVMe outside the checkout. The tool requires
4 GiB free and refuses existing outputs, checkout descendants, and root-backed
`/tmp`. It creates the candidate and each input/work/cache ancestor with explicit
owner-only mode `0700`, independent of a permissive operator umask. It never
repairs or adopts a failed candidate directory; a corrected invocation uses a
new task-specific output. Its two fixed Python containers each have one CPU, 2 GiB memory, 128 PIDs, a
read-only root, no capabilities, no new privileges, and a 1400-second deadline.
Bulky downloads, unpacking, and installation use a bounded 1536 MiB container
tmpfs; only archives, logs, and reports persist on the selected filesystem.

The existing cache supplies the reviewed musl and broker-tool inputs. When Rust
refresh is omitted, it must also supply the unchanged reviewed vendor archive:

```text
/home/catchplate/codex-offload/serverware/current/production-dependencies/cache
```

The directory's location and filenames do not prove integrity. The producer
checks copied bytes against the current committed manifests before starting
network work. By default it verifies the old Cargo archive and rejects changed
Cargo inputs; `--refresh-rust` skips that archive entirely and obtains the exact
locked crates in a separate bounded preparation container. It never reads or
reuses that directory's Python wheelhouse. That input
directory must also supply the exact `squashfs-tools_4.5.1-1_amd64.deb` and
`liblzo2-2_2.10-2_amd64.deb` bytes named by the new broker manifest. The
dependency owner acquires those from Debian before candidate preparation;
the producer only copies and verifies them, never installs them on the host.
Their primary hash records are the Debian
[SquashFS download page](https://packages.debian.org/bookworm/amd64/squashfs-tools/download)
and [LZO download page](https://packages.debian.org/bookworm/amd64/liblzo2-2/download).

## Preparation

These are preparation commands, to run after source review and outside an active
expensive build phase. Replace the example commit with the new frozen commit
containing this tool. Snapshot IDs must be new; the suggested v3 ID is valid only
if the dependency owner has not already assigned it.

```bash
findmnt -T /srv/catchplate-fast/tmp
df -h /srv/catchplate-fast/tmp
test -z "$(git status --porcelain)"
git rev-parse 'HEAD^{commit}'
git rev-parse 'HEAD^{tree}'

docker pull --platform linux/amd64 \
  python:3.11-slim-bookworm@sha256:0030323c9ce4d6dfab5f0812577cb0abd13c806f86b3a1f5b5d8f200ebb1421c
docker pull --platform linux/amd64 \
  rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89

snapshot_workdir="$(mktemp -d /srv/catchplate-fast/tmp/serverware-dependency-candidate.XXXXXX)"
python3 -B production-dependencies/prepare_snapshot.py \
  --expected-commit '<full-frozen-commit-id>' \
  --existing-cache /home/catchplate/codex-offload/serverware/current/production-dependencies/cache \
  --snapshot-id serverware-production-dependencies-linux-amd64-v3 \
  --refresh-rust \
  --output "$snapshot_workdir/candidate"
```

Only the dependency-download phases have networking. The Python download
container's fixed pip command uses the public
PyPI index, exact hashes, binary wheels, no cache, and no inherited pip settings.
The producer rejects unpinned requirements, URLs, index overrides, missing or
extra wheel packages, unexpected versions, and wheel bytes absent from the lock.
Each wheel is bounded to 256 MiB, and the complete wheelhouse to 512 MiB.

The verification container has `--network=none`. It installs from the candidate
archive with `--no-index --only-binary=:all: --require-hashes`, compares the
installed inventory with the committed lock, runs `pip check`, and imports the
locked cryptography package and its Rust extension. Wheel tar entries have fixed
ordering, ownership, modes, and timestamps; the gzip header has no filename and a
zero timestamp. A second packaging pass must produce the same archive digest.

Both phases keep download/unpack scratch on an explicit `noexec,nosuid,nodev`
`/tmp` tmpfs. Only the offline verification container receives a separate
`/installed` executable tmpfs, needed to load installed native extensions. It
uses that same directory for pip installation, inventory checks, and imports.
Verification splits the 1536 MiB tmpfs budget into 1024 MiB for `/tmp` and 512 MiB
for `/installed`; download keeps the full 1536 MiB on `/tmp`. Both containers
retain the 2 GiB memory limit, disabled extra swap, and one-CPU/PID/time bounds.

Rust refresh uses `cargo vendor --locked --versioned-dirs` from the captured
Cargo inputs. The [Cargo vendor command](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
supports this locked, versioned directory output without compiling the project.
The producer accepts only the locked crates.io package set, checks the package
checksums and vendored file hashes, and packages the verified files with fixed
ordering and normalized archive metadata. It does not run project builds,
dependency build scripts, or tests, and does not read host Cargo credentials or
mount the repository's unrelated files. The ordinary archive verifier then
checks the resulting candidate against the newly measured digest. These local
integrity checks do not replace dependency-owner review or an actual build.

The pinned Cargo producer owns package-file selection. Every selected file must
match bytes in its hash-verified original crate archive, and the actual vendor
files must exactly match that selected checksum map plus Cargo's generated
checksum manifest. Archive files omitted by Cargo are recorded by exact name
in the candidate inventory, not silently treated as missing or reimplemented
through a second include/exclude matcher. This proves the selected bytes' local
integrity; it is not independent evidence of complete or appropriate selection.

The Rust refresh helper additionally requires 12 GiB free before starting. Its
fixed downloader has one CPU, 5 GiB memory, 64 PIDs and separate 2 GiB tmpfs
limits for Cargo's cache and vendor output. No host-writable directory is
mounted into it. A capped 4 GiB transfer is verified and unpacked offline; the
verified vendor tree is limited to 2 GiB and the final archive to 1 GiB, under
the existing 250,000-member ceiling and an original 1500-second allowance.
These are preparation limits, not extra permissions for project execution.

## Candidate output and review

```text
candidate/
  candidate-report.json
  requirements.lock
  data-plane/decision-gate-rs/Cargo.toml
  data-plane/decision-gate-rs/Cargo.lock
  inputs/requirements.lock
  work/                  # preparation logs and container results
  snapshot/
    python-linux-amd64.sha256
    rust-linux-amd64.sha256
    native-broker-linux-amd64.sha256
    cache/
      python-wheelhouse-linux-amd64.tar.gz
      cargo-vendor.tar.gz
      musl-1.2.5-r12.apk
      musl-dev-1.2.5-r12.apk
      squashfs-tools_4.5.1-1_amd64.deb
      liblzo2-2_2.10-2_amd64.deb
```

All three proposed manifests identify the same new snapshot. Musl and broker-tool
hashes remain the reviewed values; the Python descriptor binds the captured lock
and newly created archive. With Rust refresh, the Rust descriptor binds the
captured Cargo inputs and the newly measured vendor archive; without it, all
Rust hashes remain unchanged. Before reporting success, the normal dependency verifier checks the
complete staged snapshot. The report records builder image identity, source
commit/tree, captured input hashes, wheel inventory, offline validation, carried
artifact hashes, Rust preparation mode and inventory when refreshed, and all
proposed manifest hashes. `published`,
`reviewed_pins_installed`, and `production_release_authority` remain `false` even
on success.

A failed run retains its task-specific partial directory and a failed report
for diagnosis. Do not reuse that directory as a successful candidate. Client
timeouts attempt to remove only the exact randomly named task container; the
container also has its own deadline. Its exact name and fixed command are
recorded in `work/<phase>-invocation.json` before startup. Daemon or host failure
can still require the operator to check that exact container before removing
task scratch.

The dependency-release owner must review the evidence, publish only the approved
`snapshot/` contents at a new credential-free immutable HTTPS prefix, verify the
published artifact bytes, and separately commit the reviewed manifest changes to
`main`. The producer does none of those steps. Co-located report hashes are local
integrity evidence and do not establish an independently authenticated release.

Retain approved artifacts and evidence outside disposable scratch before cleanup.
Then the ordinary handoff can fetch that reviewed immutable snapshot and perform
offline production builds. No production build needs network access to resolve
Python packages.

## Focused source tests

The prepared no-build verification lane can run:

```bash
python3 -B scripts/test_prepare_dependency_snapshot.py
```

The tests use small synthetic wheel/archive fixtures and mocked container
execution. They cover pin enforcement, inventory closure, deterministic
packaging, fixed container boundaries, cleanup, unchanged Rust carryforward,
failed-validation behavior, and unchanged reviewed manifests. They do not create
an installable release wheelhouse or prove an actual container installation;
only a successful real preparation run supplies that evidence.
