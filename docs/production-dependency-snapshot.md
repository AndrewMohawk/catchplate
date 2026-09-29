> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Preparing an unpublished dependency snapshot

`production-dependencies/prepare_snapshot.py` creates a real candidate wheelhouse
from the exact committed `requirements.lock`, checks offline installation, and
carries forward only the unchanged, digest-verified Rust and broker-tool artifacts. It never
publishes a snapshot, changes the checkout's reviewed manifests, or grants release
authority. Its result is local engineering evidence awaiting dependency-owner
review.

The current lock pins `cryptography==50.0.0`; the Python manifest still refers
to the old lock and archive. The v2 snapshot identity now reserves the additional
broker packaging inputs; it is not evidence that a v2 snapshot exists. Updating
the identity or manifest without producing and reviewing new wheel bytes does
not resolve the handoff requirement.

## Preconditions

Freeze a clean commit containing the producer and its reviewed changes first.
The producer records and rechecks the full commit/tree identity, source input
bytes, and its own code. Its pinned Python image must match the production
`python-deps` Dockerfile stage and must already be available as Linux/amd64. Run
as an unprivileged operator on an approved preparation host with Docker access.
This tool does not provision the restricted Coder controller or give a workload
a host Docker socket.

Use a new candidate directory on NVMe outside the checkout. The tool requires
4 GiB free and refuses existing outputs, checkout descendants, and root-backed
`/tmp`. Its two fixed containers each have one CPU, 2 GiB memory, 128 PIDs, a
read-only root, no capabilities, no new privileges, and a 1400-second deadline.
Bulky downloads, unpacking, and installation use a bounded 1536 MiB container
tmpfs; only archives, logs, and reports persist on the selected filesystem.

The existing cache can supply the three reviewed Rust inputs:

```text
/home/catchplate/codex-offload/serverware/current/production-dependencies/cache
```

The directory's location and filenames do not prove integrity. The producer
checks copied bytes against the current committed Rust manifest before starting
network work, verifies the Cargo archive structure, and rejects changed Cargo
inputs. It never reads or reuses that directory's Python wheelhouse. That input
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

snapshot_workdir="$(mktemp -d /srv/catchplate-fast/tmp/serverware-dependency-candidate.XXXXXX)"
python3 -B production-dependencies/prepare_snapshot.py \
  --expected-commit '<full-frozen-commit-id>' \
  --existing-cache /home/catchplate/codex-offload/serverware/current/production-dependencies/cache \
  --snapshot-id serverware-production-dependencies-linux-amd64-v3 \
  --output "$snapshot_workdir/candidate"
```

Only the download container has networking. Its fixed pip command uses the public
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

All three proposed manifests identify the same new snapshot. Rust and broker-tool hashes remain the
reviewed values; the Python descriptor binds the captured lock and newly created
archive. Before reporting success, the normal dependency verifier checks the
complete staged snapshot. The report records builder image identity, source
commit/tree, captured input hashes, wheel inventory, offline validation, carried
artifact hashes, and all proposed manifest hashes. `published`,
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
