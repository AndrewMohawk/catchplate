> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Native pilot startup cost

This describes the native pilot, not a browser reload of the operator demo.

## Observed on 2026-10-10

R97 accepted Start at 20:47:53.167 UTC. Its first live log timestamp was
20:47:55.077 UTC: about 1.9 seconds later. The initial host checksum and
dependency checks therefore do not explain the subsequent minutes of startup.
The retained Rust result records no new compilation on Start.

Startup still constructs a fresh, session-bound package and installs it. Source
inspection found an initial static-file hashing pass, then five complete
finalized-tree measurement passes in the same Python process. Installation
separately copies and hashes source files, rereads and hashes installed files,
enables fs-verity, and synchronizes them. Later launch authorization also has
measurable cost: observed per-role input acquisition, issuer acquisition, and
publication were approximately 17, 13, and 20 seconds respectively.

The unchanged R97 attempt reached `REGISTRATION_START_BROWSER_READY` at
21:11:02 UTC, about 23 minutes after Start. This is registration readiness,
not completed enrollment or an optimized-startup measurement.

The seven logged launch triplets total about 346 seconds: 116 seconds acquiring
inputs, 87 seconds acquiring issuers, and 143 seconds publishing. Installation
phase markers do not include individual timestamps, so the log cannot apportion
the remaining startup time. The 127-second guard aggregate is nested in other
stages and must not be added to their durations.

These are distinct costs. A count of repeated hash passes is not a measurement
of how much wall-clock time each pass consumes.

## First optimization: reuse sealed-content measurements

The implemented optimization is a bounded, process-local mapping from a kernel
fs-verity digest and file size to a previously observed full-file SHA-256.
The first observation still reads the complete file. Later observations may
reuse that SHA only for the same kernel-enforced sealed content. It is not a
pathname, mtime, permission-bit, or read-only-bind-mount cache.

The five complete measurements share the same core measurement module. Static
files and the three session-specific late files already have fs-verity enabled
before the first of these measurements. This permits reuse across the four
subsequent passes without reusing any authority receipt.

All existing tree enumeration, metadata, root identity, authorization and
deadline checks remain fresh. Unsupported, unsealed, and SHA-512-verity inputs
take the full read path. Cache entries are bounded and cleared after a PID
change. Cache eligibility requires Linux x86_64, same-open-file ext4 filesystem
identity, and a well-formed SHA-256 fs-verity measurement. An ioctl number alone
is not proof that a userspace filesystem enforces fs-verity.

The [kernel fs-verity contract](https://cdn.kernel.org/doc/html/latest/filesystems/fsverity.html)
provides a constant-time digest of the content enforced on reads. This is not
an eager disk scrub: damaged backing pages still fail when actually read.

## Second optimization: share the memo with retained launch files

The public retained-file path now explicitly opts into the same content memo
during launch input composition and issuer verification. Source inspection
found four retained-file scans per role: composition, issuer acquisition, and
verification on both sides of signing. Across the first six roles, that is
24 scans; the count is not a measurement of time saved.

Each observation still checks its own live owner, held descriptor and path,
file metadata, inode generation, frozen state, fs-verity identity, size and
EOF. A content hit does not transfer descriptor ownership or reuse another
call's native-mapping record. Claimed bundle hashes never seed the memo.
Misses retain the existing guarded 64 KiB reader. Directory, setup, credential
and mapping-fallback paths keep their prior behavior; both signing-boundary
verification calls remain in place.

The matching COMMON change is in
`docker/serverware/pilot/prepare_authority_launch.py`. This integration and the
SDK change must be assembled together; neither changes the frozen R97 runtime.

## Third optimization: share the memo with native roster inspection

Native roster inspection previously read and hashed every complete executable
and shared object immediately after the tree measurement had already populated
the content memo. It now reuses that same sealed-content measurement. ELF header
and dependency inspection still reads the actual newly opened descriptor on
every call; parsed metadata and admission decisions are not cached.

The opened file must match the measured size, mode, ownership and single-link
requirements. Caller lifetime, frozen state, descriptor identity and EOF remain
checked, and the observed digest must match the selected roster. Cold or
unsupported inputs stream through bounded 1 MiB reads, not a whole-file buffer.
The existing retained-launch reader and generic tree measurement are unchanged.

## Startup supervisor: retained-file checks

The local startup supervisor was a separate uncached caller. For each role it
hashes retained files on acquisition and at four subsequent full-check
boundaries: completion of open, beginning of run, receipt of late originals,
and authenticated child admission. Both digest sites now use the same
sealed-content memo. All five boundaries remain; their per-file checks use
captured descriptor/name ownership in constant time rather than recursively
scanning the complete owner for every file.

Every hit still checks the actual held and named file metadata, read-only
descriptor, owning process/thread, original clocks and kernel content identity.
The existing 64 KiB reader remains the fallback, including empty public modules.
Plan, credential and late-original byte readers are unchanged. The memo is
process-local and resets at fork: this does not skip another process's first
measurement or cache child admission. Savings from this integration are not yet
measured on a native startup.

## Installation phase timing

Prospective COMMON source now emits nine bounded `INSTALL_*` durations for
configuration issuance, package finalization, post preparation, measured
evidence, installation preparation, core remount, witness/package signing,
actual installation and trust commit. These use the existing best-effort
diagnostic helper, not an authorization clock or another startup gate. Original
phase markers and call order remain intact; a failed phase does not emit a
successful completion duration. These timings are not present in frozen R97.

## Runtime layout: one mount-table parse per check

`RuntimeLayout.check()` previously reread and parsed `/proc/self/mountinfo`
once for each verified mount. The prospective implementation reads and indexes
one bounded fresh snapshot per call, checks every selected mount against it,
then requires an identical fresh reread followed by namespace and original
clock checks. Calls with no verified mounts do not read the mount table. No
snapshot survives a call, and the standalone lookups used during mount creation
and cleanup still read fresh state. Every existing held-FD, named-path, link and
mounted-source identity check remains in place.

The apparent duplicate RBAC/cohort traversals in the database guard are not
removed. Their later observations enforce freshness after intervening work,
including a distinct RBAC monotonic deadline. Exact owner identity does not
prove those earlier observations are still current; safe coalescing needs an
owner-owned freshness contract rather than a caller's remembered success.

The mount-table change is committed in COMMON as `b47b8c251`. Its ten new
component groups passed together with 28 existing check-path and five timing
tests: 43 tests in 7.697 seconds. The component fixtures execute the actual
check, clock and parser methods with explicitly synthetic owner/FD/namespace
observations. They verify constant read/parse counts, fresh observations on
every call, changed-state refusal, original custody checks, bounds, cancellation
and unchanged standalone lookup behavior. A separate read-only container check
matched the old lookup semantics for all 123 targets in its actual 16,174-byte
kernel mount table, with an identical fresh reread. Neither test executes native
pilot mount setup or measures native startup latency. Frozen R97 is unchanged.

## Local verification

Nine cache test groups pass with real temporary files and synthetic kernel
responses. They cover full-read versus reuse, changed content, metadata,
filesystem admission, malformed kernel responses, original deadlines, bounded
eviction, fork/PID isolation, and unchanged miss-path callback frequency.
Thirty-four existing artifact, snapshot, and closure tests also pass using the
already available engineering image, without installing or building anything.

The combined follow-up run passes 79 tests: those 43, 23 existing launch
authorization tests, and 13 new launch-content-cache groups. The new groups use
real temporary files and descriptors with explicitly synthetic kernel and
live-owner controls. They exercise shared content reuse, fresh ownership,
wrong claimed hashes, changed metadata and post-EOF conditions, and unchanged
default and unsupported paths. Three COMMON cohort integration tests also pass.

The third optimization passes the same suite plus 12 new native-roster cache
groups: 91 tests in total, using the cached offline engineering image without a
build or dependency installation. The new groups use real temporary files,
descriptors and ELF reads with explicitly synthetic kernel/owner controls. They
cover cold streaming, warm reuse, changed content and metadata, fresh ELF
admission, unsupported inputs, EOF and size bounds, wrong claimed digests, and
cancellation or short reads without publishing a partial digest.

The startup-supervisor follow-up passed 40 tests in the cached offline
engineering image: 15 existing startup tests, six failure-diagnostic tests,
nine shared-cache tests and ten new startup-content-cache groups. The new
groups use real files, descriptors and byte reads with explicitly synthetic
kernel seals, ownership and clocks. They cover cold/warm reads, empty retained
files, false claims, changed metadata/content/names, original lifetime checks,
cancellation, unsupported inputs and preservation of all five digest
boundaries. They do not run an admitted startup or establish latency savings.
COMMON also passed five installation-timing groups and reran all 28
prepared-static groups. The timing change is committed as `69b5a2a59`.

The opt-in real-kernel test was attempted on the host's ext4 temporary volume
and **skipped** because that filesystem/kernel does not support fs-verity there.
It is not a passing real-fs-verity acceptance result. No new mounts, elevated
container capabilities, or active-pilot changes were made to obtain a test pass.

## Remaining work and evidence boundary

The measurement-cache changes alone do not provide cross-session artifact
reuse or eliminate installation, destination readback, synchronization, ELF
metadata analysis, or launch authorization. The additional prepared-static
implementation below targets the repeated static installation work; it does not
treat a stored hash as proof that mutable files are unchanged.

No active R97 assembly is modified by source changes in this workspace. A
startup-time improvement must be measured on a newly authorized deployment;
source review or an isolated cache test is not end-to-end latency acceptance.

## Prepared-static installation (source implemented)

The existing COMMON pilot assembly already reuses prepared static bytes:
`assembly/host/prepare_live.py.tmpl` creates `active-package.qcow2` over
`package.ext4`. `package_tree.stage()` populates and seals its static leaves;
finalization adds only the service configuration, witness configuration and
SBOM. The original full-copy installer then copies every entry into a separate
fresh installation tree, reads it back, seals it and synchronizes it again.

The new source prepares an authority-less `prepared-static` installation subtree
in that base image. Its static leaves are independent, fs-verity-sealed immutable
files, not hardlinks to the package source. A fresh session COW retains those
bytes without inheriting an installed generation, trust advance or authority
receipt. The complete selected static roster includes pilot public keys and
role manifests, not just a source commit or runtime image.

Explicit installation configuration v2 selects local provisioning plan v3 and
receipt v2; the original configuration v1, plan v2 and receipt v1 full-copy path
remain unchanged. The new plan and receipt distinguish `adopt-prepared-static`
from `copy-fresh`. The current signed package supplies the complete content and
metadata roster. Its exact complement of the selected fresh paths must match
the prepared tree, including directories, with no extra or missing entries.
Before consuming the subtree, the installer checks actual file contents,
fs-verity, immutability, metadata and physical identities on the destination's
device and mount. It then uses a no-replace move and copies only the fresh files.

The COMMON pilot selects exactly three per-session fresh paths:

- `configurations/authority-service.json`
- `configurations/witness.json`
- `sbom/selected-files.spdx.json`

Those files still receive the full copy, readback, sealing and synchronization
path. The SDK selector requires a sorted nonempty proper subset of the current
signed package; it does not silently infer a three-file exception for other
packages. A warm process memo may avoid rereading an adopted file's sealed
content. A cold standalone installer still hashes its actual bytes; no claimed
hash or historical receipt seeds the memo.

Package and verification signatures, current trust and signer authorization,
generation locking, original deadlines, publication, fresh receipt signing and
trust-commit checks remain required. The prepared template is not authority,
does not renew a deadline, and cannot substitute a completed session. See
[the installation contract](trusted-host-local-installation.md#prepared-static-local-installation)
for the versioned interface.

This mode is implemented in SDK commit `a1114063` and COMMON commit `89e442916`.
It is **not deployed to R97**, has no measured new startup improvement yet, and
does not establish production/native signed installation acceptance.

### Prepared-static verification on 2026-10-10

The focused SDK run passed all 41 prepared-contract, filesystem-component,
legacy installer and trust-commit tests, including the root-owned DAC checks,
using the cached offline engineering image. The 91 measurement/launch/closure
tests also passed again. A stale legacy test's rejection boundary was corrected
to the existing setup ceiling plus one second; no runtime deadline was changed.

COMMON passed 28 prepared-static tests, 10 existing preseal/loader/cohort tests,
two Rust-input roster tests, and inert rendering/syntax checks for 26 assembly
templates. The current SDK embeds `npm.publish.v1`; its omission from the
prospective assembly's Rust external-input roster was corrected. Rendering
invoked no build or preparation producer and establishes no build provenance.

The optional [kernel component checker](../scripts/check_authority_prepared_static_kernel.py)
ran once from SDK `a1114063` in a bounded offline Linux 6.8 KVM guest with a fresh
64 MiB ext4 filesystem supporting fs-verity. The runtime and source were
read-only, there was no network or host share, and the guest used no authority
keys or pilot runtime. Two independently prepared static files preserved their
actual inode/generation/verity identities through adoption and both moves; one
fresh file was copied and sealed. Real writes to sealed content were refused.
Wrong bytes, missing/extra files, absent verity, absent immutable flags,
hardlinks and a wrong generation were refused before template consumption.

Actual source `pread` counts were six cold versus three warm for three files;
warm reads were EOF checks, not full-content rehashes. Static adoption made two
EOF checks for its two files. The checker returned `ok: true`, the final guest
marker was success, QEMU exited zero and its bounded scope was inactive. This
is filesystem-component evidence only: the owner/lifetime fixture is synthetic,
full signed installation was not run, cross-mount behavior was not exercised
in the guest, and startup latency was not measured. Unit tests cover synthetic
cross-mount refusal separately.

Retained evidence directory:
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/prepared-static-kernel.vdQ0u0O4`.
Its `guest.log` SHA-256 is
`794f548fdd5b27924d4f15737c34bbe4fdffba45cf0f5707c27423e31132843c`.
The guest ran from 21:53:23 to 21:53:27 UTC. Those four seconds are the tiny
component probe, **not Serverware startup time**. The images, harness and log
were retained; no native pilot was restarted or altered.
