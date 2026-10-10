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

The opt-in real-kernel test was attempted on the host's ext4 temporary volume
and **skipped** because that filesystem/kernel does not support fs-verity there.
It is not a passing real-fs-verity acceptance result. No new mounts, elevated
container capabilities, or active-pilot changes were made to obtain a test pass.

## Remaining work and evidence boundary

The three measurement-cache changes alone do not provide cross-session artifact
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

This mode is implemented in SDK and COMMON source. Its tests and root-owned KVM
component probe are in progress. It is **not deployed to R97**, has no measured
new startup improvement yet, and does not establish production/native signed
installation acceptance. The earlier cache-test results above are unchanged.
