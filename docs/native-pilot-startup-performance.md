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

## Local verification

Nine cache test groups pass with real temporary files and synthetic kernel
responses. They cover full-read versus reuse, changed content, metadata,
filesystem admission, malformed kernel responses, original deadlines, bounded
eviction, fork/PID isolation, and unchanged miss-path callback frequency.
Thirty-four existing artifact, snapshot, and closure tests also pass using the
already available engineering image, without installing or building anything.

The opt-in real-kernel test was attempted on the host's ext4 temporary volume
and **skipped** because that filesystem/kernel does not support fs-verity there.
It is not a passing real-fs-verity acceptance result. No new mounts, elevated
container capabilities, or active-pilot changes were made to obtain a test pass.

## Remaining work and evidence boundary

This first change does not provide cross-session artifact reuse or eliminate
fresh installation, destination readback, synchronization, separate closure
analysis, or launch authorization. Removing those recurring costs requires a
separate reusable immutable-build artifact and fresh session authorization,
rather than treating a stored hash as proof that mutable files are unchanged.

No active R97 assembly is modified by source changes in this workspace. A
startup-time improvement must be measured on a newly authorized deployment;
source review or an isolated cache test is not end-to-end latency acceptance.
