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

## Package loading: populate the shared memo on the first read

COMMON `package_tree.check_file()` previously performed its own full-file SHA
pass without populating the SDK memo. `load_stage()` calls it for every static
file, so the subsequent SDK tree measurement unnecessarily read those bytes
again. The loader now uses the existing guarded content-measurement helper.
It also shares measurements between independently sealed source and prepared
installation files when their kernel content identities match.

The caller still compares the result with the selected expected hash and
checks actual ownership, mode, link count, size, held/named identity and the
original deadline. Unsupported or cold content still takes the full-read path;
neither a selected hash nor a previous successful authorization seeds the memo.
This closes an actual same-process cache integration gap, not cross-session
reuse or an end-to-end startup performance result.

COMMON commit `51c03edde` passed 40 focused tests: eight new connected
loader/SDK cache groups, four existing preseal controls and 28 prepared-static
controls. The new groups use actual temporary file bytes, hashes, descriptors
and the SDK measurement functions; filesystem eligibility, kernel seals and
root ownership are explicitly synthetic. They show that the first loader pass
reads the body and the following measurement performs only its EOF read.
Wrong claimed hashes, changed content/metadata/names, unsupported filesystems
and the original deadline remain covered. No build, native startup or pilot
mutation was used for these tests.

## Installed-file readers: share content, not physical identity

COMMON commit `3d286f298` updates `RuntimeLayout._installed()` and
`StartupResources._installed()`, which also
used independent full readers. Both now use the existing SDK content memo,
which can already be warm from installation in their shared parent process.
Each caller still measures its own inode/generation and compares every field
of the current installed-file selection. Held/named file and parent identity,
read-only descriptor mode, frozen state, current kernel digest and original
clocks are checked on hits, including after the final physical comparison.
The existing full-owner and mount checks are unchanged. Cold or ineligible
inputs retain the original reader, including its different empty-file limits:
startup allows empty public modules; layout requires nonempty originals.

Seven new connected component groups passed alongside ten existing layout
checks and three cohort checks. They exercise the actual reader/clock methods
and SDK memo with real temporary files and explicitly synthetic root/kernel
observations. A separate existing listener test initially failed because it
still expected an inline `listen()` call instead of the already-existing
role-identity helper. Its fixture now extracts that helper's actual socket
call, verifies the caller wiring, and passed on its own targeted rerun. No
production listener behavior was changed. These are 61 distinct passing groups
across the package and installed-reader runs, not a native startup benchmark.

The cached offline engineering image ran all checks with network disabled,
read-only source, no capabilities or host ports, and temporary fixture storage.
The logs, including the initial listener-test failure, are retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/startup-cache-integration.3IvDdJ6F`.

## Cross-session reuse: pinned build-time content catalog

A new process still starts with an empty measurement memo. Persisting that
dictionary without an independently trusted binding is not sufficient: the
ordinary file SHA-256 and its kernel fs-verity digest are different values.
Likewise, a hash computed after loading `stage.json` does not independently
authenticate the file that supplied it.

The implemented catalog records a bounded, content-only mapping from each
kernel content digest and size to an actually observed file SHA-256. The
unsigned build observes both the sealed source tree and its independently
sealed prepared installation copy. It compares those observations with the
selected roster, rejects conflicting entries, and writes
`static-content-catalog.json` outside the package tree. The three late files
are excluded. The format contains no paths, permissions or session authority.

The host extracts the catalog only from the completed base `public.ext4`,
never the writable session COW. Its SHA-256 is selected independently in
`pilot-startup-selection.json`; the exact bytes accompany that selection in
the read-only payload, both covered by the existing assembly freeze. The
coordinator validates that pin, the closed canonical format, and held/named
read-only file custody before installation. It reads the bounded catalog once,
not again at every owner check.

During `PilotLive.run()`, a matching kernel content identity can satisfy the
first static-file hash observation even in a fresh process. Exact roster,
metadata, ELF admission, current signatures, trust state, authorization and
original deadlines remain fresh. Unsupported or absent entries take the normal
full-read path. The catalog context is single-use and PID/thread-owned, ends
on success or failure, and never seeds the observed-content memo. Forked or
exec'd children do not inherit its activation; their cold scans are not removed
by this change. Standalone callers without an independently admitted catalog
also retain their first full read.

The SDK passes 56 focused component tests, including 12 new catalog groups.
Two actual fresh-interpreter workers exercise both artifact measurement and
retained startup-file hashing with empty observed caches: catalog hits perform
only the EOF probe, and calls after context exit read the bodies again. Real
temporary bytes, descriptors and hashes are used; root ownership and kernel
fs-verity observations are explicitly synthetic. This is source/component
verification, not real-kernel acceptance or a measured native startup speedup.

COMMON also passes 55 consumer/regression groups and 14 assembly component
groups: 125 passing tests across the three focused runs. The new checks execute
the actual catalog producer, live loader and scoped run wrapper, plus the
host's extraction/pin/copy helpers. The assembly process streams are inert test
fixtures, not an executed `debugfs`, VM or image build. The retained loader
keeps metadata custody without rereading the catalog at every owner check.

The source change is not deployed in the retained R97 pilot. No native startup,
deadline reset, registration retry or pilot mutation was performed for this
work. Evidence is retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/cross-session-content-catalog.d8hGTTHt`.

### Real-kernel cold-process check

The optional [catalog kernel checker](../scripts/check_authority_content_catalog_kernel.py)
passed once on Linux `6.8.0-138-generic`, using actual ext4 SHA-256 fs-verity and
immutable files in a fresh 64 MiB offline guest disk. SDK source was archived
from `5c9aa344064f4d75efff3486f752bfc38d748309`; only the new checker was appended,
separately pinned at
`b1d0b3b6710eff6b040985e8fade9dfbdaecb91e77f09699c6fedb94f64ea7bf`.
This is not a newly authenticated assembly or signed-installation result.

The producer actually read and sealed public synthetic content. Two newly
executed isolated Python interpreters each started with an empty observed memo
and exercised both `measure_file()` and the default `_digest_owned_file()`
reader. For the 2 MiB file, each catalog hit made one actual `pread` call (EOF),
versus two 1 MiB body reads plus EOF on the cold path. The empty file required
one EOF call in both cases; no saving is claimed for it. Profiling counted the
real C calls without replacing reads, ioctl results or kernel observations.

Both interpreters rejected a wrong catalog pin, fully read a different sealed
2 MiB file, and returned to full reads of the original file after catalog scope
exit without clearing the memo. Catalog hits had not populated that observed
memo. An actual write-open of the sealed original was refused by the kernel.
This exercises the measurement helpers, not an admitted startup owner, custom
startup fallback reader, package signatures, or full Serverware startup.

The guest had no network device or credentials, read-only source/runtime
inputs, a 60-second outer watchdog and shorter parent/child deadlines. It ran
from `23:28:36.055` to `23:28:46.422` UTC on 2026-10-10; that roughly ten-second
component run is **not native pilot startup time**. It exited successfully and
its dedicated scope was then inactive. All fixture images and logs remain in
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/content-catalog-kernel.TspOaxGc`.
The `guest.log` SHA-256 is
`1b775029c48f1e7f0993046113b2ffb00443b826f0f6ba4f541ddb3214631265`.
No retained pilot was started, reset or modified.

The five SDK cache/catalog suites are also registered in the automated
isolated-test inventory, and the measurement/catalog modules are present in
both explicit source-dependency checks. Make parsed and verified those
inventory entries without running a controller workflow. The opt-in kernel
checker is deliberately not an automatic unit test.

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

## Launch publication: bounded I/O checks, full publication checks

The launch issuer previously swept every retained file's held and named
metadata before each 64 KiB write and readback chunk of a late original. Large
manifests themselves contain the retained roster, so the number of metadata
operations grew with both the roster and output size. Content-hash caching did
not remove this work.

The issuer now opts into constant-size live/source/deadline checks and exact
output-descriptor checks around each chunk. Full retained-roster checks remain
at entry, immediately before the irreversible link, and completion. Both full
live measurements around signing remain unchanged. After the final manifest
link, checks retain sources and original clocks without requiring the released
child to remain parked. Other callers keep the original per-chunk behavior.

All eight new publication groups and 23 existing launch-authorization groups
passed in the cached offline runtime. These use real anonymous temporary files,
`linkat`, descriptor metadata, readback and no-replace behavior, with explicitly
synthetic owner guards. They cover partial writes, write errors, cancellation,
changed retained paths, output descriptor substitution and post-release failure.

A separate component comparison used the actual helper and issuer roster-check
method over 4,000 real synthetic public files and a 1 MiB output. The original
default made 51 full sweeps (408,000 roster stat calls), taking 1.429 seconds;
the opt-in path made three sweeps (24,000 calls), taking 0.077 seconds. Live-owner
checks were synthetic counters, so these are neither native startup timings
nor a predicted end-to-end speedup. No signature, authority or session result
was cached.

Evidence is retained in
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/startup-work-scaling.VTN018zQ`.
Two initial benchmark invocations could not read the private evidence-directory
mount. Binding only the public benchmark script read-only resolved that harness
permission issue without changing host permissions. The successful fixture
containers and their temporary synthetic files were removed; logs remain.
No retained pilot was started or modified.

## Package verification: reuse one invocation's bundle digest

One successful `verify_signed_artifact_package()` call previously validated and
hashed the same bundle five times through nested digest and signature helpers.
For the independently decoded plain JSON used by launch input parsing, it now
retains that invocation's validated digest and constructs the same signature
messages from it. Public validators and digest helpers still validate their
own inputs. Every call still checks actual signatures, trust, time, revocation,
evidence and witness high-water, and compares final package bytes before
returning. Nothing survives the invocation as a cached authorization result.

A bounded exact-type eligibility check avoids invoking unknown Python methods.
Subclasses, shared/cyclic containers and inputs beyond that optimization's
traversal limits retain the original verification path. This matters: a custom
mapping can mutate a bundle after its initial validation. Source review found
two such refusal regressions in an early draft; both are covered by the final
tests and keep their original rejection. This is not a concurrent-mutation API.

Ten new groups plus seven signature-helper and ten prepared-contract regression
groups passed, using real signatures over synthetic package descriptions. They
prove one bundle-validation/hash pass per successor or retry call for decoded
JSON, five on the conservative fallback, unchanged digest/signature bytes,
fresh later-call refusals and mutation detection. The fixture builder itself
shares containers, so its un-decoded before/after microbenchmarks correctly
remain on the five-pass path; those logs are not evidence of a speedup.
A separate comparison of decoded JSON against the unchanged fallback verified
the identical package digest with one versus five bundle passes. Its 28-file
synthetic-package timings are not a native startup estimate.

Together with publication, 58 focused tests passed across the two runs. Both
new suites are in the isolated-test inventory, verified by parsing Make without
starting a controller workflow. Evidence shares the directory above; full
native startup latency remains unmeasured and R97 is unchanged.

## Prepared-static scan: bound metadata work by path depth

The prepared installer still swept every retained directory's named and held
metadata at each file boundary, including on content-catalog hits. The roster
grew throughout the walk, so this read-only preflight performed work proportional
to files times previously discovered directories. Avoiding body reads alone did
not remove that cost.

The scan now checks the original destination ancestry and selected prepared root,
plus the current file's ancestor chain. Every such check still observes the
original source descriptors, owner, clocks, source-root identity and frozen state.
The leaf's named/held identity, generation, permissions, immutable flag, mount,
kernel content identity and EOF checks remain unchanged. A direct `_adopt()` call
retains its original full check by default.

Full retained-directory checks remain at scan entry and exit, before any plan
publication or consumption of the prepared tree. A changed previously scanned
sibling may be detected at scan exit rather than during another sibling's read;
it still refuses before installation effects. All effect-bearing checks in
`run()`, including copying, directory freezing, renames and receipt publication,
are unchanged. In particular, this does not optimize the separate per-directory
freezing loop or cache a successful authorization.

## Assembly selection: include the optimized runtime-layout helper

The assembly's source-selection list omitted `pilot_runtime_layout.py`. The
drafting path could therefore copy an older helper from the retained baseline
drivers and pin that old copy, despite the current tracked helper implementing
installed-content reuse and bounded mount-table parsing. Explicitly selecting
the tracked helper makes those existing changes part of the next assembly and
subjects it to the same exact-source comparison as other selected drivers.

Neither change modifies an existing assembly. Full native startup latency still
requires a fresh authorized pilot measurement.

The source-selection repair is COMMON commit `db9c7c515`. Six new selection
groups execute the real draft-copy and final pin-comparison loops against
temporary stale baselines and actual tracked source. All pass, as do 14 existing
catalog/assembly groups; these do not execute a builder, guest or full assembly.

Seven new installer scan groups pass across the initial and corrected-fixture
runs. Real temporary files, named paths and descriptors exercise the actual
scan guards; process admission, clocks, source-root admission and kernel
ownership/verity observations are explicitly synthetic. Widths of 1, 8 and 24
sibling branches retain exactly two full sweeps and a maximum four-link current
path; deeper trees increase that path bound with depth, not sibling count.
The cold-catalog case observes actual file bytes before producing the catalog,
clears the observed memo, then verifies EOF-only adoption without memo seeding
while original clock and custody callbacks remain fresh. Empty-file EOF parity
is not a claimed saving. Changed current ancestors and original sources refuse
during the scan; a changed prior sibling refuses at the full exit check before
any publication or consumption. Default direct adoption retains full checks.

The first scan run exposed a fixture error: `mkdir(parents=True)` had created
intermediate directories with mode 0755, so the unchanged production 0700 check
correctly refused before the intended probes. Only the fixture's controlled
directories were corrected. The four passing groups were retained and the
three affected groups reran successfully; this is not one complete corrected
suite run. An additional 33 existing SDK controls passed; one unrelated
root-only DAC control was skipped in the non-root container. These are 60
distinct passing focused groups across the runs, not native startup acceptance.

All checks used the existing offline image with read-only source, no capabilities
or host ports, and disposable temporary storage. The prepared contract,
filesystem, catalog and new scan tests are in the isolated-test inventory;
Make parsed that inventory without invoking a build or controller. Logs,
including the initial fixture failure, are retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/startup-prepared-scan.HZXocMr5`.

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

The process-local memo alone does not provide cross-session reuse. The pinned
catalog above adds it for the main startup process's sealed-content hashes,
not child-process activation, installation, destination readback,
synchronization, ELF metadata analysis, or launch authorization. The additional
prepared-static implementation below targets repeated static installation
work; it does not treat a stored hash as proof that mutable files are unchanged.

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

### Cold catalog through prepared installation

The connected component suite now passes a catalog produced by actual file
observations into two fresh, isolated Python interpreters. Each invokes the
actual prepared-tree validation/adoption readers with an empty observed-content
memo. Matching static files receive only EOF probes; their selected hashes,
metadata, roster and physical identities are still checked. After catalog scope
exit, the same readers read the full bodies again without clearing the memo.

Wrong catalog pins, wrong selected content, changed permissions, extra entries
and the original cancellation exception are refused without consuming the
prepared tree. The workers ignore ambient Python optimization settings so these
assertions cannot silently disappear. All 25 connected, prepared-install and
catalog tests passed in 10.219 seconds in the cached, network-disabled test
runtime. Two initial failures were test-oracle mistakes, corrected before this
passing run; no production behavior was changed.

These checks use real bytes, descriptors and hashes, with explicitly synthetic
root ownership, filesystem eligibility and kernel seals. They join the catalog
and installer code paths; they are not signed-installation acceptance or an
end-to-end startup measurement. Frozen R97 remains unchanged. Evidence:
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/prepared-catalog-connected.Zj076r6W/tests-isolated-worker.log`.
