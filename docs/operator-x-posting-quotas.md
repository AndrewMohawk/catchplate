> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Shared X posting-attempt limits

Implementation is being verified; this document is not a deployment or
real-provider acceptance record.

At the October 13 source checkpoint, `acd157de` passed 120 focused Rust tests
across 16 filters and produced normal executable
`fd951c487b04c0c0e4d7a43e0c406484c2efcaa75635c697b9f6a2df9da7de08`.
The independent `x-quota-release-source.QT00amZr` join verified 516 compiler
inputs and 1,175 selected source files against immutable candidate `5dd72259`.
That join did not execute the normal binary; compilation, test-binary and
source-join evidence alone do not establish proxy enforcement.

The first ordinary CI run, `38355568971`, passed 45 of 46 suites;
its sole failure was an incomplete legacy route fixture. The test-only repair
passed all seven affected controls, with the original failure retained.
[CI run 38358032103](https://github.com/example/private-deployment)
then passed all 51 offline suites in 341.576 seconds with no skips: 419 observed
Python tests and 145 Node groups. This includes the relay's ten controls with
one actual isolated-loopback raw-byte/drop/no-retry test, not a joined
signed-app/Rust/provider fault run.

The first A+B joined attempt, `x-quota-sdk-acceptance.KE9Khear`, failed during
Docker keeper startup at its original 20-second start bound, before the
task/provider started. Its terminal receipt records network-phase failure
and successful cleanup after 57.152 seconds; the startup cause is unproven.

The second attempt, `x-quota-sdk-diagnostic.cPTGQyTk`, started the keeper within
that original bound, reached app/gate health and executed normal `fd951c48…`
and the first Node SDK request. It failed at `node:a_first`, with no completed
phases: the generation-metadata POST returned 200, but the Rust quota path
mistook metadata-only `secret_available:false` for a missing credential and
returned 503 / `credential_generation_missing`. Cleanup succeeded after
56.977 seconds. A narrow Rust correction is being implemented and is not yet
verified. Joined A+B success, separate lost-acknowledgement/revocation fault
lanes, retained-data rollout and real-X acceptance remain open. The running
instance has not received this feature.

The correction at `94b7f755` adds two real signed-metadata/lease regression
groups. Its first test compilation stopped on a missed borrow of the now-owned
injection plan in the existing Gmail fanout initializer; no tests executed.
The failed build and successful owned-container cleanup remain in
`serverware-x-quota-rust.Wg85qphg`. The follow-up restores that explicit borrow
without changing quota, Gmail or forwarding semantics; compilation and runtime
acceptance are still required.

At `5312c41b`, CI run `38361539528` passed all 51 offline suites with no
skips. The separate Rust test compilation succeeded, but its first executed
group passed 13 existing tests and failed the two new quota-release tests.
The signed audit preflight correctly rejected the fixture after its real
configuration reload lost a test-only quota selection. No audit guard was
relaxed, no normal executable was published, and the live instance was not
changed. The failed test output and successful container cleanup are retained
in `serverware-x-quota-rust.btsZVUPw`; fixture repair and a fresh test run are
required before continuing.

At `06ffbeb7`, the test-only selection survives the real profile reload without
changing production reload or signed-audit checks. All 122 focused Rust tests
passed across 16 disjoint filters. Normal executable
`682d66d8fe97d3022513b79292bfe6710c60bfb6f54342f910da94df2db39d80`
was built separately; `x-quota-release-source.bhLjGrAF` independently joined
its 516 compiler inputs and 1,176 selected source files to the immutable
candidate. [CI run 38363191655](https://github.com/example/private-deployment)
also passed all 51 offline suites with no skips.

The first R4 joined attempt, `x-quota-sdk-r4.rrYx6uJe`, stopped at the original
app-startup deadline with no gate or SDK execution. A separate startup-only
stack diagnostic reached health in 22.36 seconds within the unchanged bound;
its observed source compilation/import work does not establish the earlier
timeout's cause. Both attempts cleaned up their owned containers and retained
their evidence; the diagnostic did not run the normal proxy or any SDK.

The next uninstrumented attempt, `x-quota-sdk-r4-after-trace.7sY8prb9`, ran
normal `682d66d8…` and completed the first Node, Python and Go posts, each
returning 201 from the isolated TLS provider. Exactly three posts carried the
correct provider credential and no proxy authorization header. The restart
snapshot then failed before restarting the app: the fixture incorrectly
looked for `/x-custody/master.key`, while the actual owner uses
`/x-custody/provider-key.json`. Cleanup succeeded after 69.008 seconds.
The narrow fixture correction preserves all four mandatory key hashes and
adds a regression against the actual owner's filename; all ten focused
fixture controls pass. This needs no Rust rebuild. Full restart/refresh,
exhaustion/reconnect and separate fault-lane acceptance remain open; these
three successful requests are partial evidence, not deployment approval.

Candidate `6235402e` then passed the complete A+B run in
`x-quota-sdk-keyfix.nEItdQ2X` (191.455 seconds including cleanup): seven actual
SDK phases, four allowed posts, three denied attempts, one expiry-triggered
refresh, and unchanged quota/key/policy state across the same-ID app/gate
restart. Two applications share the limit; disconnect/reconnect with a new
credential ID does not reset it. The audit chain and four reservation/claim
joins passed. All owned containers were removed. This is isolated TLS-provider
evidence, not real-X acceptance. CI `38367263218` also passed 51/51 suites.

The separate first dropped-ACK attempt, `x-quota-fault-drop.9aIhKfH0`, stopped
before gate or SDK execution. Its relay started, but Docker's first health
probe exceeded its three-second timeout; the next probe was scheduled after
the runner's six-second startup cutoff. Cleanup succeeded after 37.724 seconds.
The fixture-only wait is now twelve seconds (fifteen-second outer command
bound), allowing that next bounded probe. The original 75-second preparation,
300-second keeper, 240-second relay, 180-second checker, token lifetimes and
five-second claim deadline remain unchanged. Both actual fault lanes and
retained-data rollout remain required.

The next fault attempt, `x-quota-fault-drop-healthfix.qxqHLbQD`, admitted the
relay but the normal proxy refused startup: its fixed ordinary lease URL is
`http://serverware:3000/api/data-plane/credential-leases`, while the fixture
had substituted port 3001. No SDK ran; cleanup succeeded after 48.426 seconds.
The proxy's admission guard is unchanged. The repaired fault-only fixture
instead gives the gate a fixed loopback hosts mapping: `serverware` resolves
to the raw relay at `127.0.0.2:3000`, which forwards to the app bound at
`127.0.0.1:3000`. Control stays separate at `127.0.0.1:3001`. All required
control-plane URLs and raw Host, request and response bytes stay unchanged.
Only the fixed attestation, audit, lease and claim routes are forwarded, with
their route-specific bounds. Both listeners share the original lifetime,
eight active slots and 128-request cap; no general proxy or retry was added.

The wiring passed 55 focused fixture controls and 13 pure relay controls.
An actual network-none loopback run then passed all 14 relay controls,
including raw attestation/audit forwarding and a dropped claim response with
no repeated upstream call. Its first container never started because Docker
refused a one-file compressed log setting; the corrected two-file setting
was used in a fresh container. Both owned check containers were removed.
These checks still do not replace either joined app/proxy/provider fault lane.

At `5f0ab174`, [CI 38369900173](https://github.com/example/private-deployment)
passed all 51 suites in 414.778 seconds, with 427 observed Python tests,
145 Node groups and no skips. The next joined dropped-ACK attempt,
`x-quota-fault-drop-loopback.6Fcyi1v4`, stopped before relay, gate or SDK startup:
the app remained running without logs or a listening socket through the
original startup deadline. Cleanup succeeded after 51.083 seconds. Its image,
command, resources and normalized mounts match the successful A+B app; only
the fault profile's loopback bind differs, and binding happens after imports.
This is a pre-listen startup failure, not demonstrated quota or relay failure.
Host I/O pressure and earlier import/compilation stacks are compatible with a
delay but do not prove its cause. The bounded startup comparison below preceded
the next joined fault run; live services and the successful A+B evidence are
unchanged.

The optional startup optimization prepares checked-hash Python bytecode once,
outside the source tree, using the exact app image's CPython 3.11.15. The
`prepare_operator_python_bytecode.py` helper separates host-side committed
source inventory, offline compilation, validation and non-executing cache
consumption checks. Its externally pinned manifest binds the helper, every
selected source file, interpreter and every compiled file. The caller must
retain the actual compiler-container image/configuration receipt; the helper
does not authenticate its own container. Identical Python/helper bytes may be
reused across documentation-only commits after comparison with Git objects.

The X fixture accepts the paired `--python-bytecode` and
`--expected-python-bytecode-manifest-sha256` inputs. Without them, behavior is
unchanged. With them, only two read-only app cache mounts are added, and the
artifact is checked before and after the run. No timeout, application code,
proxy guard or page-load path changes. Source mountpoints must already exist;
Docker must not create them or write bytecode into a checkout. Actual image-side
cache consumption and a matched startup-only comparison remain separate
acceptance. A release must also reconcile its exact-source readback with these
explicit cache mounts before adopting them on the live app.
The initial source batch passed 59 focused cache/recipe/runner/quota controls
and 12 ordinary-orchestration controls; the new cache suite is included in the
52-suite ordinary CI inventory. These component results are not startup timing.

At `415faeb4`, actual pinned-image compilation and non-executing consumption of
all 1,745 cached modules passed. The matched startup samples reached their first
retained successful health probe in 11.390 seconds without the artifact and
11.437 seconds with it (`x-quota-startup-comparison.QlUWMT71`). This single pair
showed no startup-time improvement; the cache remains optional and is not selected
for the live rollout. The following joined dropped-ACK run reached healthy app,
relay, gate and edge, then failed in the test-only gate namespace probe because
the curated gate deliberately has no source mount
(`x-quota-fault-drop-cached.5yDO3CDa`, 56.261 seconds, cleanup successful).
The probe now carries only its fixed standard-library checks into that same
container; no mount, production guard or deadline changes.

The rendered account/setup suite subsequently passed all ten groups with eight
masked 1280/390-pixel screenshots and unchanged source. It verified default
omission, exact limited grants, invalid input and capability withdrawal. The
first run's stale-read test failure is retained; the correction waits for the
actual catalog response and rendered refusal, without changing product code.
All browser API/provider traffic was intercepted: this is UI evidence, not
provider or proxy enforcement acceptance. The eight unchanged PNGs are retained
with a source/copy hash manifest in `x-quota-browser-evidence.Mzl4cwzo`;
preserving those files did not rerun the browser suite.

An operator may optionally set `daily_post_attempt_limit` when granting an
application permission to post to a connected X account. Omit the field for
no limit; explicit null and non-integer values are invalid. Valid limits are
1 through 1,000,000,000. Existing grants are not changed automatically.

The limit covers the verified X account across applications, credential IDs,
OAuth clients and token generations. All active grants for the same account
must agree, including whether a limit exists. Replacing an app, refreshing a
token, disconnecting/reconnecting the account or restarting Serverware does
not reset the counter. The period is a UTC calendar day. An explicit operator
change to unrestricted access is a policy change; posts during that interval
are not retrospectively counted.

This counts posting **attempts**, not successful tweets. An outstanding
reservation temporarily occupies capacity. Immediately before sending, the
proxy claims it durably and once. A claimed attempt remains charged if the
provider fails, the outcome is unknown or the claim acknowledgement is lost.
Serverware does not automatically repeat that claim or post. An unclaimed
reservation expires within its original five-second limit and before the
UTC day ends. Neither claiming nor refreshing extends that deadline.

## Deployment boundary

The optional `docker-compose.x-post-quota.yml` layer enables
`SERVERWARE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED=1` in both the app and gate.
It requires the existing ordinary managed-X runtime and curated gate, with
matching app and Rust implementations. The flag defaults to `0`. It does not
configure an OAuth application, approve an upstream or connect a real account.
It can be installed while X remains unconfigured.

The app initializes a separate quota namespace in its normal startup
transaction, retaining its initialization audit event. Existing partial or
missing required quota state is refused, not silently repaired or reset.
Rehearse this additive migration on a fresh retained copy before promotion;
preserve every pre-existing table, row, audit entry, key and identity. The
second start must preserve the initialized quota state exactly.

The UI advertises limits only when both the actual gate descriptor and the
durable store are ready. An unavailable capability is not permission to send
without the configured limit. These are trusted-host ordinary SQLite controls,
not native approval authority or protection against a privileged rollback of
the complete database and audit history.

## Required acceptance

The joined verification uses a synthetic TLS provider and actual Node, Python
and Go SDKs through the normal Rust proxy: two applications share four attempts,
with a real app/gate restart, expiry and refresh, then exhaustion and reconnect
under a new credential ID. Separate controls cover UTC rollover, expired
reservations, a lost committed-claim acknowledgement and revocation before
the final send. Pure UI or storage checks alone do not close these boundaries.
