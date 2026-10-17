> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Shared X posting-attempt limits

## Current deployed checkpoint

The ordinary instance now runs source
`a3899a95ce6affa88a5f27862585ef09c064d617` with normal Rust executable
`682d66d8fe97d3022513b79292bfe6710c60bfb6f54342f910da94df2db39d80`.
App `3fca3e3a…` and gate `0c323408…` passed paired and final readback in
`x-quota-candidate-readback.mTrM7n7D`; the existing edge reopened and all four
services were healthy, with no restarts, OOMs or published host ports.
The paired and final receipt SHA-256 values are
`1a703dfca03da755071fcb2cfbe122f5ffb94183f1152f4fbe54d066afa01bbd`
and `e7ba6b840acb368671811788e3747a6f2a6396e4fd8bb854ec08c8cdf6c51a6c`.

The approved first-start transition added exactly 19 schema objects, including
four quota tables. It created one state row and appended one initialization audit
event; usage is empty.
Preservation receipt
`fcdc5f420c8832fbce8702f326f05ba1e30624c6a355436b2615bc5bf4f6be10`
records the retained-state comparison. Its only existing-row exception is the
bounded `policy_candidate_authority.applied_at` startup refresh; all 495 earlier
audit entries remain, followed by the one verified initialization event.
Catalog revision 85, policy sequence 33, all 20 credentials,
21 applications and 21 rules, approved origins and CA custody were preserved.

The actual internal browser pass in `x-quota-live-browser.rSenfdNt` completed
21 GETs and seven screenshots in 27.495 seconds with zero page/console errors
or refused requests. Its receipt SHA-256 is
`c04dfeb1a1da4cb3aa230e1da31f2beddfc59850dba767ae78da1ee28bb3f701`;
durable closeout is `6c6974745c870dd211f03b7ec0db11dda740619d88d927706f460cb2357d3a84`.
This is actual app rendering, not human SSO, provider, proxy-client or CA-download
acceptance. Google and X remain unconfigured; the X quota capability is correctly
null. Deployment did not connect an account, approve an X origin or create a grant.

Isolated real-SDK verification passed the shared-limit/restart/refresh/reconnect,
lost committed-claim acknowledgement, revoke-before-release and quota-free
legacy compatibility stories below. Real-X posting and native/production
authority acceptance remain separate. Exact-source
[CI run 38377576998](https://github.com/example/private-deployment)
passed all 52 offline suites in 339.117 seconds: 452 observed Python tests,
145 Node groups and no skips.

## Historical implementation and verification attempts

The failed attempts and then-pending statements below describe their original
checkpoints; they do not supersede the current deployed checkpoint above.

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
56.977 seconds. At that checkpoint, the narrow Rust correction, joined A+B
success, separate lost-acknowledgement/revocation fault lanes, retained-data
rollout and real-X acceptance were still open; the running instance had not
received the feature.

The correction at `94b7f755` adds two real signed-metadata/lease regression
groups. Its first test compilation stopped on a missed borrow of the now-owned
injection plan in the existing Gmail fanout initializer; no tests executed.
The failed build and successful owned-container cleanup remain in
`catchplate-x-quota-rust.Wg85qphg`. The follow-up restores that explicit borrow
without changing quota, Gmail or forwarding semantics; compilation and runtime
acceptance were still required at that checkpoint.

At `5312c41b`, CI run `38361539528` passed all 51 offline suites with no
skips. The separate Rust test compilation succeeded, but its first executed
group passed 13 existing tests and failed the two new quota-release tests.
The signed audit preflight correctly rejected the fixture after its real
configuration reload lost a test-only quota selection. No audit guard was
relaxed, no normal executable was published, and the live instance was not
changed. The failed test output and successful container cleanup are retained
in `catchplate-x-quota-rust.btsZVUPw`; fixture repair and a fresh test run were
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
fixture controls pass. This needed no Rust rebuild. Full restart/refresh,
exhaustion/reconnect and separate fault-lane acceptance were then open; these
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
retained-data rollout were then still required.

The next fault attempt, `x-quota-fault-drop-healthfix.qxqHLbQD`, admitted the
relay but the normal proxy refused startup: its fixed ordinary lease URL is
`http://catchplate:3000/api/data-plane/credential-leases`, while the fixture
had substituted port 3001. No SDK ran; cleanup succeeded after 48.426 seconds.
The proxy's admission guard is unchanged. The repaired fault-only fixture
instead gives the gate a fixed loopback hosts mapping: `catchplate` resolves
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

The repaired dropped-ACK run at `a6347076`, `x-quota-fault-drop-probe.pGCAykD9`,
passed in 71.883 seconds with successful cleanup. One actual durable claim's
successful response was dropped; Node returned 409 without retry, and a distinct
Python request was denied by the exhausted quota (429 in the signed audit).
The provider received zero posts, original-client token cleanup completed,
and the audit chain verified. The terminal and checker SHA-256 values are
`188772bda64bee1976cba23aac5c8eee4c83602e5d6b0d03550a3b3719e90ab4`
and `c4712da58f78482f41c5bbbd855dc87eb584947091a5e71864048b54789d56d5`.

The first revocation run, `x-quota-fault-revoke.B108rt68`, failed on the
checker's 49th control-call admission, exceeding its 48-call budget. The relay
reached a real held claim ACK, then expired without release; no revoke request
was observed. Cleanup succeeded after 64.740 seconds. Relay lines lack timestamps,
so they do not establish precise SDK startup/selection latency. The checker now
paces pre-lease polling separately and reserves its final control calls, without
increasing any control/request budget, SDK timeout or original claim deadline.

The paced run, `x-quota-fault-revoke-paced.o54MGJmj`, reached actual rule revoke,
loaded policy and ACK release, then failed its exact SDK-status assertion.
The SDK status was not retained. Source review shows that the revoked snapshot
withholds the inner HTTP response, so the hold-mode oracle now requires Node's
exact `httpStatus: null`; dropped-ACK mode still requires 409. All unexpired-ACK,
audit, no-replay and zero-provider-post checks remain. Fresh joined acceptance
of the corrected hold-mode oracle was then pending.

The corrected run, `x-quota-fault-revoke-final.IJmy5XvP`, passed in 68.519
seconds with successful cleanup. After the claim ACK was held, actual rule
revocation and loaded policy were confirmed before releasing that ACK. Node
finished with exit 2 and `httpStatus: null` before the original claim expiry;
the provider received zero posts. `terminal.json` SHA-256 is
`3a2cfcd3e422776b6481a66361024db4ba991452fe14e3125c97ba3be996a0d3`;
the checker SHA-256 is `630e39bbd706cc6fcff67968270ca1980725a66f3230b5917697f3d8fad4b0f4`.

The separate quota-free compatibility run,
`x-quota-legacy-compatibility.wVIYY8Dy`, passed 19 SDK phases in 205.960 seconds:
six confirmed posts, one refresh, one reflection control and twelve denials,
with successful cleanup. `terminal.json` SHA-256 is
`a3be50fab95dca71e7f40a5ebb94192cd0d198dbb1b5042a76507f3e0d78629c`;
the checker SHA-256 is `ec9361aebfff81456f38e6ed2c312a608c8555dd4485f2359ee6679dac6f6b72`.
Both runs used the isolated synthetic provider, not a real X account.

The rendered account/setup suite subsequently passed all ten groups with eight
masked 1280/390-pixel screenshots and unchanged source. It verified default
omission, exact limited grants, invalid input and capability withdrawal. The
first run's stale-read test failure is retained; the correction waits for the
actual catalog response and rendered refusal, without changing product code.
All browser API/provider traffic was intercepted: this is UI evidence, not
provider or proxy enforcement acceptance. The eight unchanged PNGs are retained
with a source/copy hash manifest in `x-quota-browser-evidence.Mzl4cwzo`;
preserving those files did not rerun the browser suite.

## Limit semantics

An operator may optionally set `daily_post_attempt_limit` when granting an
application permission to post to a connected X account. Omit the field for
no limit; explicit null and non-integer values are invalid. Valid limits are
1 through 1,000,000,000. Existing grants are not changed automatically.

The limit covers the verified X account across applications, credential IDs,
OAuth clients and token generations. All active grants for the same account
must agree, including whether a limit exists. Replacing an app, refreshing a
token, disconnecting/reconnecting the account or restarting Catchplate does
not reset the counter. The period is a UTC calendar day. An explicit operator
change to unrestricted access is a policy change; posts during that interval
are not retrospectively counted.

This counts posting **attempts**, not successful tweets. An outstanding
reservation temporarily occupies capacity. Immediately before sending, the
proxy claims it durably and once. A claimed attempt remains charged if the
provider fails, the outcome is unknown or the claim acknowledgement is lost.
Catchplate does not automatically repeat that claim or post. An unclaimed
reservation expires within its original five-second limit and before the
UTC day ends. Neither claiming nor refreshing extends that deadline.

## Deployment boundary

The optional `docker-compose.x-post-quota.yml` layer enables
`CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED=1` in both the app and gate.
It requires the existing ordinary managed-X runtime and curated gate, with
matching app and Rust implementations. The flag defaults to `0`. It does not
configure an OAuth application, approve an upstream or connect a real account.
It can be installed while X remains unconfigured.

The app initializes a separate quota namespace in its normal startup
transaction, retaining its initialization audit event. Existing partial or
missing required quota state is refused, not silently repaired or reset.
Rehearse this additive migration on a fresh retained copy before promotion;
preserve every pre-existing table, audit entry, key and identity, with only the
explicitly reviewed bounded `policy_candidate_authority.applied_at` startup
refresh excepted from row equality. The second start must preserve the
initialized quota state exactly.

The UI advertises limits only when both the actual gate descriptor and the
durable store are ready. An unavailable capability is not permission to send
without the configured limit. These are trusted-host ordinary SQLite controls,
not native approval authority or protection against a privileged rollback of
the complete database and audit history.

## Acceptance boundary

The joined verification uses a synthetic TLS provider and actual Node, Python
and Go SDKs through the normal Rust proxy: two applications share four attempts,
with a real app/gate restart, expiry and refresh, then exhaustion and reconnect
under a new credential ID. Separate controls cover UTC rollover, expired
reservations, a lost committed-claim acknowledgement and revocation before
the final send. Pure UI or storage checks alone do not close these boundaries.
