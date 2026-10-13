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
