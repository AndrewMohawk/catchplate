# npm package publishing

The `npm.publish.v1` adapter and `npm_publish_v1` operator permission authorize
publishing new versions of **one exact package with one configured tag**. The
permission also includes metadata GETs for that same package. This is separate
from the metadata-only preset and the legacy `npm.registry` approval workflow;
neither existing permission is automatically upgraded.

**Verification status: the complete isolated stock-client flow and two retained
cold starts passed for app `37241109` and gate `82a99cf0`. No live rollout or
public npm registry acceptance is claimed.** See [run twenty](#run-twenty-complete-isolated-stock-client-flow-passed)
and the [retained-state rehearsal](operator-managed-retained-verification.md#npm-candidate-two-retained-cold-starts-passed).
Earlier failed runs and their original evidence boundaries remain documented below.

## Operator workflow

1. Select an existing named npm-token connection (`npm_token_v1`), or save one.
   The real npm token remains in Serverware. Saving it does not verify the npm
   account, package rights, expiration or provider policy, and does not renew it.
2. Choose the application and **Publish package**. This option requires the
   matching app/gate capability and an operator-approved
   `https://registry.npmjs.org` destination. Saving a token alone does not approve
   that destination or give the application publishing authority.
3. Enter one exact lowercase package name, including its scope if applicable,
   and the tag. The default tag is `latest`; tags must match
   `[a-z][a-z0-9._-]{0,63}`. No wildcard, dependency expansion or arbitrary URL is
   accepted. The grant permits new versions of this package, not only a single
   version selected when the permission is created.
4. Optionally select daily publishing hours in UTC. The start is inclusive and
   the end exclusive: `09:00`–`17:00` allows publishing from 09:00 until just
   before 17:00 UTC. Both use `HH:MM`, with start before end; overnight windows,
   equal endpoints and `24:00` are not supported. No window means any time.
5. Review and explicitly save the permission. Use its copied client recipe only
   after reviewing the local package, version and intended publication.

Publishing hours constrain the PUT, including its check before forwarding. They
do not schedule a future publish or create an approval request. The companion
bodyless metadata GET remains permitted outside these hours, subject to the
application's token, policy and provider rights. Both routes belong to one saved
permission, so revoking it removes both grants.

Only one active npm metadata **or** publishing permission is supported per
application. Conflicting single-segment registry GET/PUT rules are refused. Reuse
an appropriate existing permission or explicitly revoke the conflict before
creating a replacement; the UI does not merge, broaden or revoke grants for you.

## Stock npm client recipe

The recipe targets ordinary npm **11.8.0** on Node.js **25.5.0**, without replacing
its transport. These exact versions passed the isolated seven-phase flow in
run twenty. Use the exact application ID, HTTPS proxy authority and CA material
shown by your deployment; the placeholders below are not a working endpoint.

Save a dedicated `serverware-npm.npmrc`. Keep the `${...}` references literal in
the file. `SERVERWARE_PROXY_TOKEN` is the **application's Serverware token**, not
the provider's npm token. The registry value below is intentionally public dummy
data, which Serverware matches before injecting its saved credential.

```ini
registry=https://registry.npmjs.org/
https-proxy=https://<application-id>:${SERVERWARE_PROXY_TOKEN}@<proxy-host>:<proxy-port>
//registry.npmjs.org/:_authToken=serverware-npm-placeholder-v1
strict-ssl=true
noproxy=
fetch-retries=0
update-notifier=false
cache=${SERVERWARE_NPM_CACHE}
```

Use a clean client environment and a fresh private cache directory named by
`SERVERWARE_NPM_CACHE`. Remove conflicting inherited npm, proxy and TLS settings.
Load the extra CA before Node starts. `NODE_EXTRA_CA_CERTS` adds trust while
retaining Node's default roots; if the outer HTTPS proxy uses a private CA, the
scoped extra-CA file must contain both that CA and the interception CA. Keep TLS
verification enabled; do not add a `cafile` override or disable `strict-ssl`.

The following is an explicit **public-publishing** example. `./package.tgz` must
already be a reviewed local tarball whose manifest name matches the saved
package. Replace `latest` with the permission's exact tag when different. Review
any package-specific publishing configuration too; it cannot broaden the grant.
This command changes the registry and is never run by the setup page:

```sh
NODE_EXTRA_CA_CERTS="$(realpath ./serverware-ca.pem)" npm \
  --userconfig ./serverware-npm.npmrc --globalconfig /dev/null \
  publish ./package.tgz --access=public --tag=latest \
  --ignore-scripts=true --provenance=false --force=false \
  --dry-run=false --workspaces=false --json
```

The saved npm token must permit noninteractive publishing under the provider's
own policy. The proxy's app-token validity and publishing permission cannot
override a provider rejection. This recipe does not establish compatibility with
other npm versions or the client's default retry settings.

## Request and response limits

Publishing is an HTTPS PUT to the selected package at `registry.npmjs.org`, with
no query string or redirect authority. The JSON request must contain one version,
one configured dist-tag and one attachment. Package/version identities and the
attachment's declared length, canonical base64, SHA-512 integrity and SHA-1
shasum must agree. Scoped names use the canonical encoded package path.

The full request is limited to 16 MiB and the decoded tarball to 8 MiB. Its sole
manifest has a conservative budget of 65,536: JSON punctuation, escaped UTF-8
strings and literals use their compact byte counts, while every finite numeric
node costs 320. This is not an exact serialized-length allowance. Dynamic
manifest fields remain bounded; the closed `dist` object admits only integrity,
shasum and tarball metadata. Additional `dist` fields or extra provenance
attachments are refused, not removed.
Validation preserves the accepted request bytes. It does not extract or scan the
archive, verify its contents are safe, or fetch a tarball. Stock npm's HTTP-valued
`dist.tarball` is inert metadata; the actual publish transport remains HTTPS.

Publish success and selected error responses must be nonempty strict JSON
objects with `application/json` (optionally UTF-8 charset), at most 64 KiB.
Admitted statuses are 200, 201, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503
and 504. Credential-reflection checks precede release; bounded unselected HTTP
metadata is checked and discarded. Compression offers are discarded and encoded
upstream responses are unsupported. There is no response-field setup or
unchecked pass-through mode. The companion GET retains the separate
[metadata response contract](operator-npm-metadata.md#authority-and-response-limits),
including its 1 MiB success and 64 KiB error limits.

## Uncertain publication and unsupported operations

A timeout, lost reply or blocked response can occur **after** the registry has
received the PUT. Treat the write outcome as unknown, not as proof that nothing
was published. There is no automatic retry or exactly-once guarantee. Inspect
the package's registry metadata and Serverware audit evidence before deciding
what to do; a single missing version observation is not proof an in-flight write
cannot still finish. Do not automatically repeat `npm publish` or add a generic
retry loop. Likewise, a lost permission-save reply requires inspection of saved
state, not an automatic second grant request.

This profile does not authorize installation, tarball downloads, unpublish,
standalone tag administration, staged publishing, npm audit, provenance,
provider 2FA, trusted publishing, token renewal or a JIT approval ceremony.
It does not modify the legacy adapter's approval requirements. The broader
requirements remain in [ordinary npm client compatibility](operator-npm-client-compatibility.md).

## Verification boundary

The current bounded checks passed:

- 77 focused Python tests covering protocol, catalog, metadata, publishing hours
  and events at `37a3b36d`.
- UI source and pure checks, plus six of six rendered-browser groups, at
  `e841f843`. These do not execute a real registry publish.
- 23 of 23 stock-fixture pure tests at `477efa5a`. These inspect the fixture/checker contract,
  not a running stock client.
- 27 of 27 fixture tests at `918d5bb7`, including four groups executing the
  actual JavaScript classifier/job with synthetic I/O in a bounded Node VM.
  Fixed diagnostic labels distinguish stdout shape, error-code presence and
  selected npm/fetch contexts without exporting summaries, URLs or raw output.
  The four accepted denial codes and positive receipt checks are unchanged;
  HTTP 503 and fetch timeouts remain failures. These tests are not stock-client
  runtime acceptance.
- Nine audit-timing tests and five existing legacy scheduling tests pass with
  the timing hooks. The new checks exercise the registered ASGI route/middleware
  and real Ed25519 signing with synthetic storage/context/key inputs: traced,
  disabled and failed-diagnostic responses are byte-identical, rejected requests
  emit no observation, and cancellation retains the shielded worker slot until
  completion. The real policy getter/loader also preserves lock scope, cached
  validation order and fresh copies under synthetic external I/O; event-driven
  contention separates lock waiting from loader work. These are not policy
  authentication, database, service startup or deployment acceptance tests.
- 33 of 33 genuine Rust tests at source commit `58b10689`: 11 publishing,
  15 metadata and seven shared send-deadline/revocation regressions. A separate
  normal gate binary was then built, SHA-256
  `09b9551d63b77353b50cd52aa0beb2e746314ff4f2e16a469b7017555f13abff`.
- 49 of 49 genuine Rust tests at `15119cfe`, including the earlier 33, eight
  static-preparation checks and eight bounded acquisition-diagnostic checks.
  An interleaved diagnostic/libtest-log parser refusal was corrected before
  running the remaining eight checks; the first 41 tests were not rerun or
  replaced. The separate normal binary is SHA-256
  `3ab55d012e6ae8aa2681cc833fb869a08556a99011b122d242e4700ad4ecbb46`.
- 11 of 11 actual SQLite outbox checks at `f6352287`. Empty fresh SQLite drains
  now avoid acquiring a write lock; pending/claimed work retains the locked
  re-read, audit append and terminal update. PostgreSQL and active borrowed
  transactions keep their existing behavior. These tests do not establish
  end-to-end latency or a permanently empty queue.

The earlier failed Rust run and first two bounded stock-checker failures remain
retained. A third isolated stock run passed the exact prerequisite-read and
unscoped-publish checkpoints, including the corrected framing and keep-alive
checks. It then stopped: the scoped npm client exited with status 1 after the
synthetic registry returned HTTP 400, and only the unscoped version was stored.
The third failure is retained. A fourth diagnostic run completed the
prerequisite-read, unscoped-publish, scoped-publish and wrong-package checkpoints,
storing two fixture publications. The scoped HTTP 400 did not recur. This run
then stopped at the outside-window control: stopped-state evidence shows both
GET and PUT denied with proxy credential-generation-unavailable HTTP 503
(`credential_generation_missing`) before the intended time-window guard.
This is not proof of the expected HTTP 403 time-window denial. The client exited
with status 1; its exact npm error code was not established. Five earlier
upstream releases completed, and both scoped and unscoped versions were stored.
The gate logged lease-renewal failures; their underlying cause remains under
diagnosis.

A fifth isolated run at `15119cfe` completed prerequisite reads and both
unscoped/scoped publications, then failed the unchanged zero-audit-failure
requirement. Its retained diagnostic records a transport-stage failure with
3,095 ms total attempt time and unknown HTTP status and delivery outcome. This
duration includes publication-lock/policy work; it is not an HTTP-only timing
or proof of the underlying transport error. Observed application
HTTP 200 audit responses cannot be correlated to that failed batch, and no
static acquisition-failure diagnostic was emitted. The run stopped before the
remaining controls; it neither repeats nor resolves the fourth run's 503.
Both source and stock npm inventories remained unchanged after teardown.

The app-only SQLite optimization at `f6352287` retains the same normal Rust
binary: all 497 compiler inputs and all 740 crate files match `15119cfe` byte
for byte. No new Rust build is claimed. A sixth isolated run of this pair
completed prerequisite reads, both publications and the wrong-package
checkpoint. The audit transport failure did not recur in its retained log;
this is not causal proof that the optimization resolved it. The run stopped
on the outside-window npm command (exit 1, `npm_denial` stage, closed error code
`unrecognized`). The stopped database contains six response-release events
and the three earlier expected 403 denials, but no outside-window denial
record. Neither the intended time-window 403 nor a repeated 503 is established
for this run. Seventeen lease-renewal warnings remain, without a static
preparation diagnostic. Generation acquisition and pre-diagnostic admission
paths remain under investigation.

All sixth-run containers were removed, private evidence retained, and the
4,933-file source and 1,782-file stock npm inventories remained unchanged.

A seventh isolated run at `918d5bb7` used the same verified normal Rust binary
and unchanged limits. It completed prerequisite reads, both publications and
the wrong-package command, then failed that command's audit checkpoint before
attempting `outside_window`. The initial four-event audit POST failed at the
transport stage with an unknown status/outcome and 3,112 ms total attempt time;
the snapshot and policy sequence remained unchanged. This duration includes
pre-HTTP work. It is not an HTTP-only timing or proof that the receiver did not
commit. Ten background lease-renewal warnings were also retained. No npm client
failure fields were emitted, so this run neither reproduces nor resolves
the sixth run's outside-window error. All seventh-run containers were removed,
private evidence retained, and both complete source/npm inventories remained
unchanged. App-side audit admission, commit and response timing still need to
be distinguished; unrelated HTTP 200 access-log entries cannot identify the
failed batch's acknowledgement.

An operator-development-only audit timing observation now separates worker
admission/executor wait, ingestion, post-request outbox draining and response
signing milestones. It activates only after the existing token and batch
validation. At most 64 terminal records per process contain a public batch
digest, event count, fixed outcome and monotonic millisecond marks; no body,
token, nonce, URL or exception text is exported. The clock starts after parsing,
so it is not total HTTP latency. Missing/capped observations prove nothing,
and `complete` means the original ASGI send returned, not that the gate accepted
an ACK. Diagnostic locks never wait; the stderr sink is synchronous after send
and is not claimed to be immune to backpressure. Worker bounds, shielding,
database operations, signed response contents and deadlines remain unchanged.
This source diagnostic is not a live deployment or a latency fix.

The ninth-run observation added fixed marks immediately before and after taking
the existing policy-snapshot lock. Together with the policy-completion mark,
these distinguish mutex waiting from loader/validation/copying time. They apply
only to the already-admitted audit signer; ordinary calls kept their existing
argument-free path, and that revision changed neither lock scope nor policy checks.

An eighth isolated run at `7989eee9` used the same verified normal Rust binary
and unchanged limits. It completed prerequisite reads, both publications and
the wrong-package checkpoint, then stopped on the outside-window npm command:
exit 1, `npm_denial` stage, recognized `E503`, with closed `npm_error` and
`http_error` labels. No gate audit-post failure was recorded in this run. All
24 emitted application timing records report `complete`; their maximum
post-parse duration is 1,564 ms. The largest measured signing-policy lookup
interval is 1,136 ms, combining global-lock wait, loading/validation and snapshot
copying. It does not yet identify which of those operations caused the delay,
explain earlier audit transport failures or prove the cause of this npm 503.

The stopped database passed `quick_check` and contains 62 lease-issued events,
zero lease-rejected events, six response releases and only the three earlier
403 denials. It contains no outside-window denial, so the precise proxy error
and intended time-window 403 remain unproved. Nineteen background lease-renewal
warnings were retained. All eighth-run containers were removed, no project
network remained, private evidence was retained, and the complete 4,935-file
source and 1,782-file npm inventories remained unchanged after teardown.

The ninth isolated run at `ffd635a0` reproduced the outside-window `E503` after
the same four successful checkpoints. Its 23 emitted audit observations all
report `complete`, with a maximum post-parse duration of 1,947 ms. Waiting for
the existing policy lock reached 1,268 ms; loading/checking/copying after
acquisition reached 727 ms. Those maxima belong to different requests. Across
the observations, those intervals totaled 4,608 ms and 3,945 ms respectively.
This proves meaningful lock contention, not the exact cause of the npm 503.
No audit-post or static-preparation failure diagnostic was retained; 16
background lease-renewal warnings remain.

Stopped-state scope projections for both the eighth and ninth runs confirm
the sixth response release was the outside-window metadata GET. The ninth
store contains 63 lease issuances, including two generation and two secret
issuances for the outside-window publish route; issuance is not proof of proxy
receipt or acceptance. Both runs contain only the three earlier request denials,
five established/keep-alive CONNECT pairs, and no upstream-resolution or CONNECT
denial. The failed command exits before its audit-drain checkpoint, so missing
later denial records cannot locate the failure. Ninth-run cleanup completed,
and both full source/npm inventories remained unchanged.

The subsequent concurrency change gives each caller a private loader seeded
from the shared cache. Every existing file, trust, publication, high-water and
snapshot-copy check still runs for that caller, outside the short bookkeeping
lock. Explicit invalidation generations and configured-path/loader/configuration
checks prevent an older reader from repopulating invalidated state. Concurrent
fills can agree only on the complete file/trust identity and policy authority;
the caller returns its own verified snapshot, never another reader's cached
result as a fallback. A late failed read cannot clear a newer winning cache.
The global loader identity and existing outer-lock publication consumer remain
supported. The cache generation is not publication authority, and the existing
compiled-route-authority alias is unchanged; this is not new object-graph
hardening. With this change, the interval after initial lock acquisition includes
validation/copying and final merge-lock waiting, not just loader work.

The focused concurrency, audit-timing and legacy scheduling batch passed all
24 tests in 0.530 seconds in the isolated retained Python image, with no
network or writable source mount. The concurrency controls use the actual
getter/loader with synthetic external policy I/O; the publication-owner checks
are source checks, not publication-transaction acceptance. This result does
not establish runtime latency improvement or resolution of the stock npm 503.

A tenth isolated run at `5a6519ef` retained the same normal Rust binary and
unchanged limits. It completed the prerequisite command, then the unscoped
publication failed with npm `E503` (`npm_process`, exit 1, 213 stdout bytes,
zero stderr bytes). This earlier failure is not a repaired end-to-end flow.
All 11 admitted audit observations completed; initial policy-lock waiting was
zero milliseconds in all 11, but validation/copying/final-merge time still
reached 1,105 ms and the complete observed audit path reached 1,456 ms. The
observed initial-lock contention is absent in this run, not proof that total
latency or publication reliability improved. Ingestion reached 342 ms, outbox
work 379 ms, and the pre-sign scheduling gap 1 ms (different-record maxima).
One renewal warning and no audit-post or static-preparation failure record were
logged. A complete ASGI observation still does not prove receiver acceptance.

The stopped tenth-run database passed `quick_check`: two response releases
were prerequisite and unscoped metadata GETs, with one earlier request denial,
two established CONNECTs, one keep-alive event and 14 issued leases. Unscoped
primary-route generation and dispatch leases were issued, but issuance does
not prove receipt or admission. No CONNECT or upstream-resolution denial was
stored. As above, immediate failure teardown can precede optional audit
delivery; these absent rows do not identify the terminal 503 cause. Cleanup
completed and all 4,936 source and 1,782 npm files remained unchanged.

The follow-up failure-only observer performs at most four existing health GETs
and one bounded durable audit GET after a terminated npm child fails. It keeps
both original deadlines, never retries the command, and re-raises the original
failure. Only fixed statuses, validated queue/failure counters and a durable
event count enter the failure receipt. A sampled empty queue is not successful
delivery or proof that an earlier timed-out operation has finished. The success
path and acceptance predicate are unchanged. All 32 fixture controls passed in
0.798 seconds in the isolated retained client image, including five new observer
groups and four existing Node-VM groups. An initial app-image attempt stopped
at the first Node launch because that image lacks `libatomic.so.1`; the corrected
run used the same client image and Node binary as the stock fixture. These are
synthetic fixture controls, not another end-to-end publication run.

The Rust follow-up observes the existing guarded-write result at both ordinary
503 sites in `forward_absolute_request_to`: upstream preparation and the final
buffered response. It excludes proof requests, production and non-operator or
non-legacy profiles. At most 64 records contain a fixed call-site boundary,
allowlisted response-body category, body shape and write-result boolean. It
does not log raw response text, identifiers, URLs, credentials or hashes, and
does not change response bytes, admission, deadlines or the original return.
Classification is bounded to 24 KiB total, 8 KiB headers and 16 KiB JSON; its
additional sensitive JSON temporary is scrubbed after use. Unknown or malformed
503 bodies produce only a fixed unclassified category. A matching body label
does not prove its producer or internal cause, and a completed guarded write
does not prove client receipt. The stderr sink is synchronous, not a guaranteed
nonblocking channel.

At `dbcb36d47f8de737876689e9105f4aea657ba50d`, a genuinely recompiled Rust test
binary passed all **62** selected controls, including 13 new response-diagnostic
checks, with no failures or skips. The eight test phases executed in 5.55 seconds
after compilation. A separate normal release build also completed successfully;
its SHA-256 is
`92ee92a218e3aa97df228b055c10a528935a294dd016fe0e070ac7001ac4dc33`.
Both builds used the same frozen 4,938-file source tree and offline dependency
inventory. These are fresh test executions, not a relabelled earlier binary or
combined historical pass count. Build and test receipts are retained in
`serverware-genuine-rust-response-diag.j5yQ1LeF` under the private evidence root.

The eleventh isolated stock-client run used that exact new normal binary and
source, with unchanged deadlines, resource limits, seven-command recipe and
acceptance predicate. It completed prerequisite and unscoped client commands,
then stopped on **ordinary audit delivery failed**. The gate recorded one
initial audit transport failure with unknown outcome at an attempt age of
2,947 ms, for a two-event batch with matching policy snapshot and sequence.
That timer includes preflight work before HTTP execution; it is not measured
HTTP transport latency. This is not an npm
503 reproduction or a passing publishing flow. The npm-child failure observer
was not invoked because this failure occurred at the subsequent audit check.

All 12 admitted app audit observations completed, with elapsed time reaching
1,164 ms. Initial policy-lock waiting reached 1 ms; validation/copying/final
merge reached 479 ms, ingestion 209 ms, and outbox work 492 ms (different-record
maxima). These app observations are not correlated to the failed transport
batch and do not prove acknowledgement. Two renewal warnings were logged;
no terminal-503 or static-preparation failure observations were emitted.

The stopped database passed `quick_check` and retained three response releases
(prerequisite GET, unscoped metadata GET and unscoped PUT), one earlier request
denial, two established CONNECTs, two keep-alive events and 17 issued leases.
The isolated project containers and networks are absent after cleanup; all
4,938 source and 1,782 npm files remain unchanged. The one-shot run receipt and
logs are retained in `serverware-npm-publish-runner.50YMCZ2u`; runtime data is
preserved in `serverware-npm-publish-private.AmyKEaAg`. Nothing was replayed or
promoted to the live demo.

The next narrow control-plane correction changes operator high-water reads to
select only `sequence`, `policy_hash` and `updated_at`, instead of also fetching
the full signed policy. It also deterministically closes its owned SQLite
connection: the former connection context committed/rolled back but did not
close the handle. No authority check, publication check, transaction borrowing,
deadline or cache lifetime changes. All **6** new real-SQLite test groups pass
in **3.285 seconds**. Two selected controls against frozen `dbcb36d4` detect the
old full-policy read and unclosed handle as intended, in 3.216 seconds.

Read-only profiling on a private copy of the stopped 1,335-object database
measured new-connection WAL/schema initialization at a median 21.636 ms over
21 opens; the following three-column query's median was 0.062 ms. A separate
copy-only measurement of the actual 13,701-byte, seven-route synthetic policy
had a 1.614 ms median with one caller and 9.322 ms with four callers (40 copies
each). These isolated measurements do not attribute the failed transport or
prove full-request improvement. The initial diagnostic probes needed the
schema's REGEXP function and explicit frozen-source import precedence;
corrected probes changed no product code or live state. The reader correction
was then exercised in the twelfth stock-client run described below.

The twelfth isolated run used app source `dee69622` with the same genuine
`dbcb36d4` Rust binary (`92ee92…`); all 498 compiler inputs and 742 crate files
were verified unchanged, not rebuilt or relabelled. From 16:03:43 to 16:05:07 UTC
on October 10, it completed prerequisite and unscoped client receipts, then
ended with a generic `TimeoutError`. A client receipt is recorded before its
audit/catalog checkpoint: this does not establish that the unscoped checkpoint
finished or that the scoped npm command began. The existing receipt cannot
distinguish registry observation, audit, health or catalog HTTP reads. Neither
an npm-child failure observation nor an audit transport/terminal-503/static-
preparation diagnostic was emitted. Seven renewal warnings were retained.

All 12 admitted application audit observations completed, covering 15 events.
Observed elapsed time had a 244 ms median and 1,619 ms maximum. Initial
policy-lock and worker-slot waits were zero; policy validation/copy/final merge
had a 168.5 ms median and 1,007 ms maximum. Ingestion and outbox-worker maxima
were 309 ms and 321 ms respectively. These are different-record maxima, not
components of one correlated failed request; they do not identify the timeout
or prove end-to-end improvement from the reader correction.

The stopped database passed `quick_check`: three response releases were the
prerequisite GET, unscoped metadata GET and unscoped PUT; one earlier denial,
two established CONNECTs, two keep-alives and 11 issued leases were retained.
No CONNECT/upstream-resolution denial was stored. All project containers and
networks were removed, private runtime evidence retained, and all 4,939 source
and 1,782 npm files remained unchanged. Receipts are in
`serverware-npm-publish-runner.lOXT2PYo`, runtime data in
`serverware-npm-publish-private.fpE8q8SZ`. The run was not retried or promoted.

A second narrow lifecycle correction closes the SQLite connection owned by
`drain_metadata_audit_outbox()` after its existing transaction context exits,
including empty returns and failures. Ownership is determined on the factory
return before a borrowed facade can expose its caller's raw connection.
Borrowed handles, PostgreSQL paths, SQL, locking and audit results are unchanged.
All **18** real-SQLite controls pass in **0.055 seconds**, including seven new
lifecycle groups. Two selected tests against the frozen pre-fix source detect
three missing-close assertions in 0.008 seconds, as intended. This proves the
resource-lifetime correction, not the cause or repair of the HTTP timeout.

The checker now adds a failure-only, allowlisted `failureLocation` containing
phase and stage. It distinguishes pre-client catalog, client, checkpoint
registry/audit/health and post-checkpoint catalog work, with bounded startup,
final and unknown states. These are enclosing checker steps, not transport
sub-stages or root causes. No additional request, polling, clock, retry or
deadline change is introduced; success receipts and acceptance remain unchanged.
The six new breadcrumb groups and 32 existing fixture controls all pass in
**0.856 seconds**, including the four actual Node-VM groups under synthetic
I/O seams. Review caught and corrected a test-helper ownership mismatch before
execution. These are isolated controls, not another stock-client run or a live
rollout; neither follow-up change has end-to-end acceptance yet.

A thirteenth, one-shot isolated run used source `37c12a0f` and the same
genuinely built `92ee92a2` gate artifact after verifying its compiler-input
equivalence. From **16:18:01 to 16:19:20 UTC on October 10**, it completed the
prerequisite and unscoped client phases, then failed with
`ordinary audit delivery failed`. The new breadcrumb places this at
`unscoped / checkpoint_health`: the health response failed the existing
zero-audit-failure-counter requirement, rather than a checker HTTP timeout.
The first publish and its preceding audit checks do not establish the complete
seven-phase flow.

The gate reported an initial two-event audit POST with transport-stage
`outcome_unknown`, no HTTP status, unchanged snapshot/sequence and **2,960 ms**
elapsed. That duration includes policy-refresh/preflight work; it is not an
HTTP-execution measurement or proof of the underlying cause. All 11 admitted
application observations completed, covering 13 events, with a 202 ms median
and 883 ms maximum elapsed time. Initial policy-lock and worker-slot waits were
zero. No two-event observation was retained, but its absence does not establish
whether that failed batch reached an earlier admission boundary. No terminal
503 or static-preparation diagnostic was emitted; two renewal warnings were
retained. Sampled container CPU-throttle counters were aggregate observations,
not correlated evidence for the failed POST.

The stopped database passed `quick_check`, retaining 15 issued leases, the
same three prerequisite/unscoped response releases, one earlier denial, two
established CONNECTs and two keep-alives. All project containers and networks
were removed, while private evidence was retained. All 4,940 source files and
1,782 npm files remained unchanged. Receipts are in
`serverware-npm-publish-runner.ICReyHDi`, with runtime data in
`serverware-npm-publish-private.eLoDjS3P`. The run was not retried or promoted.

A follow-up source correction extracts the existing ownership-aware outbox
context into opt-in `db.metadata_connection()` and applies it to seven more
paths: single/batch audit writes, credential lookup, both static-lease snapshots
and the operator-demo nonce reserve/read functions. The unchanged factory's
return determines ownership before context entry. Existing transaction/lock
lifetimes remain intact; only directly owned SQLite handles close afterward.
Borrowed facades and PostgreSQL wrappers retain their original behavior. No
query, validation, timeout or global connection-factory semantics changed.

All **nine** new real-SQLite groups pass in **3.434 seconds**, covering audit
replay/conflict and rollback, detached encrypted-row reads, competing-writer
exclusion across snapshot yields, nonce expiry/replay and caller ownership.
The first execution caught a fixture-only profile-mock restoration error;
correcting that test seam did not change production code. All **18** existing
outbox groups also pass in **0.053 seconds**. Two selected controls against the
frozen pre-fix `37c12a0f` source detect the missing closes in **3.203 seconds**.
PostgreSQL coverage is of its Python context wrapper, not a running server.
This establishes deterministic resource cleanup, not the cause or repair of
the transport failure.

A fourteenth, one-shot run exercised that correction at source `4364c3e6`
with the unchanged, compiler-input-matched `92ee92a2` gate. From **16:37:03 to
16:38:27 UTC on October 10**, prerequisite and unscoped client/checkpoint work
completed, including the post-unscoped catalog guard. The scoped command then
failed at `scoped / client`: npm returned `E503` with process exit 1. Two static
diagnostics identify `generation_refresh / fetch_transport`; two guarded
terminal-response observations identify `credential_generation_missing`, with
both writes completed. These identify the failure boundary, not its root cause
or independent correlation of a particular gate write to npm's response.

An initial one-event audit POST had transport-stage `outcome_unknown`, no
status, unchanged snapshot/sequence and **3,893 ms** whole-attempt elapsed time.
Its recorded retry failed preflight as `not_sent` after **5,000 ms**, without
snapshot comparisons. Those spans include preflight, not just HTTP execution.
The failure observer made four health reads and still saw queue depth 3, one
optional in-flight event, one retry batch/event and `send_failed=1`; the bounded
durable-audit read was unavailable. Twenty renewal warnings were retained.

All 12 emitted application audit observations completed, covering 15 events.
Elapsed median/maximum were 215.5/1,586 ms; policy validation/copy/final merge
were 96/1,273 ms. Initial policy-lock waits were zero, slot waits at most 1 ms
and audit-worker handoff at most 5 ms. These uncorrelated admitted observations
do not locate an unobserved transport failure. Docker's last two application
health probes exceeded their three-second limit before cleanup. The final
application exit was 137 after the runner's bounded stop, with `OOMKilled=false`;
this does not establish an earlier crash or an out-of-memory cause.

The stopped database passed `quick_check`, retaining 15 issued leases, the
three prerequisite/unscoped response releases, one earlier denial, three
established CONNECTs (including scoped) and two keep-alives. No scoped response
release or CONNECT/upstream-resolution denial was retained. All project
containers and networks were removed; all 4,941 source and 1,782 npm files
remained unchanged. Receipts are in `serverware-npm-publish-runner.zQQuTjOW`,
with private runtime evidence in `serverware-npm-publish-private.riK50xhb`.
No run was restarted and nothing was promoted. The next diagnostic boundary
is the application's actual execution state during the transport stall; these
results do not justify pooling, caching or a deadline increase by themselves.

The private diagnostic uses `scripts/operator_private_stack_diagnostic.py`
as a separately pinned, launch-only wrapper around the unchanged application
entrypoint. It first requires the real custody initializer's unconfigured
development result, the exact synthetic fixture marker and loopback-only
namespace. One 50-second watchdog writes thread frames, without local variables
or source lines, to a fresh mode-0600 file on a dedicated app-only 2 MiB tmpfs.
The original source, gate binary, client phases, deadlines and verdict remain
unchanged. Collection must happen before stopping the app because stopping
destroys its tmpfs. A missing, truncated or mistimed snapshot is inconclusive.
This instrumented run is diagnostic-only, not an equivalent acceptance run or
a production entrypoint; it does not authorize a retry of a terminal fixture.
All seven focused wrapper controls pass in the network-none pinned app image
in **0.946 seconds**, including one finite child using real `faulthandler` and
checks that local-value canaries are absent. Configuration, custody ordering
and mount-admission controls use explicit synthetic seams; they are not proof
of a running application or an actual captured stall.

The diagnostic-only run from **16:59:25 to 17:00:50 UTC on October 10** used
the same frozen `4364c3e6` application and `92ee92a2` gate, with the wrapper
from `9619c4e3`. It reproduced `scoped / client` npm `E503` after prerequisite
and unscoped completion. The bounded pre-stop collector retained a 5,664-byte
snapshot (SHA-256 `f1077a082afe14a6cf5d078668a37190acf1dc43cdec0f73a6b4514a43d34ed4`).
Three threads were inside `db.connect()` at `PRAGMA journal_mode=WAL`: response
signing's first policy high-water check, a lease's final policy recheck, and
nonce connection setup before `BEGIN IMMEDIATE`. The preceding connection
callbacks register SQL functions but execute no SQL, so this is also the first
database-touch point. The snapshot does not distinguish schema-loading cost
from locking, identify a lock owner, measure continuous waiting, or prove that
changing the WAL statement repairs the request failure.

Two generation-refresh transport failures and two guarded terminal 503 writes
were retained again. The initial one-event audit transport outcome was unknown
after 3,589 ms; its later preflight was not sent after 5,000 ms. All 12 emitted
application audit observations completed (15 events, median/maximum
334/1,412 ms); these cannot be correlated to the unobserved failed request.
The stopped copy passed `quick_check` and retained the same phase/count pattern
as run fourteen: 15 leases, three releases, one denial, three CONNECTs and two
keep-alives. Cleanup succeeded, the wrapper hash matched afterward, and all
4,941 source and 1,782 npm files remained unchanged. Receipts and frames are
in `serverware-npm-publish-diagnostic-runner.lWTJdsyo`; the stopped private data
is in `serverware-npm-publish-private.LPrK4IjN`.

`scripts/test_db_wal_connection_setup.py` then characterized disposable tmpfs
copies of that stopped SQLite database: 1,335 schema objects and 1,288,121 SQL
bytes, using the same two function-registration callbacks. Both the existing
WAL assignment and a read-mode-first alternative returned WAL on all 16 calls.
Two three-caller batches took 318–381 ms process CPU with assignment and
320–365 ms with read-first; there was no consistent read-first benefit, so no
application change was made. Synthetic held-reader, writer and schema-write
controls likewise did not reproduce a setter-specific failure.

A separate eight-call comparison serialized only the mode/foreign-key setup
statements, not connection ownership, close, later queries or transactions.
Its two three-caller batches used 119–142 ms process CPU and 101–121 ms wall
time, including setup-gate waiting, versus 135–192 ms wall time for the earlier
assignment batches. This small, separate measurement suggests initialization
concurrency is worth investigating; it does not establish the live stall's
cause or an end-to-end repair. The diagnostic uses a 0.1-second SQLite busy
timeout and copied temporary storage, not the application's 10-second timeout
or original filesystem. Original DB/WAL/SHM bytes remained unchanged.
The JSON measurements are retained beside the diagnostic-run receipts.
All four final characterization controls pass in **0.271 seconds** in the
network-none pinned app image. The execution-context receipt distinguishes
the initial two-strategy source from the later serialized-only supplement.
Before any application setup-serialization change, aggregate waiting must stay
within the existing budget and held-lock, nested-call, failure-cleanup and
process-lifecycle behavior need explicit controls. No connection pool,
authority cache, deadline increase or live rollout had been introduced at that
checkpoint.

### Bounded setup candidate and stock run sixteen

Commit `5afe10e1` adds a process-local setup gate in
`serverware/sqlite_connection_setup.py`, reached only by `db.connect()`'s
existing SQLite branch. Every caller still gets a fresh handle, both SQL
functions, row factory, WAL assignment and foreign-key enforcement. Borrowed
connections and PostgreSQL bypass the helper. The gate ends before caller
queries or transactions; it does not cache schema, mode or authority state.

The original ten-second allowance is shared by setup-gate waiting and sampled
SQLite busy-timeout allowances. Nested setup inherits the earlier deadline;
failed handles close without replacing the original exception. Returned handles
retain their original 10,000 ms busy timeout. Forked children reset the gate
and thread-local deadline; inherited SQLite handles are not made fork-safe.
Late completion is refused, but this is not a hard interruption of SQLite CPU
or filesystem work. See [SQLite's busy-timeout semantics](https://www.sqlite.org/c3ref/busy_timeout.html).

Eight focused groups pass in **3.503 seconds** in the pinned, network-none app
image. They cover real SQLite setup and foreign keys, fresh/replaced paths,
concurrency, nested/expired budgets, failed-handle ownership, a real exclusive
lock and recovery, an actual bounded fork child, and the real `db.connect()`
branch selection. Review strengthened one concurrency assertion to directly
probe lock ownership while registration is held; that affected group passes
in **0.007 seconds**. The fixture retains the original `5afe10e1` test text;
the strengthened test changes no application source. Both test hashes and
results are retained separately in `sqlite-setup-test-context.json`.

The fresh **stock** run from **17:25:10 to 17:26:40 UTC on October 10** uses
the complete 4,946-file `5afe10e1` snapshot and the unchanged genuine `92ee92a2`
gate. All 498 compiler inputs and 742 crate files match its original build.
After substituting only fresh source/job identities, the runner, inspector and
Compose recipe match run fourteen exactly. The normal application entrypoint,
all seven client phases, deadlines, resources and acceptance predicates remain
unchanged; the run-fifteen stack wrapper is absent.

This run completes **prerequisite, unscoped, scoped and wrong_package**, then
fails **outside_window / client** with npm `E503` instead of the expected
policy denial. Its one bounded 503 record is
`request_policy_deadline_invalid`, not `credential_generation_missing`.
No static-preparation, lease-renewal or audit-post failure was retained. The
failure observer successfully reads 98 durable events, with one event queued
and zero failed sends/retry batches. All 25 emitted application audit timing
records complete (30 events; median/maximum 433/896 ms); those completed
records are not measurements of the failed request or a matched latency test.

The stopped database copy passes `quick_check` and retains six releases,
including scoped metadata/publish and outside-window metadata, three denials,
five CONNECTs, five keep-alives and 64 credential leases. There is no retained
outside-window publish release. Cleanup succeeds, no project containers or
networks remain, and all 4,946 source and 1,782 npm files remain unchanged.
Evidence is in `serverware-npm-publish-runner.FTgo1eR4`; stopped private data is
in `serverware-npm-publish-private.bOrnkKZe`. The run receipt SHA-256 is
`9a6cb1794b6fdba79160394695c6d17f0fa2f09fa63f5fe4024db57e99f31a60`.

Source inspection identifies the next integration defect: matching
operator-demo shadow admission is inactive, and binding its decision time does
not evaluate the pure policy plan. Ordinary forwarding's remaining constraint
calls select rate limits only, so the request-time semantic check is skipped
before credential preparation. The late send-deadline guard still refuses the
closed window. This is not a near-expiry race: the fixture selected
06:00–07:00 UTC during a 17:25 UTC run. The required next change is to call the
existing semantic evaluator in the ordinary decision path before credential
resolution, using the same decision-time sample, while preserving quota-only
effects and the late dispatch guard. An actual operator-profile denial test
must cover this join, not just the existing time-window helper tests.

### Ordinary request admission repair candidate

The ordinary decision path now revalidates the rewritten provider target and
requires adapter rewrites to converge before binding the provider account from
the compiled credential, evaluating request semantics, and checking response
binding sources. The account and captured request fields remain in the operation
used by subsequent canonical digests and quota keys. Shadow binding and semantic
checks share one decision-time sample; a per-call test-only override permits
deterministic window controls without changing the production clock.

These checks precede new credential acquisition. X metadata acquisition moves
after them because X adapter admission consumes signed policy bindings, not
runtime credential metadata. Its existing credential validation remains intact.
Gmail's earlier cached-generation and prior-search-proof prerequisite is retained.
Rate-limit-only effect passes and the late upstream-send expiry guard are
unchanged. The repair does not substitute a shadow verdict for the ordinary
request path or broaden scoped npm admission.

This remains a repair candidate until the complete isolated stock-client
acceptance run passes. The fresh genuine Rust build and focused ordinary-path
regressions below passed; they are not a deployed repair or native pilot
acceptance.

The first `73479a8c` test compilation was deliberately stopped after source
review caught an incorrect test assertion: ordinary legacy success omits a
top-level `preview` field. The assertion now checks that absence and the actual
`legacy_rate_limits_committed` result, alongside its existing counter checks.
The interrupted compilation is not a test failure or pass. Its frozen source,
logs and terminal receipt remain in `serverware-genuine-rust-response-read.LxeT9IH6`;
the production repair is unchanged, and the corrected test requires a new
source freeze and run.

The corrected `23a7fe29` test binary compiled in **4 minutes 50 seconds**.
All **62 existing tests** passed; four of the six new groups passed, including
closed-window denial before acquisition, open-window/metadata acquisition,
missing/noncanonical response-binding sources, and X denial before generation.
Two new groups failed on fixture assumptions: the existing local quota returns
403 rather than 429, and raw colons in a date query are refused before semantic
admission. The test now requires the exact quota error and canonical `%3A`
query encoding; production behavior is unchanged. Evidence remains in
`serverware-genuine-rust-ordinary-semantics.gE6GcmF4`. The six additional exact
tests, normal release build and stock fixture did not run from that snapshot.

The final corrected source snapshot `995d5d18911256491846cf4d585f09e4a854bcaf`
(tree `494fab7775f2f5a230d670eb57ada25492782ace`, 4,947 manifest-verified
files) passed **74 tests across 15 phases**, with zero failures or ignored
tests. This includes all six ordinary decision groups and the six additional
exact semantic, response-source, provider-account, rewrite, shared-rate and
client-proof checks. Test compilation took **4 minutes 52 seconds**; the
reported test execution times totalled **6.79 seconds**.

The separate normal release build completed in **5 minutes 48 seconds** and
produced a new 40,897,712-byte executable, SHA-256
`5c803d937fa0c3fc6ee72ef73bd503e27da2756b5bfac0f590a220735d0c1fe4`.
Both runs exited successfully without OOM or deadline termination. Frozen
source, original phase logs, manifests and terminal receipts are retained in
`serverware-genuine-rust-ordinary-fixed.TJMtScbX`. Test receipt SHA-256:
`10c7b042d9cec69cc6fab8d6bb79ce41da7778e2993f550075cccd6824c28677`;
normal-build receipt SHA-256:
`05702c90c63cc158a8a2f0912151c1be450ceead8146fa2539fad18f1a36fcb6`.
This isolated dependency/build result is not production release approval.

### Seventeenth isolated stock-client run: client phases complete, audit gate fails

The fresh run used that exact source and newly built executable from
**18:07:55–18:09:29 UTC on October 10, 2026**. All seven client phases
completed: prerequisite, unscoped, scoped, wrong package, outside publishing
window, wrong placeholder and revoked application. The first six checkpoints
passed. The final revoked-application checkpoint failed with
`unaccounted publish audit event`; full acceptance and the final audit-chain
verification therefore did **not** complete.

A bounded, network-isolated inspection of a private stopped SQLite copy passed
`quick_check` and found six response releases (four metadata GETs and two publish
PUTs), six request denials and two revoked CONNECT denials. The outside-window
PUT now has the intended early 403 denial rather than the previous late 503.
The release audit's status field is 200 for both PUTs; it is not being presented
as an independently captured provider response status.

The unexpected records are two `data_plane.credential_lease.rejected` events.
Both are previous-policy `dispatchSecret` requests, ordered after the
application-revocation audit and before the gate's reload audit. One was refused
with 503 (`active signed policy bundle is unavailable`); the other with 409
(`data-plane policy hash is not active`). The database also contains 64 issued
leases, including two under the replacement policy. The retained gate log has
five renewal-failure records. No credentials were disclosed by this inspection.

The old-policy refusals are correct fail-closed broker behavior during the
publication transition; they do not demonstrate unauthorized provider dispatch.
Source review separately identifies preventable background work: queued workers
do not recheck whether their scope cooled or was refreshed, and scope-only
activity survives policy reload. The current projection cannot distinguish
already in-flight acquisitions from queued ones. A correct follow-up must
address stale work without suppressing rejection audits or claiming that a
local dequeue check alone eliminates the distributed publication race. No
renewal change or acceptance relaxation was made in this run.

The original seven phases, 64-issued-lease bound, deadlines, resource limits,
zero client retries and normal app entrypoint were unchanged. The runner exited
1 and its scoped cleanup succeeded; no fixture containers or networks remain.
Runtime files and originals are retained in
`serverware-npm-publish-private.P9QtY1Ru` and
`serverware-npm-publish-runner.f4Ash5Tj`. Run-receipt SHA-256:
`ba87a77fa9193113c6f810c89d7a892f28df3b9290c8a1947712ae43daf102c2`.
The failed fixture was not restarted, and the live demo/native pilot was not
changed.

### Background renewal repair candidate

Activity marking now holds the admitting snapshot's read guard; reload clears
that activity under its write guard. A surviving route tuple therefore cannot
inherit activity from the previous policy, and an old request cannot reinsert
it after publication. Coordinator pruning also retains the active snapshot's
read guard so an obsolete scan cannot delete newly published cache entries.
Queued work rechecks its exact scope, purpose, hotness and material freshness
without pruning caches or switching a secret task into a metadata task.

Admitted operator-static background acquisitions now coordinate with the same
pinned publication inode used by Python's exclusive publisher. Only the elected
singleflight leader acquires a separate credential lane and shared publication
ownership. It synchronizes the policy, rechecks the original task, and retains
ownership through the single signed lease response and exact cache insertion.
A changed snapshot is a refusal, never a retargeted or repeated request. A
follower holds no publication ownership while waiting for its leader.

Renewal tasks now capture a deadline at enqueue using the existing 15-second
singleflight bound, then cap it by application expiry. Publication acquisition consumes at most
five seconds of that original budget; it does not replace the operation deadline
or shorten returned material to the acquisition-only cutoff. The existing
three-second HTTP cap, five-second requested lease TTL, cache/version checks,
broker rejection auditing and final-send guards remain. Native and OAuth
acquisitions do not enter this operator-static publication lane.

The frozen regression roster retains the prior 74 tests, adds six existing
renewal/reload/singleflight controls, six new finite-executor groups, all 27
publication-owner tests and three signed publication/ACK integration tests:
116 tests across 26 phases. The new fixtures cover stale/cold/fresh queued work,
finite application expiry, exact leader/follower results, signed static lease
acquisition, publication-first reload without retargeting, deadline exhaustion,
shared-inode lane exclusion and lock substitution.

The frozen source `b55f3024a0a2e696a462df723dae9a8a1fdded6a` passed all
**116 tests across 26 phases**, with zero failures or ignored tests. Test
compilation took **4 minutes 55 seconds**; the six new background-renewal
groups completed in **0.42 seconds**. The 51,420,344-byte test executable has
SHA-256 `03eb7a78dc12da978f8fe3ee249b53c14436234fcf14b96059a4e54c71342b4d`.

Evidence is retained in `serverware-genuine-rust-background-renewal.UnelJrUY`.
Test-receipt SHA-256:
`fc98d3de725e82c22faa26fb6bd71d3853b2394717cdc977f4f8e73d401fdd88`.
The source archive is SHA-256
`73dc5eae40b46d29cedd60834d0b85a5c70ce6731b8dfb99787758be7db5b996`;
all 4,949 source files were verified against their Git blobs and modes, with
source-manifest SHA-256
`00222091afb64341390fbd9dd3f250a0b346542ea52f8d8192cea0254a20718e`.

The separate normal `cargo build --release --frozen --offline` also passed,
in **5 minutes 46 seconds**. It actually recompiled the changed data plane and
produced a 40,881,328-byte mode-0555 executable, SHA-256
`82a99cf00a7763dd1187f86607ffe2415487e98734f4b7d585f44909150e7b85`.
Its compiler dependency file includes both `main.rs` and the new production
background-renewal module. The normal-build receipt is SHA-256
`b4679c6b62b9e0add258fdc419b560d16be94e945025fc90298e881567e74382`;
the successful terminal receipt is SHA-256
`5e782979d11b6900d3923697b2d1aec11c0f9935c85189e8114a10bb6535cb17`.
The compiler exited zero with no timeout or OOM.

### Run eighteen: durable revocation, incomplete acknowledgement

The fresh stock fixture used the exact `b55f3024` source and normal executable
above. A pre-launch renderer refused an inconsistent inherited source/binary
path pair; no runtime had started. The new adapter was corrected to retain all
parent identity guards, then apply independently reviewed, counted and reversible
identity-only substitutions. No checker, acceptance predicate or runtime bound
was changed. Its SHA-256 is
`4e4168cbc7005acf1096dfd01a9a8f53b7abdec4c72fb112bb227bbc5c1f1466`.

Run eighteen ran once from **18:46:29 to 18:47:51 UTC on October 10** and
terminated with exit 1. The first six client phases and their checkpoints
completed: prerequisite, unscoped, scoped, wrong package, outside window and
wrong placeholder. The `revoked_app` phase reported **`TimeoutError`** at
`stage=unknown`, before its client command completed. That stage spans the
revocation mutation and its surrounding catalog/readiness checks; it does not
identify which request timed out. The final audit-chain verification was not
reached. Scoped cleanup succeeded, with no fixture containers or networks left.

Two bounded, network-none inspections used ephemeral copies of the stopped
database mounted read-only. They confirmed `quick_check=ok`, three active
applications and one revoked application, **42 issued leases and zero rejected
leases**, six paired credential-release/response events, six request denials,
six established CONNECT events, six keep-alive events and no revoked-client CONNECT denials
(that client phase did not run). These are retained database observations, not
a substitute for the failed client acknowledgement or full audit-chain check.

The revocation audit was recorded at **18:47:49.450576 UTC**, followed by the
gate reload audit at **18:47:50.311522 UTC**. Both match the final committed
policy hash and sequence. **No leases were issued after the revocation audit.**
Thus revocation committed and the gate loaded it; this is not evidence that
the operation rolled back or that a permanent event-loop deadlock occurred.

No completed revocation HTTP response appears in the retained access log,
while other app requests continued. The exact delay remains unproven: the
checker's per-request timeout is four seconds, publication acquisition permits
five seconds, and mutation completion also includes materialization, optional
gate/state observation and an audit-outbox drain. Overlapping publication
readers have no explicit writer-priority mechanism. These are source-level
latency candidates, not measured attribution. The next investigation must
separate acquisition, commit/materialization and response-completion timing;
do not extend deadlines, retry the mutation or remove publication coordination
to turn this failed run into acceptance.

Originals are retained in `serverware-npm-publish-runner.te64GJ1X` and
`serverware-npm-publish-private.41QYQs6r`. Run-receipt SHA-256:
`8577312237b889932373074a8a2cbde0a759d458495862b9ca7876b33c0d2984`.
Checker-result SHA-256:
`0f0ad5bdb34ce19efff6a6c842fc0fb0fde074e3f688f1ce8db8a7dacffda8bc`.
The failed fixture was not restarted. No live demo rollout or native-pilot
action was performed.

No expiry extension, retry workaround or live-deployment change has been made.
At that checkpoint, the complete stock-client flow had not passed; no production
defect was inferred.

The isolated fixture must prove metadata GETs independently: npm can suppress
preflight GET errors, so a
successful publish command alone is insufficient. No real provider token,
public registry mutation, live operator rollout or native hardware acceptance
is claimed here. Existing metadata-only acceptance does not prove publishing.

### Durable mutation receipts and bounded timing

Catalog mutation responses now describe the captured committed revision, policy
hash and sequence without a subsequent gate-health request or database read.
They return `activation: "pending"` and `loaded_policy_hash: null`, including
when policy-file materialization succeeds. Only a fresh catalog GET can confirm
that the current committed hash and the gate's loaded hash agree. One-time
application tokens remain in the original response; a materialization failure
after COMMIT must not masquerade as rollback or invite mutation replay.

Admitted operator-development mutations also have optional closed timing records
covering worker admission, publication ownership, SQLite work, commit,
materialization, receipt assembly, the existing audit-outbox drain and the outer
ASGI send. Each process attempts at most 64 records, each at most 4 KiB, with
fixed operation/stage labels and no resource identifiers, secrets or error text.
Diagnostic failures drop observations; they do not change transaction behavior,
retry work, release an active worker slot or extend a deadline. The stderr sink
is synchronous, so this is not a latency-neutral logging claim.

The terminal outcome describes response delivery, not mutation success:
`complete` can describe a successfully sent error response and is not a client
acknowledgement. Cancellation permanently seals the record even if its shielded
worker later commits. Missing marks therefore cannot establish rollback. The
stock checker now identifies each revocation read, the single POST, validation,
loaded-policy wait and warmed snapshot separately, using the same original
requests, validators and timeouts. No writer-priority change has been inferred
from run eighteen.

Focused verification passed **101 distinct checks**: 12 catalog-timing controls,
four connected mutation-receipt groups, nine existing audit-timing controls,
five bounded-worker scheduling controls, nine checker-breadcrumb groups,
32 publish-fixture/JavaScript controls, eight actual loopback HTTP lifecycle and
key-replacement groups, 13 workspace-store groups, five header-replacement
groups and four response-mode groups. These ran in bounded, network-none
containers with read-only source. The JavaScript controls used the pinned
client image and Node binary, not a package installation or provider connection.

The broader tests exposed a pre-existing positional assumption: compiled routes
are sorted by randomly generated route IDs, not catalog creation order. The
header-replacement fixture now joins both exact receipt IDs and checks the
complete two-route set, retaining the original semantic and negative assertions.
The new ASGI timing fixture also normalizes HTTP header names before asserting
`no-store`; the actual sender deliberately writes its security-header casing.
Neither test correction changes production behavior or relaxes stock acceptance.

There is no Rust source change in this repair. A new Python snapshot may reuse
the genuine `b55f3024` executable only after separately proving equality of all
499 actual compiler inputs, the complete 745-file crate and its nine external
schema inputs, including Git modes. That evidence must retain distinct source
and binary-build commit identities; it is not a new Rust build or a new run of
the previously retained 116 Rust tests. The stock-client acceptance outcome
remains separate from these focused checks.

### Run nineteen: revocation POST remains unresolved

The fresh isolated run of source `869fbbe8` ran from **2026-10-10
19:11:32 to 19:12:55 UTC** and failed with `TimeoutError` at
`phase=revoked_app`, **`stage=revocation_post`**. The first six client phases
passed: prerequisite, unscoped, scoped, wrong package, outside window and
wrong placeholder. The revoked-client command and final audit-chain check were
not reached. Cleanup succeeded; no fixture containers or networks remained.
The normal entrypoint, original deadlines and 64-issued-lease bound were
unchanged. The mutation was not retried.

The frozen-source comparison verified all 4,952 candidate Git blobs and modes,
plus the unchanged Rust input sets described above. This run reused the genuine
`b55f3024` executable; it did not rebuild Rust or rerun its retained tests.
The source-equality receipt SHA-256 is
`5b307ad51ca6fbee4e7fbba24a83c1632a6bfeb60a2ee43e4281f612c8e6df5a`.

A bounded, network-none inspection of an ephemeral copy of the stopped SQLite
database and its WAL/SHM confirmed `quick_check=ok`, **four active applications,
zero revocation audit rows, 46 issued leases and zero rejected leases**. It
also found four setup reloads, six paired credential-release/response events,
six request denials, six established CONNECT events and six keep-alive events.
Unlike run eighteen, no committed revocation was visible. The strict final-policy
inspection correctly refused its missing-revocation prerequisite, so there is
no final-policy ordering result for this run. The original storage was retained
read-only during inspection.

Nine terminal catalog timing records describe earlier setup mutations only.
They completed in 72–544 ms, with publication waits of 0–373 ms, SQLite opens
of 19–33 ms, BEGIN marks of 0 ms and commits of 4–18 ms. **There is no terminal
`revoke_application` record or completed revocation HTTP response.** Those
earlier timings do not attribute the revocation delay to publication ownership,
SQLite or any other stage, and the absent commit does not prove rollback.

The runner captured service logs before stopping the containers; a later
terminal record could therefore be absent from retained logs. A next diagnostic
can add bounded, fixed-label progress records to the admitted revocation tracker
and retain a separate post-stop log snapshot, without changing transaction
ordering or deadlines. Neither diagnostic is implemented by this checkpoint.

Originals are retained in `serverware-catalog-receipt-validation.koRjRmL8` and
`serverware-npm-publish-private.KtH13Z0W`. Run-receipt SHA-256:
`740e035d094627a603038a2e932497c5c3eadd331dbbd7e50c2d291176786efd`.
Checker-result SHA-256:
`960fa4414339f8f41161a92f423205a80aac93817547a5a3402d8e21c7585536`.
At that checkpoint, the complete stock-client flow still had not passed. No live
rollout, real provider request, notification delivery or native-pilot action was performed.

### Revocation progress diagnostics

Already admitted, input-validated `revoke_application` requests now emit a
separate `serverware.operatorCatalogProgress/v1` record at nine existing marks:
worker queue, slot and entry; publication wait and acquisition; SQLite open and
BEGIN; and commit start and completion. Each closed record contains only the
fixed operation/stage, elapsed milliseconds and a process-local ordinal.
Only the first mark is eligible; pre-activation marks are not replayed.

Progress has its own process cap of 64 attempted records and a 512-byte ASCII
line limit, leaving the terminal timing schema and its original budget intact.
Collection and reservation use nonblocking locks; failures drop observations.
The stderr sink remains synchronous, including marks taken while publication
or SQLite ownership is held. These limits bound output size, not sink latency.
No transaction ordering, admission, worker ownership or deadline changed.

A sampled mark can race terminal output. Output order is therefore not a
completion or acknowledgement guarantee, and a missing mark does not prove
that a stage was not reached. A positive `publication_acquired`, `sqlite_open`,
`sqlite_begin` or `commit_done` observation narrows the next investigation to
work after that boundary; retained database and client evidence remain required.

The timing suite passed **21 groups in 6.535 seconds** in the pinned backend
image with no network, read-only source, private temporary storage and bounded
CPU/memory/process resources. It retains all twelve terminal controls and adds
nine progress controls, including the actual bounded worker's cancellation and
the real revoke API's admission/response path. Storage callbacks in this suite
are explicitly synthetic; this is not a revocation commit or stock-client pass.

### Run twenty: complete isolated stock-client flow passed

The fresh run of source `37241109` completed successfully from **2026-10-10
19:27:55 to 19:29:18 UTC**, using the unchanged, genuinely built `b55f3024`
Rust executable. All seven stock-client phases passed, including refusal after
application revocation. The checker verified both scoped and unscoped publishes,
all six expected upstream arrivals, four prerequisite metadata releases, no
unauthorized PUTs and the complete durable SQLite audit chain. Strict TLS and
default-root preservation remained enabled; neither command nor configured
transport retries were used.

The checked audit inventory contained six release-start/response pairs, six
request denials, two revoked-client CONNECT denials, one matching revocation
and policy reload, and **36 issued leases**, below the unchanged 64-event bound.
Each completed checkpoint also enforced zero dropped, required-failed and
send-failed audit counters and a drained audit queue. Cleanup completed with
no fixture containers or networks remaining. The normal entrypoint and all
original workload, request and cleanup deadlines were preserved.

The retained pre-stop trace measured the successful revocation response at
**1,757 ms**: publication wait began at 1 ms and acquisition completed at
1,366 ms; SQLite open and BEGIN completed at 1,398 ms; COMMIT completed at
1,586 ms; materialization and publication release at 1,640 ms; and the outbox
drain at 1,745 ms. Thus publication acquisition consumed 1,365 ms in this
successful run. It does **not** establish the cause of the timeouts in runs
eighteen and nineteen. The diagnostic writes can affect scheduling; no
writer-fairness repair or general latency guarantee is claimed.

Optional post-stop log collection failed independently, before capturing any
files: the inherited cleanup listing supplied 12-character container IDs,
whereas the new helper's exact-set comparison required the full 64-character
IDs in the stopped-state projection. Its receipt correctly says `incomplete`.
The original pre-stop logs, complete revocation trace and passing client result
are intact. Do not modify or replay this terminal fixture. A fresh future
collector should request `docker ps --no-trunc` when gathering cleanup IDs and
use separate ID-format and duplicate assertions, retaining the exact join and
original cleanup budget.

Originals are retained in `serverware-catalog-timing-validation.qg5M5tPT` and
`serverware-npm-publish-private.kiNN0MiC`. Run-receipt SHA-256:
`761e89f4ddd07f939ce48b0b139e8718fb77828f4d0aab3e9426aec5b660e42e`.
Checker-result SHA-256:
`9859f6716cd159c0015f561de6630fc7b7a634fc6221f2eff307babb74c793bf`.
Source-equality receipt SHA-256:
`3b39eadb5829cb20c07f27f185829775ec9bf34798dca2ff08ee4e1c62f749ef`.

This proves the isolated flow for this snapshot, not intermittent-timeout
resolution, real npm service access, npm installation, public DNS, notification
delivery, native hardware acceptance or production readiness. No live rollout
or native-pilot action occurred. The next latency investigation should use a
controlled same-inode shared-reader/exclusive-writer concurrency test, preserving
the existing acquisition deadlines and proving cleanup after readers exit,
before selecting any publication-fairness change.

### Controlled publication-lock contention

`scripts/test_operator_publication_contention.py` passed **three groups in
21.114 seconds** in the pinned backend image, with no network, read-only source,
private temporary storage and bounded CPU, memory and process resources. Two
child processes independently open the real publication inode; the writer uses
the unchanged Python `operator_publication.exclusive()` implementation. Pipe
barriers follow actual failed exclusive-lock attempts, not simulated lock
results or scheduling sleeps.

The checks demonstrate that late shared readers can enter while an exclusive
writer waits, that continuously overlapping short readers can exhaust its
original five-second acquisition budget, and that reader exceptions and process
exit release their separate lock ownership. After readers stop, a new independent
writer succeeds; the timed-out operation is not retried or rearmed. No SQLite
database is created and no provider or native operation runs.

This is an adversarial Linux lock schedule, **not** actual Rust/HTTP traffic or
proof of the cause of runs eighteen and nineteen. It does not justify changing
the production coordination protocol on its own. The generic acceptance checker
allows at most four seconds per HTTP request; the browser allows thirty seconds,
while publication acquisition retains its five-second limit. The product
requirement is revocation enforcement after the new policy is loaded, including
warmed credentials—not a separately specified four-second revocation SLA.
Earlier fixture failures remain failures under their original limits.

No lock protocol, timeout, cancellation or authority behavior changed. Further
fairness work is optional hardening; the passing stock-client snapshot may
proceed through the existing retained-state, paired-deployment and runtime
verification gates without a speculative lock rewrite.

### Deployment preparation, not live rollout

The app `37241109` and gate `82a99cf0` were promoted to immutable artifact storage
after checking all 4,952 source Git blobs and modes and the original rich equality
receipt for 499 compiler inputs. The app snapshot and `b55f3024` compiler commit
remain distinct; this is reuse of the existing Rust build, not a new build or
fresh Rust test run. The managed deployment reviewer passed **24 tests in
0.485 seconds**. Its read-only comparison against the current live configuration
also passed, admitting only three proposed changes: app source, gate executable
and the app's expected gate digest. This configuration review follows the
[two isolated retained cold starts](operator-managed-retained-verification.md#npm-candidate-two-retained-cold-starts-passed);
it is not a live rollout. A fresh stopped-consistent backup and the normal paired
runtime/browser verification gates remain required. This candidate has not been
rolled out live.
