# npm package publishing

The `npm.publish.v1` adapter and `npm_publish_v1` operator permission authorize
publishing new versions of **one exact package with one configured tag**. The
permission also includes metadata GETs for that same package. This is separate
from the metadata-only preset and the legacy `npm.registry` approval workflow;
neither existing permission is automatically upgraded.

**Verification status: focused Python, UI, fixture and genuine Rust checks have
passed; isolated stock-client runtime acceptance remains pending.**
This document describes the implemented contract and client recipe, not completed
end-to-end publishing acceptance, a live deployment, or public npm registry acceptance.

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
its transport. These versions and this publishing flow still require isolated
acceptance. Use the exact application ID, HTTPS proxy authority and CA material
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
still requires another full stock-client run.

No expiry extension, retry workaround or live-deployment change has been made.
The complete stock-client flow has not passed; no production defect is inferred.

The isolated fixture must prove metadata GETs independently: npm can suppress
preflight GET errors, so a
successful publish command alone is insufficient. No real provider token,
public registry mutation, live operator rollout or native hardware acceptance
is claimed here. Existing metadata-only acceptance does not prove publishing.
