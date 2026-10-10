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
- Seven audit-timing tests and five existing legacy scheduling tests pass with
  the timing hooks. The new checks exercise the registered ASGI route/middleware
  and real Ed25519 signing with synthetic storage/context/key inputs: traced,
  disabled and failed-diagnostic responses are byte-identical, rejected requests
  emit no observation, and cancellation retains the shielded worker slot until
  completion. No database, service startup or deployment acceptance follows.
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

No expiry extension, retry workaround or live-deployment change has been made.
The complete stock-client flow has not passed; no production defect is inferred.

The isolated fixture must prove metadata GETs independently: npm can suppress
preflight GET errors, so a
successful publish command alone is insufficient. No real provider token,
public registry mutation, live operator rollout or native hardware acceptance
is claimed here. Existing metadata-only acceptance does not prove publishing.
