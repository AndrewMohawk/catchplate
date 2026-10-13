> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# X account posting: implementation boundary

Status on 2026-10-12: the typed posting contract, ordinary SDK examples and
feature-gated account/permission console flow are implemented in source,
including connected consent, refresh and protective disconnect at `c207ac75`.
**This work is not deployed and has not passed actual TLS/Rust/SDK-through-proxy
or real-X acceptance.** The deployed username-read preset does not authorize
posting. No pilot is required to finish or verify this ordinary workflow.

## Fixed permission

`x.post.v1` admits only `POST https://api.x.com/2/tweets`, with no query, aliases,
media, replies, quotes or threads. The body is a duplicate-free UTF-8 JSON object
containing only `text`; original bytes are preserved. Text is 1–16,384 UTF-8 bytes
without NUL, and the complete body is at most 32,768 bytes. These are local
transport limits, not an implementation of X's weighted text or entitlement
rules. The operation is classified as a write, not as a read-only HTTP POST.

The signed credential binding selects one verified X OAuth subject and OAuth
client, with `offline.access`, `tweet.read`, `tweet.write` and `users.read` scopes.
An app-only bearer key is not a substitute. Applications send only the public
`serverware-x-post-placeholder-v1` dummy; exact Authorization replacement selects
the stored access token. Existing current-generation and credential metadata
checks remain authoritative. This adapter does not obtain consent or refresh a
token itself.

An admitted HTTP 201 response is a whole JSON object, bounded to 1 MiB. Selected
error statuses permit bounded JSON objects up to 64 KiB. Response metadata and
raw/decoded credential reflection checks remain required; no response-field
editor or projection is needed. Invalid responses after dispatch do not prove
the post failed. Existing unknown-outcome handling and the client examples
prohibit automatic replay.

The optional UTC-day quota is keyed by the verified provider account, not by
application, route, OAuth client, credential ID or credential version. All typed
posting routes for that account must agree on whether a quota exists and its
maximum. When selected, same-account legacy X writes and generic routes matching
the posting endpoint are rejected. This is a policy consistency guarantee, not
proof of a functioning quota backend. The connected console/API offers only a
quota-free typed grant and explicitly refuses requested daily-quota fields.
The required shared quota execution path remains unsupported; no local-counter
fallback or native-authority bypass was added.

## Ordinary client examples

- [Node](../examples/x-post-node/README.md): official XDK 0.6.6 and Undici 8.11.2.
- [Python](../examples/x-post-python/README.md): official XDK 0.10.6.
- [Go](../examples/x-post-go/README.md): community go-twitter/v2 2.1.5.

Each example makes one explicitly confirmed stock SDK posting call, with
separate proxy authentication and verified TLS. It never receives the real X
credential, refreshes a token or retries a write. Its success output is only the
observed HTTP 201 and decimal post ID, not submitted text or a provider response
dump. Offline SDK tests use synthetic transports; they are not real TLS,
credential-injection, consent or posting acceptance.

## Offline verification

The actual SDK examples passed 19 Node tests, 14 Python groups and 10 Go groups.
They cover exact serialization, explicit confirmation, TLS configuration,
bounded outputs, wrong statuses and refusal to replay uncertain writes. No
provider or proxy requests were made. Go additionally inspects and preserves
response bytes because its SDK omits the provider's optional `errors` field.

All 11 Python core groups passed in the retained application dependency image,
with network disabled and read-only source. These use the actual compiler,
schemas, metadata validator and parsed-field response functions, not the Python
forwarding transport: its existing credential-replacement refusal is unchanged.
The 13 X-read and 15 npm-metadata regression groups also passed. The attempted
GitHub suite stopped before test discovery because that image lacks `mitmproxy`;
it is not counted as a pass. No dependencies were installed for these checks.

All 45 selected Rust tests passed from source commit `2bc016ed`: nine new posting
tests, 11 X-read tests, 12 credential-replacement tests, eight post-dispatch
outcome tests, three provider-request tests and two legacy-X controls. The new
tests reach the real embedded v1/v2 schema compiler, OAuth metadata checks,
account-quota key/conflict rules, body preparation and bounded loopback response
finalizers. They prove neither OAuth consent nor shared-store consumption.

The test binary SHA-256 is
`7af4c9261ff7a74dcecb7558619bb52ba09e038a04ca2f53ec3dca948def2313`.
Evidence is retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/x-post-core-r3.kww8UBlX`.
Compile and test containers had network access disabled; selected response
fixtures used only their own loopback. Every owned container was removed, and
the retained cache stayed unchanged. No normal release binary was built or
deployed by this run.

Earlier evidence is retained separately: the first build was stopped after a
review found a test-fixture omission; the next build passed compilation but its
startup-schema test failed on an unsupported external fragment reference.
Moving the unchanged quota definition into the bundle's local definitions fixed
that real startup issue without widening the closed resolver. All 11 Python core
tests passed again, followed by the final Rust build and 45 passing tests above.

### Build timing is not session initialization

The first completed offline optimized Rust test build took 587.689 seconds.
Inspection found avoidable library compilation: fresh Git archives refreshed all
760 Cargo/source file timestamps, although the next change touched only two
schemas. The library's 207 recorded inputs were byte-identical and included
neither schema, but Cargo reinvoked it; that stage previously took about 286
seconds. All 223 third-party dependency artifacts remained fresh.

The new `scripts/prepare_operator_build_snapshot.py` is the build-preparation
helper for that copy step. It reads and verifies exact committed Git objects,
independently checks the entire predecessor tree, and preserves modification
times only for identical file bytes, type and mode in new inodes. It accepts the
retained archive's conventional `0664/0775` modes as well as canonical and
read-only modes; reused files keep their full prior mode. Added/deleted paths
disable all timestamp reuse. Changed/new files are strictly newer than the
caller-supplied, verified upper bound over cached dependency/build timestamps,
the captured clock and all predecessor file timestamps.

The interface requires an exact full commit ID and a new absent absolute output
directory. Reuse additionally requires `--predecessor`, its exact
`--predecessor-revision` and `--fresh-after-epoch-ns`. The helper never reads a
cache or proves it usable: receipts explicitly report `cacheVerified: false`
and `readOnlyFrozen: false`. The caller still verifies compiler/cache identity
and pins/freezes the output before running a compiler. Failures may leave the
new incomplete output for inspection, but never overwrite the predecessor.

Do not change Cargo fingerprints, use shared hardlinks or edit running compiler
inputs. The existing read-only deployment-snapshot verifier remains unchanged;
it is not a build-preparation tool. Integration with the retained one-shot build
wrappers and a measured Cargo speedup are still pending. None of these developer
builds or source inventories runs on ordinary page load.

All eight synthetic Git/filesystem groups passed in 1.799 seconds. They cover
unchanged timestamp/mode preservation without hardlinks, changed/new/deleted
inputs, dirty working files, archive attributes, replacement objects, unsafe
paths/modes/links, bounds and timestamp readback. They do not benchmark Cargo or
verify a retained cache. No real build source, cache or deployment was changed.

## Remaining work before enabling the preset

The intended story is: connect an X account in the console, give an application
a posting permission, send its ordinary SDK request through the proxy, and
inspect the durable audit result. The source now joins application configuration,
the separate `x_oauth` account type, PKCE callback, encrypted custody, refresh,
protective disconnect and capability-gated quota-free posting UI. These do not
automatically enable the feature on the running instance.

1. Execute connected acceptance with the independently joined normal Rust
   artifact, then complete the matching app/proxy release.
2. Exercise actual SDKs through verified TLS and the real proxy against an
   isolated provider, including denials, uncertain writes and durable audit.
3. Add durable shared-account quota execution before offering that restriction;
   the current account/grant flow must continue to refuse it.
4. With operator-supplied provider configuration and consent, verify the real X
   journey separately. Public proxy DNS repair remains a separate approval.

### Connected lifecycle checkpoint

`x-accounts-connected.hWXZjH/joined-05` passed four groups across five actual
ASGI workers in 83.961 seconds, with synthetic provider wire and gate health.
It exercises configuration through disconnect and a fresh-process reopen. Only
the proven `policy_candidate_authority` migration row's `applied_at` startup
stamp may change on reopen; all other retained cells, schema, key and policy
remain exact. Earlier namespace/reopen-oracle failures remain in that evidence
directory. The [lifecycle record](operator-x-account-lifecycle.md#verification-checkpoint)
also records the frozen ordinary regression's 27/29 result and the two separate
focused stale-test fixes. Hosted CI at `1ee2f04d` subsequently passed all 29
suites in 396.277 seconds, without erasing the earlier failed receipt. Corrected
Rust source `6d67ab37` passed 112 tests across 15 filters and produced
normal executable `811082ac5e87f9ec…`, with an actual 515-input compiler receipt.
This is separate from the historical 45-test core result above. The independent
join subsequently verified the normal compiler inputs against committed
`1ee2f04d`; normal-binary runtime acceptance remains pending. None of these
results establishes deployed or real-X posting.

### Ordinary X account ownership contract

The operator journey is **configure the X application once → connect an account
→ give one application permission to post**. Configuration, account consent and
posting readiness are separate states. App-only username lookup stays separate;
it must never be relabelled as a user account or a posting permission.

The configuration preset is `x_text_post_v1`. The server fixes its four
scopes, confidential-client authentication, provider endpoints and callback
`/api/oauth/callback/x`. The administrator supplies only the client ID and a
write-only client secret, alongside the normal operation/revision/policy guards.
A public profile describes configuration; neither its digest nor a validated
input object proves ownership, activation or permission to contact X.

`operator_x_configuration.py` now joins first-save configuration, its dedicated
SQLite custody namespace, one catalog revision and one audit event in the same
publication-owned transaction. The authenticated API and Proxy setup panel use
`/api/operator-demo/oauth/x/configuration/v1`; exact actor-owned operation GETs
recover a lost save response without resubmitting. Discovery uses an existing
read-only database and authenticates retained ciphertext; missing or corrupt
state is not silently initialized. Existing credentials, applications, permissions,
signed policy and upstream settings are unchanged by saving an X application.

This configuration is per-operation control-plane state, not Google's cold
app/proxy profile selection. Saving requires no restart and does not populate
global X OAuth settings. Actual process admission still excludes native/enrolled
ownership. Consent, refresh and cleanup owners bind the exact retained
configuration version before contacting X. Client-configuration replacement and
disabling remain refused; account disconnect does not implement those separate
configuration-change workflows.

The deployment owner must explicitly select
`SERVERWARE_OPERATOR_MANAGED_X_ENABLED=1` and an existing private 0700
`SERVERWARE_OPERATOR_X_CUSTODY_DIR`, mounted only in the app. This directory must
be separate and non-nested from both app data and Google's provider key directory;
it must also be kept out of gate/notification mounts. The normal Compose
deployment has not been changed or enabled by these source additions. X controls
stay hidden when the deployment reports the feature disabled. When selected,
account consent and new posting grants additionally require the actual matching
app/gate configuration and policy observation; saved configuration alone cannot
make them ready. Protective disconnect and operation recovery remain separate
from posting readiness.

The public profile/input validator remains separate from ownership admission.
Write-only serialization omits the client secret; the connected HTTP handler
returns fixed errors instead of raw Pydantic diagnostics. The browser clears
secret fields after request serialization or navigation and retains only a public
operation UUID for recovery, with explicit guidance after an uncertain reload.

Source verification on 2026-10-12 covered 132 focused tests/groups: 24 X custody,
27 provider-key, 12 admission, 9 API, 12 real-service, 2 full-application ASGI,
14 offline UI, 11 read-only bridge and 21 renderer/asset controls. The real-service
reopen fixture initially omitted publication startup admission; that fixture was
corrected and its one failing group passed independently. The full-ASGI harness
initially omitted the runner's private-file umask and compared HTTP header names
case-sensitively; both test-only mistakes were corrected without relaxing runtime
checks. Both full-app stories then passed in 27.474 seconds, including real
administrator/Origin checks, encrypted readback, preserved existing resources and
policy, one revision/audit event, lost-response recovery, and missing-key refusal.

Backend checks used the retained application dependency image with networking
disabled, read-only source and fresh disposable data. UI and browser-helper tests
used inert DOM/transport fixtures: no rendered-browser, real-provider, Internet
proxy or deployed-X acceptance is claimed. No Rust build, service restart, DNS
change or pilot ran. The operator-owned private evidence directory is
`serverware-operator-workspace-evidence/x-configuration-connected.basqSwQ1`.

`operator_x_oauth_protocol.py` additionally builds private request descriptions
and classifies supplied token, identity and revocation responses. All ten
synthetic protocol groups passed under the same offline/read-only conditions.
It implements form-encoded confidential-client Basic authentication, S256,
bounded duplicate-aware JSON and valid chunked-response metadata. Malformed or
mixed token/error replies retain private raw material; omitted scopes or a
missing returned refresh token remain uncertain under this conservative preset,
not rejection or permission to reuse the old token. It assumes no unconditional
refresh-token rotation guarantee.

These codecs are not themselves a transport or lifecycle owner. Request reconstruction
checks client/phase consistency, but a parsed success or denial is not proof of
provider contact, verified account ownership or permission to retire cleanup.
The connected owner now supplies the bounded no-redirect transport and durable
material retention; joined tests feed synthetic wire, not real provider TLS.
Revocation recognizes bounded empty HTTP 200
and exact JSON `{"revoked":true}` acknowledgments; neither proves propagation.
The latter shape is supported by X's [official TypeScript OAuth client](https://github.com/xdevplatform/twitter-api-typescript-sdk/blob/main/src/OAuth2User.ts),
while endpoint and confidential-client behavior follow the [X OAuth flow guide](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token).

The source now joins these owners; deployment and provider acceptance remain
separate:

| Boundary | Required owner and durable result |
| --- | --- |
| Configure | Implemented in source: explicit ordinary-development admission, provider-disjoint retained configuration/custody, exact version and atomic audit/revision. No restart or provider contact. |
| Consent | Implemented: actor-owned X intent, browser-bound one-use state and S256 PKCE, exact profile/revision checks, and retained cleanup capacity before code exchange. |
| Connect | Implemented: verify `/2/users/me`; atomically join encrypted token, credential generation, X catalog identity, completed intent, cleanup disposition and audit. No implicit app grant. |
| Refresh | Implemented: retain issued material before validation; atomically join replacement generation and audit. Preserve uncertain outcomes and original-client cleanup custody; no automatic replay after a CAS conflict. |
| Disconnect | Implemented: fence credential and dependent permissions locally, publish reduced policy, then perform provider cleanup outside publication/DB locks. Local denial is distinct from provider acknowledgment. |

Stable numeric user ID is authority; `@username` is display metadata. Keep the
current core X client binding (`x_app_id`) and any new public configuration
binding consistent through explicit validation. Do not send X intent tags into
Google's `profile_for_refresh`, adopt untagged legacy X credentials, enable the
generic OAuth routes, or remove native/enrolled-writer refusals.

Google's existing custody table has a global configuration-version key and its
reader validates the entire retained version roster. X must not add rows to it.
The X store uses its own `operator_x_provider_custody` namespace and its own
app-only key directory. First-key initialization refuses retained X configuration
or custody objects; Google first-key initialization is unchanged. There is no
shared provider-key bootstrap or cross-provider key adoption.
Decryption alone does not select the active profile/version. Client replacement
remains refused until a reviewed configuration-rotation workflow preserves all
original-client account and cleanup obligations.

Neither X consent nor posting capability should appear ready merely because a
profile parses or the app is healthy. Posting additionally requires the actual
matching proxy binary, loaded policy and selected configuration. Account-wide
quota remains unavailable until its real shared backend is connected; a local
counter or relaxed PostgreSQL authority check is not a substitute.

Provider references: [Create Post](https://docs.x.com/x-api/posts/create-post)
and [OAuth authorization code flow](https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code).
