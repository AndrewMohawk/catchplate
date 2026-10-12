> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# X account posting: implementation boundary

Status on 2026-10-12: the typed posting contract and ordinary SDK examples are
implemented in source. **Posting is not available in the operator console and
has not passed SDK-through-proxy or real-provider acceptance.** The deployed
username-read preset does not authorize posting. No pilot is required to finish
or verify this ordinary application workflow.

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
proof of a functioning quota backend. The ordinary deployment does not yet
provide the required shared quota execution path; no local-counter fallback or
native-authority bypass was added.

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
inspect the durable audit result. The first unimplemented boundary is account
connection: `operator_catalog_schema.py` admits `google_oauth` but no X OAuth
credential type, and `operator_demo.py` does not admit an X callback. Full-flow
verification stops there; the component results above do not bridge that gap.

1. Join administrator X OAuth setup, genuine account consent, verified identity,
   encrypted custody and managed refresh to the ordinary operator lifecycle.
2. Join durable shared quota execution when that optional restriction is chosen.
3. Add the capability-gated account/permission UI and matching app/proxy release.
4. Exercise the actual SDKs through the real proxy against an isolated provider,
   including denied requests, uncertain writes, quota boundaries and audit.
5. With operator-supplied provider configuration and consent, verify the real X
   journey separately. Public proxy DNS repair remains a separate approval.

### Ordinary X account ownership contract

The operator journey is **configure the X application once → connect an account
→ give one application permission to post**. Configuration, account consent and
posting readiness are separate states. App-only username lookup stays separate;
it must never be relabelled as a user account or a posting permission.

The proposed configuration preset is `x_text_post_v1`. The server fixes its four
scopes, confidential-client authentication, provider endpoints and callback
`/api/oauth/callback/x`. The administrator supplies only the client ID and a
write-only client secret, alongside the normal operation/revision/policy guards.
A public profile describes configuration; neither its digest nor a validated
input object proves ownership, activation or permission to contact X.

The public profile/input validator and explicit-key encryption primitives are
implemented in `operator_x_oauth_profile.py` and `operator_x_provider_custody.py`.
Nine profile and nine real-AES envelope tests passed in the retained application
dependency image, together with all 29 existing Google custody controls. Source
was read-only and container networking disabled. These modules create no key or
table, select no active configuration, and do not contact a provider. The existing
Google module is unchanged. Write-only serialization omits the client secret;
future HTTP handlers must still suppress raw Pydantic structured errors because
their default diagnostic objects can include submitted input.

`operator_x_oauth_protocol.py` additionally builds private request descriptions
and classifies supplied token, identity and revocation responses. All ten
synthetic protocol groups passed under the same offline/read-only conditions.
It implements form-encoded confidential-client Basic authentication, S256,
bounded duplicate-aware JSON and valid chunked-response metadata. Malformed or
mixed token/error replies retain private raw material; omitted scopes or a
missing returned refresh token remain uncertain under this conservative preset,
not rejection or permission to reuse the old token. It assumes no unconditional
refresh-token rotation guarantee.

These are codecs, not a transport or lifecycle owner. Request reconstruction
checks client/phase consistency, but a parsed success or denial is not proof of
provider contact, verified account ownership or permission to retire cleanup.
The future owner must provide the authenticated, bounded no-redirect transport
and durable material retention. Revocation recognizes bounded empty HTTP 200
and exact JSON `{"revoked":true}` acknowledgments; neither proves propagation.
The latter shape is supported by X's [official TypeScript OAuth client](https://github.com/xdevplatform/twitter-api-typescript-sdk/blob/main/src/OAuth2User.ts),
while endpoint and confidential-client behavior follow the [X OAuth flow guide](https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token).

The next integration must join these actual owners:

| Boundary | Required owner and durable result |
| --- | --- |
| Configure | Explicit ordinary-development admission, provider-disjoint retained configuration/custody, exact selected version, audit and paired activation. No browser-triggered restart. |
| Consent | Actor-owned X intent, browser-bound one-use state and S256 PKCE, exact profile/revision checks, and retained cleanup capacity before exchanging a code. |
| Connect | Verify `/2/users/me`; atomically join encrypted token, credential generation, X catalog identity, completed intent, cleanup disposition and audit. No implicit app grant. |
| Refresh | Retain issued material before validation; atomically join replacement generation and audit. Preserve uncertain outcomes and original-client cleanup custody; do not automatically replay after a CAS conflict. |
| Disconnect | Fence credential and dependent permissions locally, publish reduced policy, then perform provider cleanup outside publication/DB locks. Report local denial separately from provider acknowledgment. |

Stable numeric user ID is authority; `@username` is display metadata. Keep the
current core X client binding (`x_app_id`) and any new public configuration
binding consistent through explicit validation. Do not send X intent tags into
Google's `profile_for_refresh`, adopt untagged legacy X credentials, enable the
generic OAuth routes, or remove native/enrolled-writer refusals.

Google's existing custody table has a global configuration-version key and its
reader validates the entire retained version roster. X must not add rows to it.
Any future X tables need their own `operator_x_provider_custody` namespace, and
shared-key first initialization must check both providers' retained history.
Decryption alone does not select the active profile/version. Client replacement
must remain refused until original-client cleanup ownership is implemented.

Neither X consent nor posting capability should appear ready merely because a
profile parses or the app is healthy. Posting additionally requires the actual
matching proxy binary, loaded policy and selected configuration. Account-wide
quota remains unavailable until its real shared backend is connected; a local
counter or relaxed PostgreSQL authority check is not a substitute.

Provider references: [Create Post](https://docs.x.com/x-api/posts/create-post)
and [OAuth authorization code flow](https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code).
