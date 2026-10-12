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

Future build snapshots should preserve prior modification times only for files
whose bytes, type and mode are independently verified identical, before freezing
the new snapshot. Changed/new inputs must remain newer than cached dependency
records. Reverify the exact Git tree afterward; never alter old snapshots,
shared hardlinks, Cargo fingerprints or a running compiler's inputs. The existing
read-only deployment-snapshot verifier is not a build-preparation tool. This
procedure has not yet been integrated into it or measured as an optimization.
None of these developer builds or source inventories runs on ordinary page load.

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

Provider references: [Create Post](https://docs.x.com/x-api/posts/create-post)
and [OAuth authorization code flow](https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code).
