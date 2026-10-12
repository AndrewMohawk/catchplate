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

## Remaining work before enabling the preset

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
