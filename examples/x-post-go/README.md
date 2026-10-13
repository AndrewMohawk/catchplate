# X plain-text posting with Go

**Isolated synthetic-provider posting acceptance passed; deployment and real X
remain unverified.** This actual entrypoint passed before and after genuine
token expiry/automatic refresh through normal Rust and verified outer/inner
TLS, plus wrong-app, wrong-CA and disconnected controls. See the
[full checkpoint](../../docs/project-completion.md) for the 19-phase joined run
and retained receipts. It is not live-provider, quota or native acceptance.

This is the community `github.com/g8rswimmer/go-twitter/v2` SDK, pinned to
`v2.1.5`, not an official X SDK. It invokes the SDK's `CreateTweet` exactly once
with only `CreateTweetRequest{Text: text}`. The destination is fixed to
`POST https://api.x.com/2/tweets`; no media, replies, polls or other operations
are selected. The [pinned SDK implementation](https://github.com/g8rswimmer/go-twitter/blob/v2.1.5/v2/client.go)
accepts HTTP 201, matching the [X create-post API](https://docs.x.com/x-api/posts/create-post).

## Prepared input contract

Use only after the matching posting deployment is enabled and the operator has
issued an explicit posting grant; isolated acceptance is not live authorization:

| Input | Meaning |
| --- | --- |
| `SERVERWARE_PROXY_URL` | Explicit HTTPS proxy origin with a distinct DNS hostname; no credentials in the URL. |
| `SERVERWARE_APP_ID` | Saved Serverware application UUID. |
| `SERVERWARE_PROXY_TOKEN` | Private, issued Serverware application token, canonical 43-character base64url. Never an X token. |
| `SERVERWARE_CA_FILE` | Inner interception CA PEM bundle. |
| `SERVERWARE_PROXY_CA_FILE` | Optional additional outer proxy CA PEM bundle, alongside OS roots. |
| `SERVERWARE_X_POST_TEXT` | Exact text, 1–16384 UTF-8 bytes, without NUL. |
| `SERVERWARE_X_POST_CONFIRM` | Must equal `post-once`. This is a local intent check, not proxy authorization or a quota. |

The SDK JSON body is additionally limited to 32768 bytes, including escaping.
Newlines, tabs and carriage returns are preserved. These bounds are a supported
example profile, not complete X weighted-character or account-entitlement
validation. No naive 280-codepoint limit is applied.

The inner request carries only the public dummy bearer
`serverware-x-post-placeholder-v1`. Serverware keeps the actual
user-context X token on Serverware; this client does not perform OAuth or read
ambient X/Twitter credentials. Application Basic authentication is attached only
to CONNECT, never the inner request. Both TLS hops retain normal certificate
verification and are checked against separate per-host root sets. Nonempty
`SSL_CERT_FILE` or `SSL_CERT_DIR` is refused rather than silently changing the
process environment. Ambient proxy variables are not used; there is no direct
fallback, redirect following, disabled TLS verification, or automatic retry.

The call has a 30-second context/client deadline. Success requires HTTP 201 and
a 1–20-digit decimal post ID, and prints only `{"status":201,"id":"…"}`. Text,
tokens and provider error bodies are never printed. After dispatch, **any failure means
the outcome is unknown**, including a response withheld with HTTP 409. The post
may already exist. Inspect Serverware audit records and the X account before any
further action; never automatically replay the job. This client cannot enforce
cross-process deduplication or a shared daily quota.

Pre-invocation failures exit 1. Once the SDK call begins, failures exit 2,
including failure to write the summary after a successful post. Classification
uses a typed outcome error, not provider messages. Do not replay either an
unknown outcome or an acknowledged post whose output was lost.

A small example-level response guard limits all response bodies to 64 KiB and
refuses ambiguous 201 envelopes (including nonempty or malformed `errors`,
duplicate top-level fields, or trailing JSON). It closes the original body and
passes unchanged accepted bytes to the actual SDK. This is not SDK-native
validation: the pinned SDK's response type has no `errors` field. Absent, null
or empty-array `errors` is accepted; the SDK still enforces status 201 and the
example validates the post ID. No response status or payload is synthesized.

## Offline tests

With Go 1.23+ and the pinned dependency already present in a reviewed local
module cache, use a private build cache and disable dependency acquisition:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -mod=readonly -count=1 ./...
```

Set `GOCACHE` and `GOTMPDIR` to private test directories when other builds are
running. The tests use in-memory transports and synthetic certificates only;
they do not open sockets or call `main`. Passing them does not establish proxy
admission, server-side OAuth injection, account quota enforcement, response
release, or live X acceptance.
