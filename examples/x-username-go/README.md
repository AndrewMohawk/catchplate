# Go: look up one X username through Serverware

**Isolated SDK-through-proxy acceptance passed.** This example uses the real, pinned community
[`g8rswimmer/go-twitter/v2` v2.1.5](https://github.com/g8rswimmer/go-twitter/tree/v2.1.5/v2)
SDK, not an official X SDK. Its ordinary `UserNameLookup` call reads exactly one
saved username with no query, pagination, posting, search, OAuth exchange or
provider token in the client. The response summary contains only a user count.

On 2026-10-10, this actual entrypoint passed through the genuine Rust proxy to a
network-isolated synthetic X service, with separate verified TLS trust roots
and server-side token replacement. Wrong application, username and revoked-grant
controls were refused. The run used source `eb5d12e5` and contacted no provider.
See the [verification record](../../docs/operator-x-username-verification.md).

Separately, all six offline test groups passed using Go 1.23.12, the pinned SDK,
in-memory HTTP responses and synthetic certificates. Those tests are not a
proxy/TLS handshake or provider acceptance result.

Before using this recipe on your deployment, confirm that its complete X preset
and paired proxy implementation are available and the saved policy is loaded.
The isolated result does not establish deployment acceptance, provider
entitlement, or that your real X token is valid. The
[acceptance gates](../../docs/operator-provider-presets.md#acceptance-gates-in-order)
keep these boundaries separate.

## Configure and run

When the deployment supports `x_app_bearer_v1` and `x_username_read_v1`, save the
real app-only X bearer token in Serverware, create an application, and grant
**X username: read** for one exact lowercase username (`[a-z0-9_]{1,15}`). Select
the application's **Basic and Bearer** proxy authentication mode
(`basic_and_bearer_v1`); this recipe uses Basic authentication only for CONNECT.
Keep the real X token in Serverware, not in the application's environment.
The operator must separately approve `https://api.x.com` (HTTPS port 443); choosing
a provider or saving a rule does not approve that destination. Confirm the saved permission
and the currently loaded policy before making a lookup.

Download and verify the Serverware interception CA through the authenticated
operator setup flow. Use the HTTPS proxy URL, not the admin UI URL. Supply:

| Variable | Value |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, optionally with a port; no credentials or path |
| `SERVERWARE_APP_ID` | Saved application UUID |
| `SERVERWARE_PROXY_TOKEN` | That application's issued proxy token, **not** an X token |
| `SERVERWARE_CA_FILE` | Local PEM file containing the Serverware interception CA |
| `SERVERWARE_PROXY_CA_FILE` | Optional additional outer HTTPS-proxy CA; omit for a publicly trusted certificate |
| `SERVERWARE_X_USERNAME` | The exact lowercase username selected in the permission, without `@` |

Use an environment/CI secret store for the application token; do not place it in
command arguments, URLs or tracked files. With Go 1.23 or later:

```sh
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go run .
```

The tests use in-memory SDK responses and generated synthetic certificates; they
do not contact X or a proxy. **`go run .` makes one real read request** through
your configured proxy, subject to its policy. A matched response prints
`{"users":1}`. HTTP-200 error envelopes, missing data, wrong-user responses,
provider errors and transport failures are not reported as successful lookups.
The X response may preserve capitalization; it must match the requested username
case-insensitively. No provider profile contents are printed.

The request has a 30-second context/client deadline, a 10-second TLS-handshake
limit and a 20-second response-header limit. Redirects are not followed. There
are no application or SDK retry loops; automatic compression and connection reuse
are disabled. Inspect the saved permission and audit records before running again.

## Ordinary SDK and verified TLS configuration

The pinned [SDK lookup method](https://github.com/g8rswimmer/go-twitter/blob/v2.1.5/v2/client.go)
uses fixed `Host: "https://api.x.com"`, one username, and empty `UserLookupOpts`.
It sends `GET /2/users/by/username/<username>`, an empty query/body, and
`Accept: application/json`, without `Content-Type`. The documented
[`Authorizer` hook](https://github.com/g8rswimmer/go-twitter/blob/v2.1.5/v2/auth.go)
supplies `Authorization: Bearer serverware-x-placeholder-v1`. That is a public
dummy, replaced by Serverware; it is never a real X secret. No SDK HTTP methods
or request headers are rewritten. Standard Go HTTP/1.1 transport additionally
sends its default `User-Agent` and `Connection: close`.

The application UUID/token are supplied only to the HTTPS proxy's CONNECT request
through `GetProxyConnectHeader`. They do not appear in the inner X request or
the proxy URL. Ambient `HTTPS_PROXY`, `NO_PROXY`, `X_BEARER_TOKEN` and
`TWITTER_BEARER_TOKEN` are not read; there is no `.netrc` or provider-token
discovery. No direct-network fallback is configured.

Go shares one TLS configuration between outer proxy TLS and inner intercepted
X TLS. Normal verification remains enabled. A standard `VerifyConnection`
callback additionally re-verifies each chain using only the roots for that exact
hostname: system roots plus the optional proxy CA for the proxy; the Serverware
interception CA for `api.x.com`. Do not put the interception CA in the proxy CA
file. No `InsecureSkipVerify`, custom dialer, or disabled certificate check is
used. Tests cover crossed-CA refusal in addition to valid chains.

## Verification boundary

The dependency version and its module declaration were checked against the
[Go module proxy](https://proxy.golang.org/github.com/g8rswimmer/go-twitter/v2/@v/v2.1.5.info):
the tag resolves to `cec1b956cc1113a84c20d4a5f5e02b4d5534c0af`.
The source has no external module dependencies. Generate/verify dependency
checksums with normal Go module tooling; never substitute guessed checksums.

The passed offline tests cover actual SDK request serialization, exact target and dummy
authentication, CONNECT-only application authentication, no redirects/retries,
bounded configuration, fixed error messages, structured-error rejection and
per-hop TLS trust. Their results remain separate from the passed isolated
real-proxy run above. Nothing here creates a provider credential, destination
approval, native enrollment or deployment; real X access remains unverified.
