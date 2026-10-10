# Go: read GitHub issues through Serverware

This read-only example uses the real, pinned `google/go-github/v74` SDK and its
normal `Issues.ListByRepo` / `Response.NextPage` pagination. It counts open issues
and pull requests in **one explicitly permitted repository**; it does not create
or edit anything, discover repositories, or print issue contents.

## Configure and run

In Serverware, save the GitHub provider token as a `github_token_v1` connection,
create an application, and grant **GitHub issues: read** for the exact owner/repo.
Select the application's **Basic and Bearer** proxy authentication mode
(`basic_and_bearer_v1`). This example uses Basic authentication for CONNECT;
a Bearer-only application is not compatible with this recipe.
Keep the real GitHub token in Serverware, not in this application's environment.
Download and verify the Serverware interception CA through your operator's
authenticated setup flow. Use the deployed proxy's HTTPS URL, not the admin UI.

Supply these values using your environment or CI secret store:

| Variable | Value |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, optionally with a port; no username/password or path |
| `SERVERWARE_APP_ID` | Saved application UUID |
| `SERVERWARE_PROXY_TOKEN` | That application's issued proxy token; **not** the GitHub token |
| `SERVERWARE_CA_FILE` | Local PEM file containing the Serverware interception CA |
| `SERVERWARE_PROXY_CA_FILE` | Optional additional outer HTTPS-proxy CA; omit for a publicly trusted certificate |
| `SERVERWARE_GITHUB_OWNER` | Exact owner selected in the permission |
| `SERVERWARE_GITHUB_REPO` | Exact repository selected in the permission |

With Go 1.23 or later, from this directory:

```sh
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go run .
```

The test suite uses generated synthetic certificates and in-memory SDK
responses, not GitHub or a real proxy. **`go run .` makes real read requests**
through the configured proxy. It prints only counts, for example
`{"pages":2,"issues":102,"pull_requests":7}`. A request failure, two-minute total
deadline, invalid pagination, or 100-page limit exits without reporting partial
counts as a complete result. Nothing retries automatically at the application
level. Inspect the saved permission and audit records before running again.

## Why these transport settings matter

The stock SDK keeps its normal API URL, request headers, and pagination methods.
A standard `oauth2.Transport` with a **static public dummy** and `TokenType:
"token"` supplies `Authorization: token serverware-github-placeholder-v1`.
Serverware replaces that exact value. This is not an OAuth exchange; there is no
refresh token or provider login. The SDK's `WithAuthToken` helper would use
`Bearer`, which is not this preset's replacement contract. Ambient `GITHUB_TOKEN`,
`GH_TOKEN`, `HTTPS_PROXY`, and `NO_PROXY` are not consulted.

The application UUID/token are sent only as HTTPS CONNECT
`Proxy-Authorization`, using Go's standard `GetProxyConnectHeader` hook. They are
never placed in a URL or the tunneled GitHub request. Redirects are not followed;
each next page is rebuilt by the SDK for the same selected repository. Automatic
compression and connection reuse are disabled; rate-limit sleep/retry helpers
are not enabled. Errors do not print SDK response bodies or configuration values.

Go's standard transport shares one TLS configuration between outer HTTPS proxy
and inner GitHub TLS. Normal certificate verification remains enabled. The
standard `VerifyConnection` callback additionally verifies the chain against
**only** the appropriate roots: system roots plus the optional proxy CA for the
exact proxy hostname, and the Serverware CA for `api.github.com`. Do not put the
interception CA in the proxy CA file. This does not use `InsecureSkipVerify`, a
custom dialer, or an HTTP request-header rewriter. Tests include crossed-CA
rejections, not just successful chain checks.

## Compatibility and verification boundary

Version `v74.0.0` sends the exact issue-list media type
`application/vnd.github.squirrel-girl-preview` (**without** `+json`). The narrow
Serverware source compatibility update admits that exact SDK value; an older
deployed gate can still reject it. Do not work around a rejection by rewriting
SDK headers or weakening the permission.

The checked-in `go.sum` records resolved dependency checksums. All six top-level
test groups passed with Go 1.23.12 on 2026-10-10, including actual SDK request
serialization and crossed-CA rejection. Compiled-gate acceptance and running this
entrypoint through a real proxy are **pending**.
In-memory tests alone do not establish deployed or real-GitHub compatibility.
No provider token, real repository, native enrollment, or deployment is created
by this example.

The reviewed primary sources are the [pinned SDK issue method](https://github.com/google/go-github/blob/v74.0.0/github/issues.go),
[SDK authentication and media-type definitions](https://github.com/google/go-github/blob/v74.0.0/github/github.go),
[OAuth2 token authentication](https://github.com/golang/oauth2/blob/v0.30.0/token.go),
and Go's documented [HTTP transport](https://pkg.go.dev/net/http#Transport) and
[additional TLS verification hook](https://pkg.go.dev/crypto/tls#Config).
