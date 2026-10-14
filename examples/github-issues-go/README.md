# Go: read GitHub issues through Serverware

This read-only example uses the real, pinned `google/go-github/v74` SDK and its
normal `Issues.ListByRepo` / `Response.NextPage` pagination. It counts open issues
and pull requests in **one explicitly permitted repository**; it does not create
or edit anything, discover repositories, or print issue contents.

## Configure and run

GitHub App verification/save requires `https://api.github.com` to be an
operator-allowed upstream before any provider contact. **Save and verify GitHub
App** verifies the App, installation and repository and obtains a scoped token
before saving. A PAT may be saved untested while that upstream is disabled;
granting or using either connection still requires it to be enabled.

In Serverware, choose **GitHub**, then either a personal access token (PAT,
`github_token_v1`) or a GitHub App (`github_app_v1`) connection. A PAT needs a
connection name and token. An App needs a name, App ID,
private-key PEM, exact repository owner/name and Issues access; choose `read`
for this read-only example. The installation ID is optional under Advanced;
Serverware finds and verifies it for the selected repository when omitted.
The App must already be installed in GitHub for that
repository with the required permission. Create a Serverware application and
grant **GitHub issues: read** for the same exact owner/repo.
Select the application's **Basic and Bearer** proxy authentication mode
(`basic_and_bearer_v1`). This example uses Basic authentication for CONNECT;
a Bearer-only application is not compatible with this recipe.
Keep the real GitHub credentials in Serverware, not in this application's environment.
Download and verify the Serverware interception CA through your operator's
authenticated setup flow. Use the deployed proxy's HTTPS URL, not the admin UI.

Serverware stores the App private key encrypted and automatically obtains and
renews its short-lived installation tokens. It does not renew PATs or the
Serverware application's proxy token. The App connection's repository/Issues
ceiling does not replace the application grant. App authentication is not GitHub
OAuth user login, and the GitHub App ID is not `SERVERWARE_APP_ID`.

App token reuse requires a 65-second expiry margin. Failed minting has no retry
in the same call; only a later separately authorized lease after a 60-second
backoff may attempt fresh authentication. It does not retry repository requests.

The client, SDK and input variables below are unchanged for either connection.
Do not pass an App private key, JWT or installation token to this program. The
new App flow is **not yet verified against real GitHub**;
[its synthetic verification is recorded separately](../../docs/operator-github-client-compatibility.md#github-app-feature-verification-checkpoint).

### Use the downloaded private configuration

With Go 1.23 or later, build from this directory **before supplying any token**:

```sh
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go build -o github-issues .
```

In the console's Proxy setup, select the GitHub permission and download the
private client JSON while the page still holds your application's one-time
token. Download and verify the public Serverware CA as well. Keep both files
outside the repository. The default `ca_file` is `./serverware-ca.pem`; relative
CA paths, including optional `client_recipe.proxy_ca_file`, resolve beside the
JSON file, not from the executable's working directory.

```sh
chmod 600 /path/serverware-client.private.json
./github-issues --config /path/serverware-client.private.json
```

The JSON contains your application's private proxy token: never commit, share,
or print it. It must select Basic and Bearer authentication and a matching
GitHub issues read/write permission, repository, and unexpired application
token. This example remains read-only even with a write permission. Files must
be regular, non-symlink JSON files no larger than 64 KiB. The existing unversioned
console export is supported. Only connection and repository fields are read;
embedded recipes, commands, environment blocks and entrypoints are not run.
File values replace all connection/scope environment values; an absent optional
proxy CA uses system trust, not an ambient `SERVERWARE_PROXY_CA_FILE`.

### Use environment variables instead

Without `--config`, supply these values using your environment or CI secret store:

| Variable | Value |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, optionally with a port; no username/password or path |
| `SERVERWARE_APP_ID` | Saved application UUID |
| `SERVERWARE_PROXY_TOKEN` | That application's issued proxy token; **not** the GitHub token |
| `SERVERWARE_CA_FILE` | Local PEM file containing the Serverware interception CA |
| `SERVERWARE_PROXY_CA_FILE` | Optional additional outer HTTPS-proxy CA; omit for a publicly trusted certificate |
| `SERVERWARE_GITHUB_OWNER` | Exact owner selected in the permission |
| `SERVERWARE_GITHUB_REPO` | Exact repository selected in the permission |

Build first as above, then supply the variables and run:

```sh
./github-issues
```

The test suite uses generated synthetic certificates and in-memory SDK
responses, not GitHub or a real proxy; run them with `GOTOOLCHAIN=local go test ./...`.
**Running the built executable makes real read requests**
through the configured proxy. It prints only counts, for example
`{"pages":2,"issues":102,"pull_requests":7}`. A request failure, two-minute total
deadline, invalid pagination, or 100-page limit exits without reporting partial
counts as a complete result. Nothing retries automatically at the application
level. Inspect the saved permission and audit records before running again.

## Why these transport settings matter

The stock SDK keeps its normal API URL, request headers, and pagination methods.
A standard `oauth2.Transport` with a **static public dummy** and `TokenType:
"token"` supplies `Authorization: token serverware-github-placeholder-v1`.
Serverware replaces that exact value with the saved PAT or server-derived App
installation token. This client performs no OAuth exchange, refresh-token flow
or provider login. The SDK's `WithAuthToken` helper would use
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
entrypoint through the normal Rust proxy subsequently passed in the
2026-10-10 [isolated acceptance](../../docs/operator-github-client-compatibility.md#checked-in-node-python-and-go-examples):
two-page reads succeeded against a synthetic GitHub service, while
wrong-application and wrong-repository attempts were denied before dispatch.
The actual stock SDK media type passed without client header rewriting.
That historical static-token fixture does not verify GitHub App installation
authentication or automatic token renewal. Either connection still authorizes
only the existing issue/comment presets, not arbitrary GitHub APIs, git,
GraphQL or Actions/workflow management; this example itself only reads issues.
Neither in-memory tests nor that isolated run establish public deployment or
real-GitHub compatibility with your token and repository.
No provider token, real repository, native enrollment, or deployment is created
by this example.

The reviewed primary sources are the [pinned SDK issue method](https://github.com/google/go-github/blob/v74.0.0/github/issues.go),
[SDK authentication and media-type definitions](https://github.com/google/go-github/blob/v74.0.0/github/github.go),
[OAuth2 token authentication](https://github.com/golang/oauth2/blob/v0.30.0/token.go),
and Go's documented [HTTP transport](https://pkg.go.dev/net/http#Transport) and
[additional TLS verification hook](https://pkg.go.dev/crypto/tls#Config).
