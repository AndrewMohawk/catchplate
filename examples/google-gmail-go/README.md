# Gmail with the official Go SDK

Read a small inbox sample through Serverware using the ordinary
`google.golang.org/api/gmail/v1` client. The operator connects the Google account
and owns its OAuth client secret, access token and refresh token. This app receives
only a Serverware application ID/token and an explicit permission.

The app lists at most **two pages of five inbox messages**, then reads metadata
for those returned IDs. It requests only `From`, `Subject` and `Date` headers and
prints counts, never mail headers, IDs, snippets or bodies. `more_pages: true`
means this is a bounded sample, not a complete mailbox export. There are no send,
delete, modification, attachment, history, profile or Calendar calls.

## Operator setup

1. Configure Google in the operator workspace and connect the intended account
   with the advertised Gmail read-only profile. Complete real consent separately;
   this example does not initiate or repair OAuth configuration.
2. In **Connect a real service**, select that saved Google account, then select or
   create an application whose proxy authentication supports **Basic**. Save its
   one-time application token privately.
3. Choose the named **Read Gmail** permission (`gmail_read_v1`). It must advertise
   `orderedFormV1`, which admits the SDK's repeated `metadataHeaders` parameters.
   Leave **Gmail client** set to **Official Gmail SDK**, the default for a new
   Read Gmail permission. The workspace fills in the exact public dummy and
   checks that the selected application supports Basic proxy login. Review and
   save the permission; no response fields or dummy value need to be entered.
   The SDK's fixed header value is:

   ```text
   Bearer serverware-gmail-placeholder-v1
   ```

   This is the full, case-sensitive `Authorization` value, including one space.
   **Custom HTTP client** preserves the separate automatic-insertion or custom
   dummy choices. Automatic insertion expects no provider header and is **not
   compatible with this example**. On older deployments without the Gmail client
   choice, explicitly choose **Replace a dummy header value** and enter the
   exact value above. Never enter a real Google token or application token.
   Existing permissions and application login modes are not silently upgraded;
   enable Basic in Applications if needed, select/create the intended replacement
   permission, and resolve any overlapping permission explicitly.
4. After the exact saved permission is loaded, use **Proxy setup** (also shown
   at the end of Connect). Download the interception CA, enter its local path,
   and set the optional separate proxy CA path only if your proxy uses a private
   certificate authority. **Copy connection template** supplies the Go SDK job
   recipe for this exact application and permission, not a manual Gmail cURL
   request. The public recipe contains no application or Google token and does
   not run anything in the browser. A working source checkout does not make a
   deployment or Google account ready.

This permission is GET-only for `https://gmail.googleapis.com/gmail/v1/users/me/messages`
and individual message paths. The permission itself has **no age restriction**;
the example's inbox filter and count limit do not narrow an application's saved
authority. Serverware's existing Gmail response contract limits successful JSON
to 1 MiB. See the [Gmail verification boundary](../../docs/operator-gmail-job-verification.md).

## Run

Use a supported Go release at least 1.25; this dependency repair uses the
official Go 1.26.9 toolchain. Direct dependency pins are Google API client
`v0.264.0` and OAuth2 `v0.36.0`. The patched gRPC `v1.83.1` graph requires
these coupled updates through GAX, alongside `x/crypto v0.52.0` and
`x/net v0.55.0`; they are not arbitrary latest-version upgrades.
Install dependencies before supplying the application token:

```sh
cd examples/google-gmail-go
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go build -o gmail-example .
```

The reviewed `go.mod` and `go.sum` are checked in; dependency installation should
use those pins, not regenerate them as part of running the example. Local build
binaries, real environment files and CA/key material are ignored; keep the
checked-in `.env.example` free of secrets.

With the binary built, set `SERVERWARE_PROXY_TOKEN` privately and paste the
workspace's copied recipe into Bash from this project directory. It passes the
token through stdin into the child's process environment, never a command-line
argument, and starts `./gmail-example` with only the selected SDK settings.
Ambient provider credentials, proxy overrides and TLS overrides are not carried
into that child. The parent shell's environment is unchanged. The recipe does
not install dependencies, renew the application token or repeat a failed job.

The optional **private client configuration** download is available only while
the browser holds this application's one-time token. Its `client_recipe` includes
the exact SDK environment, including that private token, plus the example
directory and entrypoint. Keep the JSON out of source control. It is reference
configuration, not an executable, and this Go program does not load it
automatically. A previously saved application's token cannot be retrieved by
opening Proxy setup.

For manual configuration, `.env.example` is a reference; the program does not automatically load it. Set
these variables in the process environment using your private secret-injection
method:

```sh
export SERVERWARE_PROXY_URL='https://your-proxy.example:443'
export SERVERWARE_APP_ID='your-saved-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/to/serverware-ca.pem'
# Set SERVERWARE_PROXY_TOKEN privately; do not paste it into shell history.
./gmail-example
```

Example output (counts depend on the account):

```json
{"pages":1,"messages_read":3,"more_pages":false}
```

The app makes at most 12 API calls, with a two-minute overall context and a
30-second per-call HTTP deadline. There is no application retry, SDK retry loop,
automatic redirect or direct-connection fallback. Transport connection reuse is
disabled. A failed read prints a fixed message and exits nonzero; inspect the
operator audit log instead of enabling raw HTTP/SDK debug logging.

Do not supply Google credentials, `GOOGLE_APPLICATION_CREDENTIALS`, `GITHUB_TOKEN`
or an OAuth refresh token to this app. It uses a static public dummy, not ADC or a
refresh-capable token source. Enabled `GOOGLE_API_USE_CLIENT_CERTIFICATE` is
refused before SDK construction to prevent ambient client-key discovery. SDK
debug output is explicitly discarded through its public logger option.

## Proxy and TLS details

The [documented `WithHTTPClient` option](https://pkg.go.dev/google.golang.org/api/option#WithHTTPClient)
supplies an ordinary `http.Client`. Standard `oauth2.Transport` attaches only the
public dummy Bearer token. Standard `net/http.Transport` sends the separate
application ID/token as **CONNECT-only Basic `Proxy-Authorization`**, after TLS
verification of the proxy. No token is placed in a URL, written to a generated
file or passed on a command line. Process environment/memory still contain the
application token and must be protected from other users and diagnostic dumps.

- Outer connection: verify the configured proxy DNS name against system roots,
  optionally extended by `SERVERWARE_PROXY_CA_FILE` for a private proxy CA.
- Inner connection: verify `gmail.googleapis.com` against **only** the downloaded
  `SERVERWARE_CA_FILE` interception CA.

Normal TLS verification remains enabled. Because Go's transport uses one TLS
configuration for both hops, an additional `VerifyConnection` check restricts
each hostname to its own root set. A CA trusted only for one hop is rejected for
the other. No global trust store is changed. The proxy URL must use a distinct,
lowercase DNS hostname, not an IP address or `gmail.googleapis.com`.

Ambient `HTTPS_PROXY`/`NO_PROXY` cannot bypass the configured proxy. The endpoint
is fixed to Gmail; the code neither rewrites SDK requests nor follows provider
URLs. [Generated SDK methods at the pinned version](https://github.com/googleapis/google-api-go-client/blob/v0.264.0/gmail/v1/gmail-gen.go)
produce the normal `alt=json`, `prettyPrint=false`, list and metadata parameters.
No unsupported `fields` projection is added.

## Evidence boundary

The included tests use the real SDK with an in-memory HTTP send boundary, not a
custom serializer. They check list pagination, metadata request paths and repeated
query values, exact public authorization, a closed stock-header set, no retry or
redirect after refusal, bounds, and CONNECT credential separation. TLS tests use
synthetic certificates to check both correct and crossed trust roles without
opening sockets.

On 2026-10-12, the upgraded graph passed all eight offline test groups and an
ordinary binary build using verified official Go 1.26.9. Tests and build ran in a
network-disabled container with read-only source and module cache. The application
code is unchanged; the stock `X-Goog-Api-Client` header is now
`gl-go/1.26.9 gdcl/0.264.0`. Fresh SDK-through-proxy acceptance remains required
for this binary and dependency graph.

The historical results below used Go 1.23.12 with Google API `v0.230.0` and
OAuth2 `v0.30.0`, not the upgraded graph. They are not renewed through-proxy
acceptance for this dependency repair.

On 2026-10-10, all eight offline groups passed with those earlier
dependencies (`GOPROXY=off go test -p 2 -count=1 -v ./...`). A separate isolated
network run passed on 2026-10-11 UTC using this actual compiled entrypoint and
the normal Serverware application and Rust proxy. It completed list/pagination
and returned-ID reads before and after genuine synthetic-token expiry: eight
requests, one automatic refresh, separate HTTPS-proxy/interception trust roots,
Basic CONNECT authentication and matching durable audit records. Wrong outer
CA, wrong inner CA, an unassigned application and a revoked permission each
failed without any extra provider request. See the
[joined verification record](../../docs/operator-gmail-job-verification.md#joined-official-sdk-result-2026-10-11-utc).

A further run at `d5daef7c` joined the actual browser permission flow to this same
compiled entrypoint and the deployed application's code. It passed one browser
grant, eight SDK reads across token expiry, one automatic refresh and all four
denial controls. See the
[fresh joined result](../../docs/operator-gmail-job-verification.md#fresh-joined-result-passed).
The browser made real app API calls; synthetic OAuth consent was programmatic.

Both runs used a local synthetic provider with no external network or real
Google credentials. They do **not** prove real Google consent, a live Google
request, public Internet proxy routing or external SSO. Python's generated Gmail client
was not substituted: its reviewed default `httplib2` transport does
not provide the required TLS-to-HTTPS-proxy hop, so this example deliberately uses
the official Go SDK instead.
