# Gmail with the official Node.js SDK

List a small inbox sample through Catchplate using Google's generated
`@googleapis/gmail` client. The operator owns the Google account's real OAuth
credentials and refresh tokens. This example receives only a Catchplate
application ID/token, the proxy address, and CA certificates.

It lists at most two pages of five INBOX messages, then calls `messages.get`
for those returned IDs with `format: metadata` and `From`, `Subject`, `Date`.
It prints only counts—not IDs, headers, snippets or bodies. A true `more_pages`
means the bounded sample is incomplete. There are no send, delete, modification,
attachment, history, profile or Calendar calls.

## Set up the permission

1. In the operator workspace, configure Google and connect the intended Google
   account through real consent. This example does not initiate OAuth or discover
   application-default Google credentials.
2. Select that saved credential in **Set up access** and choose a client.
   New guided clients receive compatible standard proxy login. For an existing
   Bearer-only client, use **Clients → Enable standard client login** so this
   SDK can use HTTP Basic on CONNECT. Keep its one-time token private.
3. Choose **Read Gmail** (`gmail_read_v1`) and **Official Gmail SDK**. The permission
   must advertise `orderedFormV1` and replace this exact full header value:

   ```text
   Bearer catchplate-gmail-placeholder-v1
   ```

   This is a public placeholder, never a real Google token. Automatic header
   insertion is a different mode and does not work with this example. Existing
   application authentication or grants are not silently upgraded.
4. Wait for the saved permission to load. Download the interception CA from
   **Proxy setup** and use its local path below. Supply the separate proxy CA only
   if the proxy's outer HTTPS certificate uses a private CA.

The permission defaults to unrestricted age; its optional **Last N days** setting
is enforced by the proxy, not by this example's inbox/count limits.
Current-source **Proxy setup** offers
Go, Node.js and Python under **Gmail SDK language**; choose **Node.js** for this
project's copied shell recipe. The Node client also accepts the private JSON
download generated for any of those languages. Prepare dependencies first:
the recipe does not install or build them. See the
[deployment record](../../docker/catchplate-operator-demo/README.md) for the live
release. All three SDK jobs have isolated synthetic-provider proxy evidence in
the [verification record](../../docs/operator-gmail-job-verification.md), not
real Google acceptance.

## Install and run

Use Node.js 22.19 or newer; the component tests were run with Node.js 25.5.0.
Install before supplying application credentials:

```sh
cd examples/google-gmail-node
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

The real npm-generated lock pins `@googleapis/gmail` 22.0.1, `googleapis-common`
9.2.0, Gaxios 7.3.1 and Undici 8.11.2. Do not regenerate it as part of running
the job. Using the scoped Gmail package avoids installing every Google API.

After installing, download **Private client configuration** and the interception
CA from **Proxy setup**. Keep the JSON private and place the CA at the path
recorded in it (relative paths resolve beside the JSON, not your working directory):

```sh
chmod 600 /path/to/catchplate-client.private.json
node client.mjs --config /path/to/catchplate-client.private.json
```

Use the complete download, not just its nested `client_recipe`. The client checks
its Gmail read permission, standard proxy login, unexpired token metadata and
matching connection fields in both copies. It accepts the default Go recipe
(v1) and Node/Python recipes (v2), but never runs JSON entrypoints, arguments or
commands, and imports only validated connection settings and the saved age policy. File settings
override ambient connection values; an absent optional proxy CA clears any
ambient `CATCHPLATE_PROXY_CA_FILE`. Keep this token-bearing JSON out of source
control and obtain a fresh download if its token has expired.

The env-only invocation still works. `.env.example` is reference configuration;
the program does not load it. Set
the following in the process environment, with the token injected privately
through your secret manager—not a command-line argument or shell-history literal:

```sh
export CATCHPLATE_PROXY_URL='https://your-proxy.example:443'
export CATCHPLATE_APP_ID='your-saved-application-uuid'
export CATCHPLATE_CA_FILE='/absolute/path/to/catchplate-ca.pem'
# Set CATCHPLATE_PROXY_TOKEN privately; optional CATCHPLATE_PROXY_CA_FILE.
node client.mjs
```

## Optional last-N-days policy

A full download may contain `age_policy: {"mode":"recent_internal_date_v1",
"max_age_days":7}` (an integer from 1 through 3650). Absent metadata or
`{"mode":"unrestricted"}` retains the original requests without `q`.
Restricted runs compute an explicit `after:<epoch-seconds>` query once, using
the ceiling of the client clock minus the selected number of days, and reuse it
unchanged across both pages. The five-message page size is below the restricted
permission's maximum of 32. Direct metadata reads do not project out `internalDate`.

This query is a convenience, not proof of age: the proxy checks Gmail's
`internalDate` and can deny the whole response when that evidence is missing or
too old. The bounded inbox sample is not a completeness guarantee. For the copied
Bash recipe or an environment-only run, `CATCHPLATE_GMAIL_MAX_AGE_DAYS='7'`
selects the same convenience query; it cannot grant or change permission.
With `--config`, only the downloaded top-level policy supplies this hint, never
an ambient variable or nested recipe override.

Example output:

```json
{"pages":2,"messages_read":2,"more_pages":false}
```

No provider credentials, Google client secret, refresh token or credentials JSON
belong in this process. Disable request/debug logging. The program refuses
`GOOGLE_APPLICATION_CREDENTIALS`, `DEBUG`, `NODE_DEBUG`, `NODE_DEBUG_NATIVE`,
`GOOGLE_SDK_NODE_LOGGING`, `NODE_OPTIONS`, and disabled TLS verification. It does
not read `.env` or browser storage. With `--config`, only a regular JSON file up
to 64 KiB is accepted; symlinks are refused. The private file, process memory and
(when using env-only setup) environment contain the application token; protect them from
other users and diagnostics. Errors print one fixed message and exit nonzero.

## How the ordinary SDK reaches the proxy

The [official Google Node client](https://github.com/googleapis/google-api-nodejs-client)
generates the list/get calls and serializes the queries and headers. An
`OAuth2` instance holds only the static public dummy, without refresh credentials
or a refresh handler. Google OAuth refresh remains Catchplate's responsibility.

The documented [Gaxios `fetchImplementation` option](https://github.com/googleapis/gaxios#request-options)
connects those unmodified SDK requests to Undici `request` and its standard
[ProxyAgent](https://github.com/nodejs/undici/blob/main/docs/docs/api/ProxyAgent.md).
This is explicit transport configuration, not Gaxios's default `node-fetch`
transport and not a hand-built Gmail request. `request` avoids browser-oriented
headers that `fetch` adds but the Gmail permission does not accept. The adapter
does not remove, reorder, or replace the SDK's request headers/query values.

- Outer TLS verifies the proxy DNS name using Node's bundled public roots plus
  the optional `CATCHPLATE_PROXY_CA_FILE`.
- Inner TLS verifies `gmail.googleapis.com` using only `CATCHPLATE_CA_FILE`.
- Basic `Proxy-Authorization` holds the application ID/token on CONNECT only.
  Gmail receives only the public dummy Bearer header before Catchplate replaces it.
- Ambient `HTTPS_PROXY`, `NO_PROXY`, or Google universe settings cannot bypass
  the explicit dispatcher or change the fixed Gmail endpoint. No global trust
  store is changed, and neither token appears in a URL.

The job permits at most 12 API calls, a two-minute overall deadline and a
30-second per-call bound, including connection and body reads. Redirects, SDK
retries, application retries and direct fallback are disabled. HTTP pipelining
and request-connection reuse are disabled. Responses must be the proxy's
uncompressed JSON envelope, at most 1 MiB for success or 64 KiB for errors.
Returned IDs/page tokens are bounded and checked before further requests.

## Verification boundary

`npm test` runs unit tests plus the actual generated Gmail SDK, Gaxios and
Undici `request` against an in-memory dispatcher. Unexpected sockets and DNS
are blocked. The tests cover real query encoding/repeated metadata headers,
pagination, exact placeholder authentication, configured trust separation,
response limits, fixed errors and one-attempt failures (including 401/403).

These component tests do not themselves prove proxy/TLS or provider success.
The separate [joined Node/Python acceptance](../../docs/operator-gmail-job-verification.md#current-node-python-and-go-sdk-acceptance--isolated-jobs-passed)
passed at source `330d9e9f` in 178.576 seconds. Both actual entrypoints ran through
the normal Rust proxy with verified TLS against a synthetic Google service:
sixteen provider reads across the original token expiry, one automatic refresh
from generation 1 to 2, and eight TLS/application/revocation denial controls
without additional provider arrivals. Durable audit verification and cleanup
passed. This is Node's own joined evidence, not an inference from the Go job.

That isolated result does not establish real Google consent, provider entitlement
or a live-account job. Deployed UI/repair checks and the separately recorded
[public synthetic-route verification](../../docs/operator-public-proxy-verification.md)
have their own scope; neither establishes real Google access.
