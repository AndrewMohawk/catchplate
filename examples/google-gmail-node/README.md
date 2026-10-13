# Gmail with the official Node.js SDK

List a small inbox sample through Serverware using Google's generated
`@googleapis/gmail` client. The operator owns the Google account's real OAuth
credentials and refresh tokens. This example receives only a Serverware
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
   Bearer serverware-gmail-placeholder-v1
   ```

   This is a public placeholder, never a real Google token. Automatic header
   insertion is a different mode and does not work with this example. Existing
   application authentication or grants are not silently upgraded.
4. Wait for the saved permission to load. Download the interception CA from
   **Proxy setup** and use its local path below. Supply the separate proxy CA only
   if the proxy's outer HTTPS certificate uses a private CA.

The permission has no age restriction; this example's inbox/count limits do not
narrow the saved application's authority. Current-source **Proxy setup** offers
Go, Node.js and Python under **Gmail SDK language**; choose **Node.js** for this
project's copied recipe and private configuration. Prepare dependencies first:
the recipe does not install or build them. See the
[deployment record](../../docker/serverware-operator-demo/README.md) for the live
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

`.env.example` is reference configuration; the program does not load it. Set
the following in the process environment, with the token injected privately
through your secret manager—not a command-line argument or shell-history literal:

```sh
export SERVERWARE_PROXY_URL='https://your-proxy.example:443'
export SERVERWARE_APP_ID='your-saved-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/to/serverware-ca.pem'
# Set SERVERWARE_PROXY_TOKEN privately; optional SERVERWARE_PROXY_CA_FILE.
node client.mjs
```

Example output:

```json
{"pages":2,"messages_read":2,"more_pages":false}
```

No provider credentials, Google client secret, refresh token or credentials JSON
belong in this process. Disable request/debug logging. The program refuses
`GOOGLE_APPLICATION_CREDENTIALS`, `DEBUG`, `NODE_DEBUG`, `NODE_DEBUG_NATIVE`,
`GOOGLE_SDK_NODE_LOGGING`, `NODE_OPTIONS`, and disabled TLS verification. It does
not read `.env`, private client-config downloads, or browser storage. Process
environment and memory still contain the application token; protect them from
other users and diagnostics. Errors print one fixed message and exit nonzero.

## How the ordinary SDK reaches the proxy

The [official Google Node client](https://github.com/googleapis/google-api-nodejs-client)
generates the list/get calls and serializes the queries and headers. An
`OAuth2` instance holds only the static public dummy, without refresh credentials
or a refresh handler. Google OAuth refresh remains Serverware's responsibility.

The documented [Gaxios `fetchImplementation` option](https://github.com/googleapis/gaxios#request-options)
connects those unmodified SDK requests to Undici `request` and its standard
[ProxyAgent](https://github.com/nodejs/undici/blob/main/docs/docs/api/ProxyAgent.md).
This is explicit transport configuration, not Gaxios's default `node-fetch`
transport and not a hand-built Gmail request. `request` avoids browser-oriented
headers that `fetch` adds but the Gmail permission does not accept. The adapter
does not remove, reorder, or replace the SDK's request headers/query values.

- Outer TLS verifies the proxy DNS name using Node's bundled public roots plus
  the optional `SERVERWARE_PROXY_CA_FILE`.
- Inner TLS verifies `gmail.googleapis.com` using only `SERVERWARE_CA_FILE`.
- Basic `Proxy-Authorization` holds the application ID/token on CONNECT only.
  Gmail receives only the public dummy Bearer header before Serverware replaces it.
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
