# One text-only X post with the official Node SDK

**Isolated synthetic-provider posting acceptance passed; deployment and real X
remain unverified.** This actual entrypoint passed before and after genuine
token expiry/automatic refresh through normal Rust and verified outer/inner
TLS, plus wrong-app, wrong-CA, disconnected and reflected-response controls.
See the [full checkpoint](../../docs/project-completion.md) for the 19-phase
joined run and retained receipts. It does not authorize live X, quota or native
use, or turn an app-only username-read permission into a posting grant.

The official `@xdevplatform/xdk` **0.6.6** performs exactly one
`client.posts.create({text})` call to `POST https://api.x.com/2/tweets`. Its
`accessToken` selects OAuth2 user context, but its value here is only the fixed
public dummy **`catchplate-x-post-placeholder-v1`**. Never supply a real X token
to this program. Catchplate must separately store the authorized user's
credential and replace this exact dummy under an explicit posting permission.
Saving an app-only token or inventing scopes is not sufficient.

There is no media, reply, quote, thread, delete, lookup, OAuth exchange, refresh,
polling or automatic retry. The confirmation below authorizes one local
invocation; it is not durable deduplication. Manually running it twice can create
two posts when the posting permission is active.

## Use after the matching posting deployment is enabled

Obtain a loaded posting permission, a Catchplate application configured for
`basic_and_bearer_v1`, its scoped application token, and authenticated CA files
from the operator. The account's genuine user authorization, posting scopes,
entitlements and credential lifecycle must be handled on Catchplate, not here.

Use a dedicated process with Node **25.5.0**, the locally checked version. Both
dependencies are exactly pinned (`@xdevplatform/xdk` 0.6.6, Undici 8.11.2), with
the reviewed username example's unchanged dependency integrity records. Install
before adding application credentials to the environment:

```sh
cd examples/x-post-node
npm ci --ignore-scripts --no-audit --no-fund
```

In **Proxy setup**, select the app and text-post permission and download its
private client JSON and CA. Connection settings can come directly from the
download, but text and confirmation must still be set locally:

```sh
export CATCHPLATE_X_POST_TEXT='Your explicitly reviewed text'
export CATCHPLATE_X_POST_CONFIRM='post-once'
node client.mjs --config /private/path/catchplate-client.private.json
unset CATCHPLATE_X_POST_CONFIRM CATCHPLATE_X_POST_TEXT
```

Relative CA paths resolve beside the JSON file. Keep it private: it contains
the scoped Catchplate app token. The loader checks Basic login, token expiry
and the exact posting permission. It imports connection fields only, never
commands, environment entries, headers, post content or confirmation. The file
alone cannot cause a post. TLS verification and the no-retry rule are unchanged.

Alternatively, the existing environment-only invocation remains supported:

Supply `CATCHPLATE_PROXY_TOKEN` through a secret manager or protected environment;
never put it in command arguments, a proxy URL, committed files or logs.
`.env.example` is reference only and is not loaded automatically. Text may also
be sensitive: the example never prints it, but it exists in process memory and
the explicit environment.

```sh
export CATCHPLATE_PROXY_URL='https://your-approved-proxy.example:443'
export CATCHPLATE_APP_ID='your-application-uuid'
export CATCHPLATE_CA_FILE='/absolute/path/catchplate-ca.pem'
# Optional separate CA for a private outer HTTPS proxy:
# export CATCHPLATE_PROXY_CA_FILE='/absolute/path/outer-proxy-ca.pem'
export CATCHPLATE_X_POST_TEXT='Your explicitly reviewed text'
export CATCHPLATE_X_POST_CONFIRM='post-once'
node client.mjs
unset CATCHPLATE_X_POST_CONFIRM CATCHPLATE_X_POST_TEXT CATCHPLATE_PROXY_TOKEN
```

Text must be 1–16,384 UTF-8 bytes, with no NUL or ill-formed Unicode. LF, tab, CR
and other valid text are preserved, not trimmed or normalized. The text-only
JSON must fit 32,768 bytes, including escaping. There is no naïve 280-codepoint
restriction or promise that every locally admitted string meets X's current
weighted-length, account-entitlement or content rules.

Success prints only `{"status":201,"id":"123456789"}`. The response must actually
be HTTP 201 with a valid decimal post ID and no provider errors. This proves a
qualifying response was observed, not an independent readback of the post.

## Unknown outcomes must not be replayed

Exit **2** means the posting outcome is **unknown**. A withheld HTTP 409, timeout,
lost connection, redirect, malformed response or any failure after the SDK call
may follow a completed write. Inspect Catchplate's audit and the account before
deciding on any new action. The client never automatically resubmits. Killing a
local process cannot undo a post or prove remote cancellation.

Exit **1** is local preparation failure before the SDK call. Errors expose only
a fixed explanation, a bounded HTTP status when known, and uncertainty flags;
never raw exceptions, provider bodies, submitted text, headers or credentials.

The SDK is configured with `retry:false`. Its `maxRetries:0` option is not used:
this release replaces zero with its retry default. An additional documented
Undici dispatcher interceptor permits only one attempted POST to the fixed
origin/path and rejects subsequent dispatches, including redirect following.
It passes the original SDK request and response through unchanged; it observes
status only. This restriction belongs to the example, not vanilla SDK defaults.
The SDK's 30-second timeout ends at response headers. A separate 35-second
dedicated-process watchdog also bounds stalled body consumption and cleanup;
it is not a real-time or remote-operation deadline.

## Transport and credential boundaries

The SDK uses native fetch. Documented Undici `ProxyAgent` and
`setGlobalDispatcher` configure transport without replacing fetch or rewriting
SDK authentication/serialization. Basic CONNECT authentication carries only the
Catchplate application ID/token, separately from the credential-free proxy URI.
The inner Authorization header carries only the public X dummy.

Both TLS legs verify certificates and hostnames. `CATCHPLATE_CA_FILE` supplies
the inner intercepted-connection trust. The optional
`CATCHPLATE_PROXY_CA_FILE` supplies separate outer-proxy trust; otherwise the
outer connection uses Node's default roots. The inner CA is not automatically
added to outer trust. No system trust store is changed and no direct fallback
exists. The isolated joined run verified these TLS boundaries separately from
the offline configuration tests below; it did not contact real X.

Ambient X credentials, proxy variables and `NO_PROXY` do not select credentials
or transport. TLS-disable settings and nonempty `NODE_OPTIONS`, `NODE_DEBUG`,
`NODE_DEBUG_NATIVE` or `SSLKEYLOGFILE` are refused. Start from a trusted, clean
process environment: Node preload/debug flags may act before JavaScript can
reject them. Do not enable SDK/HTTP logging. Environment values remain visible
to sufficiently privileged process inspection. Use a dedicated trusted process
and narrowly scoped application token; the dispatcher is process-global.

## Offline evidence

```sh
npm test
npm run test:sdk
```

All **19 tests passed** on Node 25.5.0: 11 inert configuration/behavior controls
and 8 tests using the actual pinned SDK, native fetch and Undici MockAgent. The
mock receiver consumes the original serialized body stream; no request rewrite
manufactures compatibility. Socket connection and DNS functions are refused,
and MockAgent disables network access. Tests verify exact text-only JSON,
OAuth2-user dummy authentication, actual response status, single dispatch,
redirect/no-retry controls, byte limits and redaction.

The SDK suite can read the existing sibling username example's identical
installed dependency cache when this directory is uninstalled; the actual CLI
has no dependency fallback. No dependency installation was performed for these
checks. These results do **not** prove proxy admission, OAuth custody/refresh,
TLS handshakes, deployment, provider access or successful posting to X.

Primary sources reviewed:

- [Official X create-post documentation](https://docs.x.com/x-api/posts/create-post).
- [Pinned SDK posting method](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/posts/client.ts),
  [client configuration](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/client.ts)
  and [fetch transport](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/http-client.ts).
- [Undici 8.11.2 ProxyAgent](https://github.com/nodejs/undici/blob/v8.11.2/docs/docs/api/ProxyAgent.md)
  and [documented dispatcher interception](https://github.com/nodejs/undici/blob/v8.11.2/docs/docs/api/Dispatcher.md).
