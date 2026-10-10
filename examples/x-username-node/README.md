# One X username lookup through Serverware

**Isolated SDK-through-proxy acceptance passed.** On 2026-10-10, this actual
entrypoint passed through the genuine Rust proxy to a network-isolated synthetic
X service, with verified outer and inner TLS and server-side token replacement.
Wrong application, username and revoked-grant controls were refused. The run
used source `eb5d12e5`; it contacted no provider and proves neither deployment
acceptance, real X access nor a GitHub Actions run. See the
[verification record](../../docs/operator-x-username-verification.md).

Separately, Node 25.5.0 passed seven configuration tests and four installed-XDK
tests using Undici MockAgent. Those offline results are not proxy/TLS proof.

The actual official `@xdevplatform/xdk` **0.6.6** generates one
`client.users.getByUsername(username, ...)` request. It uses the fixed public
dummy `serverware-x-placeholder-v1`, not an X credential. Serverware replaces
that dummy with the provider token held on the server. This is app-only,
read-only lookup of **one saved lowercase username**; no search, pagination,
posting, DMs, OAuth exchange or refresh is included.

## Prerequisites

An operator must separately approve `https://api.x.com` (HTTPS port 443), save an
`x_app_bearer_v1` connection, and grant the application
`x_username_read_v1` for your exact `[a-z0-9_]{1,15}` username. Confirm the saved
policy is actually loaded before using a client. These are requirements, not a
claim that your deployment currently provides the new preset. The application
must permit **Basic and Bearer proxy authentication** (`basic_and_bearer_v1`):
this client uses Basic on CONNECT; a Bearer-only application is incompatible.

Use a dedicated Node process; the documented proxy dispatcher is process-global.
The reviewed runtime recipe is Node **25.5.0**. Dependencies are exact pins, and
the lock records npm registry integrity values. The recorded local checks used
`npm ci --ignore-scripts --no-audit --no-fund` successfully. XDK's optional
`node-fetch` peer is not needed on this native-fetch runtime.

Install without application credentials in the installation environment:

```sh
cd examples/x-username-node
npm ci --ignore-scripts --no-audit --no-fund
```

Export the public configuration below and supply `SERVERWARE_PROXY_TOKEN`
through your secret manager or protected CI environment. It is the scoped
**Serverware application token**, never an X token. Do not put it in shell
arguments, a proxy URL, committed files or logs. `.env.example` is a template;
the program does not load `.env` files automatically.

```sh
export SERVERWARE_PROXY_URL='https://your-approved-proxy.example:443'
export SERVERWARE_APP_ID='your-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
export SERVERWARE_X_USERNAME='selected_name'
# Only if the outer HTTPS proxy uses a private CA:
# export SERVERWARE_PROXY_CA_FILE='/absolute/path/outer-proxy-ca.pem'
node client.mjs
```

`SERVERWARE_CA_FILE` trusts the intercepted `api.x.com` connection.
`SERVERWARE_PROXY_CA_FILE`, when set, separately trusts the outer HTTPS proxy;
otherwise that leg uses Node's default roots. Both verify certificates and
hostnames. Obtain CA files through your trusted operator channel, not from an
unauthenticated first-use connection. No TLS-disable setting is supported.

## Ordinary transport setup versus extra example restrictions

The XDK uses native `fetch` and offers no per-client fetch override. This example
uses the documented Undici **8.11.2** `setGlobalDispatcher` / `ProxyAgent` hooks:
an HTTPS proxy URI without credentials, a separate Basic proxy token, and
separate `proxyTls` / `requestTls` settings. It does not replace fetch, write an
HTTP client, or rewrite the SDK's headers. Ambient proxy variables and `NO_PROXY`
do not select its dispatcher. Provider-token environment variables are ignored;
nonempty `NODE_OPTIONS` and insecure TLS settings are rejected.

An **additional explicit dispatcher interceptor** admits only the exact GET
`https://api.x.com/2/users/by/username/<saved-name>`, with no query or body, and
only one attempted dispatch. It forwards admitted options unchanged; subsequent
dispatches, including redirect following, are refused. This is example-level
restriction, **not a claim that vanilla SDK defaults enforce it**. The SDK is
also configured with documented `retry: false`; `maxRetries: 0` is not used
because this version replaces zero with its default. A 30-second request signal
bounds the request and JSON-body consumption. There is no automatic retry.

The pinned SDK emits `Authorization: Bearer serverware-x-placeholder-v1`,
`Accept: application/json`, `Content-Type: application/json` even on GET, and
`User-Agent: xdk-typescript/0.6.6`. Native fetch adds transport headers such as
`accept-language`, `sec-fetch-mode` and `accept-encoding`; the proxy's narrow
admission accounts for those without broadening generic rules. The isolated
acceptance run exercised this entrypoint's actual SDK-generated request; it did
not contact the real X service.

Success prints only a validated matching username and numeric user ID.
HTTP200 with provider errors or missing/mismatched user data is not success.
Failures print a fixed message and bounded HTTP status, never SDK error objects,
request objects, provider response bodies or credentials. A refused lookup can
mean missing permission, policy not loaded, provider entitlement or token
failure; saving a token alone proves none of those.

## Offline checks and inactive workflow

```sh
npm test
npm run test:sdk
```

The first suite is pure configuration/behavior testing with inert doubles. The
second uses the **real pinned XDK**, native fetch and Undici MockAgent with real
networking forbidden. It checks serialization, fixed diagnostics, no retry,
redirect refusal and provider-error handling. Neither proves HTTPS trust,
proxy-authentication, server-side token injection or provider access. Both
suites passed separately from the actual isolated proxy run above.

`workflow.example.yml` is inactive. Review it and its dependency lock before
copying it into `.github/workflows/`. It runs only by explicit manual dispatch
on the default branch, in a protected environment. Only the final lookup step
receives the Serverware token. CA values are public trust material but must have
authenticated provenance; no X credential belongs in the workflow. Enabling
this sample does not grant a provider destination or application permission.

Primary sources reviewed for these exact versions:

- [Official X SDK index](https://docs.x.com/tools-and-libraries) and
  [XDK 0.6.6 npm metadata](https://registry.npmjs.org/@xdevplatform/xdk/0.6.6).
- [Pinned Client configuration and headers](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/client.ts),
  [native-fetch transport](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/http-client.ts),
  [username method](https://github.com/xdevplatform/xdk-typescript/blob/v0.6.6/src/users/client.ts).
- [Undici 8.11.2 ProxyAgent options](https://github.com/nodejs/undici/blob/v8.11.2/docs/docs/api/ProxyAgent.md),
  [dispatcher interception](https://github.com/nodejs/undici/blob/v8.11.2/docs/docs/api/Dispatcher.md),
  [native-fetch global dispatcher compatibility](https://github.com/nodejs/undici/blob/v8.11.2/README.md#undicisetglobaldispatcherdispatcher).
