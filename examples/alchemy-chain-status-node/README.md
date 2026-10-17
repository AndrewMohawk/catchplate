> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Alchemy chain status with Viem on Node

This example uses **Viem 2.57.6** and **Undici 8.12.1** on **Node 25.5.0**.
Alchemy recommends Viem for JavaScript Ethereum development after deprecating
its `alchemy-sdk` package. The old SDK repository was archived on July 13, 2026.
This recipe keeps the same Alchemy provider, two permitted reads, environment
variables and output; it no longer installs the archived SDK or its ethers v5
signing dependency graph. It is a Viem compatibility example, not a claim that
the archived Alchemy SDK has been repaired. [Alchemy's migration guidance](https://github.com/alchemyplatform/alchemy-sdk-js#readme),
[pinned Viem package](https://github.com/wevm/viem/blob/viem%402.57.6/src/package.json),
[pinned Undici package](https://github.com/nodejs/undici/blob/v8.12.1/package.json).

It makes two sequential read-only calls: `eth_chainId`, then `eth_blockNumber`,
both with `params: []`. There are no wallets, transactions, polling,
subscriptions, batches or automatic retries. A failed first call stops the job.

## Operator setup

The operator stores the real Alchemy API/access key in Catchplate. Create a
separate application with **Basic proxy authentication**, and give it the named
**Alchemy chain status** permission for exactly `eth-mainnet` or `eth-sepolia`.
Use the typed `alchemy.rpc_read.v1` preset, not a generic arbitrary POST grant.
The saved permission replaces exactly
`Authorization: Bearer catchplate-alchemy-placeholder-v1` with the operator's
key. The client never receives that provider key.

This requires a Catchplate deployment that actually supports and advertises the
paired Alchemy preset. Source changes or this example alone do not establish
that an older deployment supports it. See [provider preset boundaries](../../docs/operator-provider-presets.md).

Get the proxy URL and interception CA from the operator. Verify the CA through
your trusted operator channel; do not retrieve it with TLS verification disabled.
The configured endpoint is the keyless `https://<selected-chain>.g.alchemy.com/v2`.
The SDK's usual `/v2/<API-key>` URL is deliberately not used.
[Alchemy header authentication](https://www.alchemy.com/docs/how-to-use-api-keys-in-http-headers).

## Run explicitly

Install the locked dependencies **before** supplying an application token:

```sh
cd examples/alchemy-chain-status-node
npm ci --ignore-scripts --no-audit --no-fund
```

In **Proxy setup**, select the app and Alchemy chain-status permission, then
download its private client JSON and CA. Run the downloaded file directly:

```sh
node client.mjs --config /private/path/catchplate-client.private.json
```

Relative CA paths resolve beside the JSON file. Keep this file private: it
contains the scoped Catchplate app token. The loader checks the saved chain,
permission shape, Basic login and token expiry. It never executes recipe
commands or imports headers, environment entries or request bodies; this job
still performs only the two fixed reads. TLS verification remains enabled.

Alternatively, keep using explicit environment configuration:

Use the names in [.env.example](.env.example). Supply `CATCHPLATE_PROXY_TOKEN`
through a private environment/secret manager, not a pasted shell command or
committed dotenv file. No Alchemy key environment variable is required or read.

```sh
export CATCHPLATE_PROXY_URL='https://your-proxy.example:443'
export CATCHPLATE_APP_ID='your-application-uuid'
export CATCHPLATE_CA_FILE='/absolute/path/catchplate-ca.pem'
export CATCHPLATE_ALCHEMY_CHAIN='eth-mainnet'
# CATCHPLATE_PROXY_TOKEN is already supplied privately.
node client.mjs
```

Success prints only `ok`, `operation`, `chain`, `chainId` and `blockNumber`.
Failure prints a fixed message and exits nonzero; it does not print SDK errors,
provider responses, request headers or tokens. Inspect Catchplate's audit log to
diagnose a denial. Do not automatically rerun an uncertain result.

## Transport and limits

The launcher starts one short-lived child with an explicit environment allowlist
and a 30-second wall-clock limit. It does not inherit proxy bypass, debug,
preload, provider-key, HOME/netrc or ambient trust variables. Always use
`client.mjs`, not the internal `request.mjs`, and a trusted unmodified Node
runtime without diagnostic/preload command-line switches.

The child uses Viem's ordinary HTTP transport and documented `fetchFn` and
`fetchOptions` settings with Undici's stock `fetch` and `ProxyAgent`. Viem creates
the JSON-RPC payloads; Undici serializes HTTP and establishes the proxy tunnel.
No request implementation, SDK method or global dispatcher is patched. There is
no direct-network fallback or environment-dependent proxy selection.

The application login is a private in-memory Basic token in `ProxyAgent`, sent
only to the proxy's CONNECT request. Neither URL contains it; the provider gets
only the public dummy bearer before Catchplate replaces that value. The app
token itself is necessarily in the private child environment: same-user process
inspection, debuggers and memory dumps remain a risk. Do not enable SDK/Node
debug logging. [Viem's pinned HTTP transport](https://github.com/wevm/viem/blob/viem%402.57.6/src/clients/transports/http.ts),
[Undici ProxyAgent](https://github.com/nodejs/undici/blob/v8.12.1/docs/docs/api/ProxyAgent.md).

Both TLS legs verify hostnames and certificates:

- Inner provider-name TLS uses only `CATCHPLATE_CA_FILE` in `requestTls`, with
  the selected Alchemy hostname explicitly retained for verification.
- Outer proxy TLS uses Node's built-in roots in `proxyTls`. If your edge uses a
  private CA, `CATCHPLATE_PROXY_CA_FILE` adds that root only to the outer set.
  The existing child-only `NODE_EXTRA_CA_CERTS` setting is retained, but both
  connector CA sets are explicit; the inner set never inherits the outer root.

There is no system trust-store modification or insecure fallback. Separate-root
dual-TLS acceptance passed for this transport in the isolated actual-proxy run
at `8d07d66b`, separately from the component checks below.
[Node extra-CA semantics](https://nodejs.org/download/release/v25.5.0/docs/api/cli.html#node_extra_ca_certsfile),
[Undici tunnel implementation](https://github.com/nodejs/undici/blob/v8.12.1/lib/dispatcher/proxy-agent.js).

Public SDK settings select the exact keyless URL, `batch: false`, `retryCount: 0`,
`redirect: 'error'`, a 15-second request timeout and a 64-KiB response limit.
The transport allows only the two named RPC methods; the entrypoint awaits each
read sequentially and refuses the wrong chain before the second read. It creates
no account or wallet and starts no subscription, discovery or polling job.
The dedicated dispatcher also composes Undici's supported `responseError`
interceptor with a positive 64-KiB error-body limit. This rejects HTTP errors
before Fetch can automatically replay an HTTP 421 response; Viem's retry setting
alone does not disable that lower-level replay. Error details are never printed.
[Pinned response-error interceptor](https://github.com/nodejs/undici/blob/v8.12.1/lib/interceptor/response-error.js),
[pinned Fetch replay path](https://github.com/nodejs/undici/blob/v8.12.1/lib/web/fetch/index.js#L1645-L1672).

The stock Undici client supplies `User-Agent: undici`, `Accept-Language: *` and
`Sec-Fetch-Mode: cors`. The example supplies the public dummy bearer,
`Accept: application/json` and `Accept-Encoding: identity`; Viem supplies JSON
Content-Type. No obsolete Alchemy SDK version or method headers are fabricated.
HTTP/2 and connection reuse are disabled for the dedicated bounded job. The
proxy keeps its own strict request, response and audit checks.
[Viem request implementation](https://github.com/wevm/viem/blob/viem%402.57.6/src/utils/rpc/http.ts),
[Viem retry controls](https://github.com/wevm/viem/blob/viem%402.57.6/src/utils/buildRequest.ts),
[Undici client options](https://github.com/nodejs/undici/blob/v8.12.1/types/client.d.ts).

## Verification and CI

The Viem migration changes the SDK and HTTP transport. Its component suites
passed at `692c2923` in [hosted run 38591966831](https://github.com/example/private-deployment):
12 inert configuration tests and nine SDK/fixture tests, with no failures,
cancellations or skips and verified cleanup. The preceding failed fixture
attempt remains recorded. A fresh run at `8d07d66b` then passed all 12 actual
Node/Python/Go SDK phases through the normal Rust proxy in 79.410 seconds:
two reads per client, wrong-client/wrong-chain/revoked-permission refusals,
exact credential replacement, separate verified TLS roots and audit checks.
The existing Rust build was reused, and cleanup was verified. This is isolated
synthetic-provider acceptance, not a real Alchemy account test.

Historical acceptance remains preserved: the Alchemy SDK graph at `dcf70631`,
with normal Rust SHA-256 prefix `0908732386fa`, passed the 12-phase isolated
Node/Python/Go journey, including denial, revocation, exact key replacement,
separate TLS roots and audit controls. The later Jayson graph passed 15 component
tests but not a fresh connected run. Neither result covers this Viem migration.
See the [current verification status](../../docs/operator-alchemy-verification.md)
and [historical acceptance record](../../docs/operator-alchemy-verification.md#current-dependency-graph-acceptance).
Real Alchemy, real-provider Actions jobs, native-pilot and deployment acceptance
remain unverified.

```sh
npm test
npm run test:sdk
```

The first suite is inert configuration/launcher testing. The second uses the
actual pinned Viem and Undici HTTP serializer with an in-memory Agent connector;
real sockets and DNS are forbidden. It checks exact requests, no retry (including
HTTP 421 and 429) or redirect, wrong-chain and unsupported-method refusal, bounded responses and
fixed public error output. Neither suite proves proxy dispatch, TLS,
credential replacement, real Alchemy access, deployment, native-pilot acceptance
or blockchain freshness.

[workflow.example.yml](workflow.example.yml) is inactive here. Review it before
deliberately copying it into `.github/workflows/`. It allows manual dispatch on
the default branch only, uses a protected environment, installs dependencies
before exposing the limited application token, and never needs an Alchemy key.
This workflow has not been run.
