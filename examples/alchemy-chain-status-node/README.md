# Alchemy chain status with the ordinary Node SDK

This example uses official `alchemy-sdk` **3.6.5**, with ethers transport packages
pinned to **5.8.0**, on **Node 25.5.0**. Alchemy has deprecated and archived this
SDK; this is an explicitly pinned compatibility example, not a recommendation
to adopt an actively maintained SDK. [Official repository](https://github.com/alchemyplatform/alchemy-sdk-js).

It makes two sequential read-only calls: `eth_chainId`, then `eth_blockNumber`,
both with `params: []`. There are no wallets, transactions, polling,
subscriptions, batches or automatic retries. A failed first call stops the job.

## Operator setup

The operator stores the real Alchemy API/access key in Serverware. Create a
separate application with **Basic proxy authentication**, and give it the named
**Alchemy chain status** permission for exactly `eth-mainnet` or `eth-sepolia`.
Use the typed `alchemy.rpc_read.v1` preset, not a generic arbitrary POST grant.
The saved permission replaces exactly
`Authorization: Bearer serverware-alchemy-placeholder-v1` with the operator's
key. The client never receives that provider key.

This requires a Serverware deployment that actually supports and advertises the
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

Use the names in [.env.example](.env.example). Supply `SERVERWARE_PROXY_TOKEN`
through a private environment/secret manager, not a pasted shell command or
committed dotenv file. No Alchemy key environment variable is required or read.

```sh
export SERVERWARE_PROXY_URL='https://your-proxy.example:443'
export SERVERWARE_APP_ID='your-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
export SERVERWARE_ALCHEMY_CHAIN='eth-mainnet'
# SERVERWARE_PROXY_TOKEN is already supplied privately.
node client.mjs
```

Success prints only `ok`, `operation`, `chain`, `chainId` and `blockNumber`.
Failure prints a fixed message and exits nonzero; it does not print SDK errors,
provider responses, request headers or tokens. Inspect Serverware's audit log to
diagnose a denial. Do not automatically rerun an uncertain result.

## Transport and limits

The launcher starts one short-lived child with an explicit environment allowlist
and a 30-second wall-clock limit. It does not inherit proxy bypass, debug,
preload, provider-key, HOME/netrc or ambient trust variables. Always use
`client.mjs`, not the internal `request.mjs`, and a trusted unmodified Node
runtime without diagnostic/preload command-line switches.

The child installs a documented Node HTTPS `globalAgent` with explicit
`proxyEnv`, only within that dedicated process. The stock SDK still constructs
and serializes every RPC and uses ethers' ordinary `https.request`; no request
or SDK method is patched. A proxy URL containing the **application** login exists
temporarily in process memory only, never argv, environment, generated files or
output. The app token itself is necessarily in the private child environment:
same-user process inspection, debuggers and memory dumps remain a risk. Do not
enable SDK/Node debug logging. [Node proxy configuration](https://nodejs.org/download/release/v25.5.0/docs/api/http.html#built-in-proxy-support).

Both TLS legs verify hostnames and certificates:

- Inner provider-name TLS uses only `SERVERWARE_CA_FILE` in the HTTPS Agent.
- Outer proxy TLS uses Node's built-in roots. If your edge uses a private CA,
  supply `SERVERWARE_PROXY_CA_FILE`; only the child receives that additional
  root via `NODE_EXTRA_CA_CERTS`. The inner explicit `ca` does not inherit it.

There is no system trust-store modification or insecure fallback. Separate-root
dual-TLS verification passed in the isolated actual-proxy run recorded below;
it is not a claim made from the inert tests alone.
[Node extra-CA semantics](https://nodejs.org/download/release/v25.5.0/docs/api/cli.html#node_extra_ca_certsfile),
[Node tunnel implementation](https://github.com/nodejs/node/blob/v25.5.0/lib/https.js).

Public SDK settings select the keyless URL, disable batching/gzip requests and
set a 15-second request timeout. `throttleLimit: 1` and a callback returning
`false` give one HTTP attempt without a Retry-After sleep. Do not change this to
`maxRetries: 0`: this SDK replaces zero with its default. POST redirects are not
followed by the pinned ethers implementation. It sends SDK method `send`, SDK
version `3.6.5`, JSON content type and the public dummy bearer, without a default
User-Agent. This example explicitly sets `Accept: application/json` through the
SDK's supported header configuration so the request does not depend on an
upstream HTTP client's default Accept value. Serverware owns the bounded
64-KiB response policy.
[SDK configuration](https://github.com/alchemyplatform/alchemy-sdk-js/blob/v3.6.5/src/api/alchemy-config.ts),
[SDK provider](https://github.com/alchemyplatform/alchemy-sdk-js/blob/v3.6.5/src/api/alchemy-provider.ts),
[ethers retries](https://github.com/ethers-io/ethers.js/blob/v5.8.0/packages/web/src.ts/index.ts).

## Verification and CI

Component verification passed: **15 tests** across the two suites below, using
the installed pinned dependencies. The actual entrypoint also passed isolated
SDK-through-proxy/TLS acceptance from source `062180fe`: two mainnet reads, plus
wrong-application, wrong-chain and revoked-grant denials. The fixture used a
synthetic provider and verified exact key replacement and separate TLS roots.
See the [verification record](../../docs/operator-alchemy-verification.md),
including both earlier failed runs. Real Alchemy, Actions, native-pilot and
deployment acceptance remain unverified.

```sh
npm test
npm run test:sdk
```

The first suite is inert configuration/launcher testing. The second uses the
actual pinned SDK and Node HTTP serializer with an in-memory Agent connection;
real sockets and DNS are forbidden. Neither proves proxy dispatch, TLS,
credential replacement, real Alchemy access, deployment, native-pilot acceptance
or blockchain freshness.

[workflow.example.yml](workflow.example.yml) is inactive here. Review it before
deliberately copying it into `.github/workflows/`. It allows manual dispatch on
the default branch only, uses a protected environment, installs dependencies
before exposing the limited application token, and never needs an Alchemy key.
This workflow has not been run.
