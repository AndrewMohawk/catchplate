# Go: read Ethereum chain status through Serverware

**Component-verified; actual-proxy acceptance pending.** Eight main test groups
passed and the example binary was built. The Alchemy UI remains guide-only;
neither deployed support nor real-provider/native-pilot acceptance is verified.
This example uses the ordinary
[`go-ethereum/rpc` client pinned to v1.15.11](https://github.com/ethereum/go-ethereum/tree/v1.15.11/rpc),
not an Alchemy-specific SDK or a replacement HTTP implementation. It makes two
separate read-only RPC calls, `eth_chainId` and `eth_blockNumber`, for one selected
chain. No batching, arbitrary RPC, wallet, transaction, WebSocket or NFT operation
is available in this entrypoint. The real Alchemy API/access key stays in
Serverware; the application only receives its scoped proxy credential.

Do not use the recipe until your deployment supports the complete paired
Alchemy preset and passes the
[provider acceptance gates](../../docs/operator-provider-presets.md#acceptance-gates-in-order).
Offline SDK tests alone do not prove real-proxy acceptance, deployment support,
provider entitlement or validity of an Alchemy key.

## Configure and run

When `alchemy_key_v1` and `alchemy_chain_status_read_v1` are supported, save the
Alchemy API/access key in Serverware, create an application, and grant
**Alchemy chain status: read** for `eth-mainnet` or `eth-sepolia`. Select the
application's **Basic and Bearer** authentication mode (`basic_and_bearer_v1`);
this recipe uses Basic only on the proxy CONNECT request. Check the saved rule
and loaded policy hash before running. The operator must separately approve the
exact selected HTTPS destination; saving a key or grant does not approve it.

Download and verify the interception CA through the authenticated operator setup
flow. Use the HTTPS proxy URL, not the admin UI URL. Configure the following
environment values; [.env.example](.env.example) contains public placeholders
only and is not automatically loaded:

| Variable | Value |
| --- | --- |
| `SERVERWARE_PROXY_URL` | HTTPS proxy origin, optionally with a port; no credentials or path |
| `SERVERWARE_APP_ID` | Saved application UUID |
| `SERVERWARE_PROXY_TOKEN` | Issued Serverware application token, **not** an Alchemy key |
| `SERVERWARE_CA_FILE` | Local PEM file containing the verified interception CA |
| `SERVERWARE_PROXY_CA_FILE` | Optional extra CA for outer HTTPS-proxy TLS; omit for public trust |
| `SERVERWARE_ALCHEMY_CHAIN` | Exactly `eth-mainnet` or `eth-sepolia`, matching the saved rule |

Supply the application token through an environment/CI secret store, not command
arguments, URLs or tracked files. With Go 1.23 or later, from this directory:

```sh
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go run .
```

The tests use synthetic in-memory RPC responses and generated certificates; they
do not call Alchemy or a real proxy. **`go run .` performs two real read requests**
through the configured proxy, subject to its policy. Successful output contains
only public chain status, for example `{"chain_id":"0x1","block_number":4660}`.
The first response must identify the selected chain (`0x1` for mainnet,
`0xaa36a7` for Sepolia) before the block read is sent. The block height must be a
canonical lowercase hex quantity fitting an unsigned 64-bit integer. RPC errors,
wrong-chain responses and partial completion produce a fixed error, not a
successful summary. Raw SDK/provider error messages are never printed.

There is a 45-second total context deadline, a 30-second per-request HTTP timeout,
a 10-second TLS-handshake limit and a 20-second response-header limit. Redirects,
automatic compression and connection reuse are disabled. The HTTP RPC path and
entrypoint do not retry failed requests. Inspect audit records and the saved
permission before trying again.

## Supported RPC hooks, not HTTP rewriting

The client uses `rpc.DialOptions` with the documented `WithHTTPClient` and
`WithHeader` hooks. The endpoint is fixed by the chain enum to one keyless
`https://eth-mainnet.g.alchemy.com/v2` or
`https://eth-sepolia.g.alchemy.com/v2` URL; no endpoint override or key-in-path URL
is accepted. `WithHeader` supplies the public dummy
`Authorization: Bearer serverware-alchemy-placeholder-v1`. Serverware replaces
that exact value. No real provider key is read from the application's environment.

Both calls use normal `CallContext` with an explicitly non-nil empty variadic
argument slice. This matters: the pinned client emits `params: []` for that
slice, whereas omitting all arguments omits the `params` field. The resulting
requests have numeric IDs `1` then `2`, `jsonrpc: "2.0"`, the respective fixed
method, and `params: []`, each in its own POST. The SDK supplies
`Accept: application/json` and `Content-Type: application/json`. Standard Go
HTTP/1.1 adds its default `User-Agent: Go-http-client/1.1` and `Connection: close`.
No JSON, path or header rewriter stands between the SDK and normal transport.

These behaviors are visible in the pinned
[client options](https://github.com/ethereum/go-ethereum/blob/v1.15.11/rpc/client_opt.go),
[RPC message creation](https://github.com/ethereum/go-ethereum/blob/v1.15.11/rpc/client.go)
and [HTTP transport](https://github.com/ethereum/go-ethereum/blob/v1.15.11/rpc/http.go).
The proxy remains responsible for the complete strict response envelope checks,
including response ID/type matching, version, bounds and credential reflection;
the SDK must not be mistaken for a substitute for those checks.

## Proxy authentication and both TLS hops

The standard Go transport always selects the configured HTTPS proxy. Application
UUID/token are passed only by `GetProxyConnectHeader` as CONNECT
`Proxy-Authorization`; they never enter the inner Alchemy request or a URL.
Ambient `HTTPS_PROXY`, `NO_PROXY`, `ALCHEMY_API_KEY` and `WEB3_PROVIDER_URI` are not
consulted. There is no `.netrc`, provider-token discovery or direct-network
fallback in the recipe.

Normal certificate verification stays enabled for both outer HTTPS-proxy TLS
and the inner intercepted provider TLS. Go shares one TLS config between these
hops; a standard `VerifyConnection` callback re-verifies each chain with only the
roots for its exact hostname. The proxy uses system roots plus its optional
extra CA. Only the selected provider hostname uses the interception CA. Do not
put that interception CA in the proxy CA file. Crossed CA roles, the unselected
chain and unexpected hostnames are refused. No custom dialer, disabled TLS check
or `InsecureSkipVerify` is used.

The example refuses nonempty `SSL_CERT_FILE` or `SSL_CERT_DIR`, because Go's
system-root loader otherwise honors those ambient overrides. It does not silently
modify your environment. Remove those overrides before running, and use
`SERVERWARE_PROXY_CA_FILE` for an explicitly selected extra outer-proxy CA.

## Dependency and acceptance boundary

Version v1.15.11 is pinned for the available Go 1.23 toolchain; its
[module declaration](https://proxy.golang.org/github.com/ethereum/go-ethereum/@v/v1.15.11.mod)
requires Go 1.23.0. The [module version record](https://proxy.golang.org/github.com/ethereum/go-ethereum/@v/v1.15.11.info)
resolves to commit `36b2371c59cd91a9b1da062b3e382f05a6d8687e`. Initial module and
go.mod checksum entries come from the
[Go checksum database](https://sum.golang.org/lookup/github.com/ethereum/go-ethereum@v1.15.11).
The recorded component run resolved dependencies and built the binary; normal
Go tooling must still resolve and verify them in a fresh environment before use.
Do not disable checksum verification or download a different toolchain implicitly.

The source tests cover actual SDK request serialization, both chains, exact
empty-array parameters, fixed dummy authentication, CONNECT-only application
authentication, fixed errors, no redirects/retries and per-host TLS trust.
The eight main test groups passed; actual SDK-through-proxy/TLS acceptance has
not run and remains a separate result. Nothing here creates a credential,
approves a destination, deploys a service, or runs a provider-backed GitHub Action.
