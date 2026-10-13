# Go: read Ethereum chain status through Serverware

**Current isolated SDK-through-proxy/TLS acceptance passed** from source
`dcf70631` with go-ethereum v1.17.0 and normal Rust SHA-256 prefix `0908732386fa`.
This used the upgraded dependency graph below, not the historical `062180fe` /
v1.15.11 binary. Deployed support, Actions and real-provider/native-pilot
acceptance remain unverified.
This example uses the ordinary
[`go-ethereum/rpc` client pinned to v1.17.0](https://github.com/ethereum/go-ethereum/tree/v1.17.0/rpc),
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
arguments, URLs or tracked files. Use a supported Go release at least 1.25;
this dependency repair uses official Go 1.26.9. From this directory:

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
[client options](https://github.com/ethereum/go-ethereum/blob/v1.17.0/rpc/client_opt.go),
[RPC message creation](https://github.com/ethereum/go-ethereum/blob/v1.17.0/rpc/client.go)
and [HTTP transport](https://github.com/ethereum/go-ethereum/blob/v1.17.0/rpc/http.go).
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

The pinned [go-ethereum v1.17.0 module](https://proxy.golang.org/github.com/ethereum/go-ethereum/@v/v1.17.0.mod)
requires Go 1.24, while the complete patched graph requires Go 1.25.
In addition to `gorilla/websocket v1.5.3`, this module deliberately retains
`x/crypto v0.55.0`, `x/net v0.58.0` and `grpc v1.83.2` security floors.
The named HTTP RPC job does not compile every package in the selected module
graph. These floors protect that graph; they are not evidence that SSH, gRPC,
WebSockets or peer-to-peer networking execute in this example.

The gRPC 1.83 branch requires at least 1.83.2 for
[GHSA-2v4p-qf9q-27wj](https://github.com/grpc/grpc-go/security/advisories/GHSA-2v4p-qf9q-27wj);
the separate 1.82.2 fix does not make 1.83.1 safe. The newer crypto/net/sys/text
requirements come from the actual 1.83.2 module graph. This targeted repair is
not a claim that the whole graph is vulnerability-free.

Ordinary `go mod tidy` removes the unused floors and selects older vulnerable
upstream requirements. Do not treat that change as harmless cleanup: retain the
reviewed constraints and run `TestSelectedModuleGraphSecurityFloors`, which
queries the actual selected graph with `GOPROXY=off` and `-mod=readonly`.
The graph test requires module metadata to have been fetched during setup.
The checked-in module checksums are verified against the
[Go checksum database](https://sum.golang.org/lookup/github.com/ethereum/go-ethereum@v1.17.0).
Normal Go tooling must still resolve and verify dependencies in a fresh
environment. Do not disable checksum verification or implicitly download a
different toolchain.

The source tests cover actual SDK request serialization, both chains, exact
empty-array parameters, fixed dummy authentication, CONNECT-only application
authentication, fixed errors, no redirects/retries and per-host TLS trust.
On 2026-10-12, the upgraded graph passed these eight groups plus the selected
module-graph regression (nine groups total), followed by an ordinary binary
build, using verified official Go 1.26.9. Tests and build used a network-disabled
container with read-only source/module cache and `-mod=readonly`. The application
code and original SDK tests are unchanged. This is offline component evidence,
separate from the current SDK-through-proxy acceptance below.

The upgraded binary (SHA-256 prefix `859b36340827`, built with Go 1.26.9) now also
passed two mainnet reads and wrong-application, wrong-chain and revoked-grant
denials through normal Rust with a synthetic provider. Five current source,
module and test files matched the retained build source. The joined
Node/Python/Go run passed all **12 SDK phases**, exact key replacement, separate
TLS roots, response controls and audit-chain verification. See the
[current verification record](../../docs/operator-alchemy-verification.md#current-dependency-graph-acceptance)
and retained receipt `alchemy-current-acceptance.bHL9ONTf/result.json`.
The historical v1.15.11 component/proxy pass and both earlier fixture failures
remain recorded separately. Nothing here creates a credential, approves a
destination, deploys a service, or runs a provider-backed GitHub Action.
