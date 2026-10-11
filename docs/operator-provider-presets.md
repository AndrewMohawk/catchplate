# X and Alchemy operator presets

Status (2026-10-10): **X isolated SDK-through-proxy acceptance passed;
Alchemy is implemented and component-verified, with proxy acceptance pending.**
X has a separate adapter, catalog/API, guided UI and pinned Node/Python/Go
examples. All three actual entrypoints passed using
source `eb5d12e5` and the normal Rust binary recorded below. Each client's
wrong-application, wrong-username and revoked-grant controls were refused.
Separate raw controls refused the wrong dummy, method and query, released a
bounded HTTP 429 JSON response intact and blocked four hostile responses. The
network-none fixture verified eight upstream arrivals, 20 proxy connections,
durable audit and separate TLS roots, with no host ports or provider contact.
Its 82.017 seconds cover the fixture and cleanup, not native startup.
Offline tests remain separate results in
[the X verification record](operator-x-username-verification.md). Neither a live
X request, GitHub Actions run nor deployment acceptance is claimed. X controls
require a fresh matching gate capability; an older gate cannot implicitly enable the preset.

Alchemy's adapter, catalog/API, UI source, examples and isolated fixture/checker
are implemented. Its UI remains guide-only pending acceptance; this does not
establish support in a deployed app/gate pair.

The component checkpoint in `alchemy-verification.1YKDDXyl` records 33 passing
core/fixture/runner checks, 11 catalog checks and 5 API checks. The installed SDK
checks passed: Node 15, Python 10 with its full transitive dependencies, and Go
8 main test groups plus a built example binary. The shared 75-test Python run
had one cross-suite import-isolation failure; the isolated asset rerun passed
all 13 checks. That combined run is not recorded as a clean pass. The optimized
Rust build succeeded and all 12 Alchemy Rust groups passed. Browser checks passed
16 Alchemy groups and 13 X regression groups with unchanged source; those checks
use synthetic intercepted APIs, not the real backend. Actual SDK-through-proxy/TLS
acceptance has not passed; real-provider, native and deployment acceptance remain
unverified. The [Alchemy verification record](operator-alchemy-verification.md)
retains both failed isolated runs, the completed SDK/control checks, and the
second run's pre-dispatch refusal without treating partial progress as a pass.

## Ship X username reads first

The common journey is **save a provider key → choose an application → review one
permission → configure an ordinary client**. Keep **Manual API key** as a separate
advanced option. Saving a key grants nothing, contacts no provider and proves
neither account ownership nor provider entitlement. No response-field editor is
needed for either preset.

X username lookup is the smaller first vertical slice: an exact HTTPS GET with
no query or body. Alchemy uses POST for both reads and writes, so it additionally
needs a real JSON-RPC method/parameter guard before credential acquisition.

Two existing shortcuts would be incorrect:

- The existing `x.v2` adapter requires an OAuth2 credential, provider `x`, client
  identity and scopes. Both [its schema](../schemas/adapters/x.v2.schema.json)
  and `_validate_route_credential_binding` in
  [policy_bundle.py](../serverware/policy_bundle.py) enforce this. Do not relax it
  to accept an imported app-only bearer token or fabricate OAuth metadata.
- A generic exact GET can serve clients without a Content-Type header, but the
  official X TypeScript SDK sends `application/json` even for GET. Existing
  `generic.rest` `bodyMode: none` requires an empty media-type allowlist. Therefore
  the whole stock-SDK slice needs a narrow versioned admission path; do not claim
  current generic rules already accept it or loosen generic admission globally.

X uses the separate `x.app_read.v1` adapter; Alchemy uses
`alchemy.rpc_read.v1`. They use the existing static-custody, bounded-response
and final-dispatch machinery, keeping compatibility changes out of legacy X
OAuth and generic rules. Alchemy's implemented JSON-RPC method/parameter guard
is not an NFT GET or a generic POST grant.

## Fixed X and Alchemy contracts

| Item | X app-only username read | Alchemy chain status read |
| --- | --- | --- |
| Connection marker | `x_app_bearer_v1` | `alchemy_key_v1` |
| Permission bundle | `x_username_read_v1` | `alchemy_chain_status_read_v1` |
| Credential input | Imported app-only bearer token | API key or access key, not a URL, Notify token or wallet key |
| SDK dummy | `serverware-x-placeholder-v1` | `serverware-alchemy-placeholder-v1` |
| Upstream authentication | Exact dummy `Bearer …` replaced by stored token | Exact dummy `Bearer …` replaced by stored key |
| Target | `https://api.x.com:443/2/users/by/username/<saved-name>` | Selected exact `https://eth-mainnet.g.alchemy.com:443/v2` or `https://eth-sepolia.g.alchemy.com:443/v2` |
| Authority input | One lowercase ASCII `[a-z0-9_]{1,15}` username per rule | One enum `eth-mainnet` or `eth-sepolia`; both fixed read methods |
| Request | GET; empty query; zero body bytes | POST; empty query; one JSON-RPC request, at most 64 KiB |
| Excluded | Search, pagination, `/users/me`, posting, DMs, media, streams, OAuth exchange/refresh | Batch requests, notifications, arbitrary RPC, transactions, wallets, WebSockets, NFT and Notify APIs |

All stored bearer values are write-only, bounded to 1–8192 bytes, without spaces,
controls or CR/LF; use an opaque bearer-token grammar, not guessed provider-prefix
recognition. Validation is syntax only. Static keys are not automatically renewed;
an imported expiring access key may stop working at its provider expiry.

Alchemy officially supports API/access keys in an Authorization header at a
keyless `/v2` endpoint. This design therefore needs **no secret URL rewriting**.
The default Alchemy SDK key-in-path configuration is not the recipe.
[Alchemy header authentication](https://www.alchemy.com/docs/how-to-use-api-keys-in-http-headers).

For Alchemy, require exact root fields `jsonrpc`, `id`, `method`, `params`:
`jsonrpc == "2.0"`, `method` is `eth_chainId` or `eth_blockNumber`, and `params == []`.
Admit IDs that ordinary clients use: an exact integer from 0 through
9,007,199,254,740,991, or a nonempty bounded printable ASCII string up to 64 bytes;
reject booleans, null, floats, duplicate keys, unknown fields and root arrays.
Hash and forward the admitted original bytes, not reserialized JSON. Normalize
the operation to the selected chain and parsed method; HTTP POST alone must not
be classified as a blockchain-write grant.

Both profiles own a closed, sorted header contract. Start with `accept`,
`accept-language`, `sec-fetch-mode`, `user-agent`; Alchemy additionally needs
`alchemy-ethers-sdk-method` and `alchemy-ethers-sdk-version`. Discard only the
bounded `accept-encoding` offer, preserving the existing canonical discard-header
commitment. Authorization is handled solely by exact replacement, not forwarded
as a general allowed header. Keep existing framing, Host, proxy-authentication,
internal-header and duplicate-authentication guards. X may have no Content-Type
or one JSON/UTF-8 Content-Type while still requiring an empty body; Alchemy
requires one. Pin the actual dependency versions and confirm their wire headers
before freezing these lists; do not learn a broader allowlist from traffic.

Responses remain full bounded strict JSON, not user-configured field projection.
X admits success HTTP 200 up to 1 MiB; the Alchemy limit is 64 KiB. Supported
HTTP errors 400/401/403/404/429/500/502/503/504 up to 64 KiB. Accept only
`application/json`, optionally UTF-8 charset; no compressed bodies, redirects,
empty 204/304 or streaming. Validate and discard bounded unselected metadata;
forward no response headers initially. Reuse credential-reflection rejection
and existing response release/freshness checks. Each new adapter must explicitly
admit its exact response profile, not enable another adapter's mode globally.
Alchemy HTTP-200 envelopes must retain `jsonrpc: "2.0"`, the same typed request ID,
and exactly one of `result` or `error`; an RPC error is not a successful method
result. X may return structured provider errors; do not call any HTTP-200 body
proof of token validity or successful user lookup.

X app-only authentication is distinct from user OAuth. A future “Post to X”
permission needs its own user-token lifecycle and authorization review; OAuth1
signatures are not static header replacement. This lookup slice does not fulfill
the original posting example. [X authentication](https://docs.x.com/fundamentals/authentication/overview),
[username lookup](https://docs.x.com/x-api/users/get-user-by-username).

## Implementation seams and ownership

Assign one owner to each shared-file group; do not split the two providers across
agents editing the same catalog or UI dispatch chain. No registry framework or
general adapter refactor is needed for these two slices. Both implementations
occupy the seams below; their verification levels remain separate.

| Owner | Files and work |
| --- | --- |
| Python contract/catalog | New `serverware/x_app_read.py`, `alchemy_rpc_read.py`, `operator_catalog_x.py`, `operator_catalog_alchemy.py`; modify `operator_catalog_inputs.py`, `operator_catalog_schema.py`, `operator_catalog_mutations.py`, `operator_catalog_policy.py`, `adapters.py`, `policy_bundle.py`. Own strict inputs, closed connection dispatch, derived rules, signed policy rendering, parser parity and public capabilities. |
| Rust/schema | New `data-plane/decision-gate-rs/src/x_app_read.rs`, `alchemy_rpc_read.rs` and focused tests; narrow joins in `main.rs` and `buffered_response.rs`; new schemas under `schemas/adapters/` plus `schemas/policy-bundle.v1.schema.json`. Own startup embedded-schema compilation, request normalization, typed operation fields/read classification, response profile/finalizer joins and actual no-body/body preparation paths. |
| API admission | `serverware/operator_catalog_api.py`, `operator_demo.py`: add only the four named POST paths below using existing admin, exact Origin, strict JSON, no-store, bounded-worker and fixed-error behavior. Coordinate optional closed timing labels; unknown timing operations must not affect mutation results. |
| UI | New `serverware/operator_demo_web/workspace_x.js`, `workspace_alchemy.js`; narrow updates to `workspace_core.js`, `workspace_connect.js`, `workspace_resources.js`, `workspace_proxy_audit.js`, `index.html`. Own exact DTO projection, guided controls, write-only secret clearing, saved-rule recovery, compatibility copy and public example links. |
| Runnable examples | New `examples/x-username-{node,python,go}/` and `examples/alchemy-chain-status-{node,python,go}/`, with pinned dependency files, README, tests and Node GitHub Actions example. Own ordinary SDK configuration, not a replacement HTTP implementation masquerading as the SDK. |
| Acceptance | New focused catalog/API/browser/provider-fixture tests, reusing the existing GitHub/npm isolated fixture architecture. Rust tests stay with the Rust owner. One runtime owner executes frozen source and records results; source authors do not imply execution. |

The API base is `/api/operator-demo`; these typed paths are implemented in
source and require their matching app/gate capabilities:

- `POST /credentials/x-app-bearer` and `/credentials/alchemy-key`: exact
  `{expected_revision, expected_policy_hash, name, secret}`, maximum 16 KiB.
- `POST /access-rules/x-username`: exact CAS/name/application/credential fields,
  `operation_bundle: "x_username_read_v1"`, `username`, maximum 4 KiB.
- `POST /access-rules/alchemy-chain-status`: the same identity/CAS fields,
  `operation_bundle: "alchemy_chain_status_read_v1"`, `chain`, maximum 4 KiB.

Do not accept caller-supplied URL, methods, header lists, response mode, adapter
configuration or raw policy in a preset DTO. The catalog continues using static
credential provider `operator-demo` and its encrypted custody; `provider_id: x`
or `alchemy` is a public catalog label, not fabricated upstream identity.
Existing generic rows remain unmarked. Explicit provider markers must never fall
through to generic rules or another provider's token validator.

The catalog seams that must remain consistent are `_public`'s explicit provider
label, `replace_credential_key`'s validator selection,
`validate_static_connection`, content-mode dispatch, and renderer dispatch.
Update them together with revoke/rotation/restart tests; no separate vault is
needed. Reuse `_mutate`'s publication EX, SQLite transaction, catalog CAS, audit
append, commit, materialization and pending receipt. A mutation receipt is not
gate loading. A fresh catalog observation must confirm the policy hash before
client use. Uncertain mutations require saved-state inspection, never browser
automatic POST replay.

The deployment must separately approve the exact provider origin using the
existing [destination workflow](operator-proxy-destinations.md). A provider
choice must not add a destination, restart services, contact a provider or select
a token implicitly. Advertise only a complete paired implementation; retain
separate states for destination approval, saved permission, loaded policy and
observed client result. Preserve ordinary static generation, revocation, expiry,
audit and final-send barriers; no lease/deadline/retry changes are part of this plan.

## Runnable clients and GitHub Actions

Use the provider's supported hooks, with the saved username/chain and public
dummy credential. The passed X recipes are:

- [Node](../examples/x-username-node/README.md): official XDK **0.6.6**, Undici
  **8.11.2**, Node **25.5.0**. Native fetch uses an explicit documented global
  ProxyAgent dispatcher with separate TLS roots and a one-dispatch interceptor.
  The SDK uses `retry: false`, not `maxRetries: 0`.
- [Python](../examples/x-username-python/README.md): official XDK **0.10.6**
  with its exposed Requests session, a documented timeout adapter and separate
  verified proxy/destination TLS configuration; exercised on Python **3.12**.
- [Go](../examples/x-username-go/README.md): community `go-twitter/v2`
  **v2.1.5**, exercised on Go **1.23.12**, with its supported HTTP client and
  authorizer hooks and per-host TLS verification. It is not an official X SDK.

These are explicit supported client configurations, not a claim that ambient
proxy settings or unchanged retry defaults suffice. The implemented Alchemy
examples have passed offline SDK checks, not actual-proxy acceptance:

- [Node](../examples/alchemy-chain-status-node/README.md): pinned official
  `alchemy-sdk` **3.6.5**, ethers **5.8.0**, Node **25.5.0**, with keyless `url`,
  dummy bearer and batching disabled. Its normal `https.request` path uses a
  dedicated-process HTTPS Agent with explicit `proxyEnv` and separate TLS roots.
  `throttleLimit: 1` plus a refusing throttle callback bounds each method to one
  attempt; `maxRetries: 0` is not used. This archived SDK is a pinned compatibility
  example, not a claim of active maintenance.
- [Python](../examples/alchemy-chain-status-python/README.md): `web3.py`
  **7.13.0**, using explicitly configured Requests sessions/proxy/trust and
  disabled exception retries, without ambient `.netrc` or proxy fallback.
- [Go](../examples/alchemy-chain-status-go/README.md): `go-ethereum/rpc`
  **v1.15.11**, with `WithHTTPClient` and `WithHeader`, context deadlines,
  explicit HTTPS proxy, per-host verified TLS trust and no redirects or retries.

Source references: [X SDKs](https://docs.x.com/tools-and-libraries),
[X TS client](https://raw.githubusercontent.com/xdevplatform/xdk-typescript/main/src/client.ts),
[X Python client](https://raw.githubusercontent.com/xdevplatform/xdk-python/main/xdk/client.py),
[Alchemy configuration](https://raw.githubusercontent.com/alchemyplatform/alchemy-sdk-js/master/src/api/alchemy-config.ts),
[Alchemy provider](https://raw.githubusercontent.com/alchemyplatform/alchemy-sdk-js/master/src/api/alchemy-provider.ts),
[Node 25.5 proxy support](https://nodejs.org/download/release/v25.5.0/docs/api/http.html#built-in-proxy-support),
[Web3.py providers](https://web3py.readthedocs.io/en/stable/providers.html),
[Go Twitter](https://raw.githubusercontent.com/g8rswimmer/go-twitter/master/v2/client.go),
[Go Ethereum RPC options](https://raw.githubusercontent.com/ethereum/go-ethereum/master/rpc/client_opt.go).

The X Node Actions recipe remains an inactive, unexecuted example. GitHub Actions
stores only the scoped **Serverware application token** as a
secret. Application ID, proxy URL, public CA and dummy provider token are client
configuration, never Alchemy/X key material. Use explicit manual workflow
dispatch and pinned actions/dependencies; no provider request on PRs or page
load. Do not put proxy passwords in command arguments, tracked files or logs;
do not dump SDK exceptions/request objects. Source downloads contain no private
configuration. The proxy's outer TLS and intercepted destination TLS both need
verified trust; never use TLS-disable settings.

## Acceptance gates, in order

1. **Contracts and persistence:** Python/Rust shared positive/negative vectors;
   exact schema compilation; duplicates, wrong dummy, crossed provider marker,
   malformed target, broad methods, unsupported media and response reflection
   refused. Alchemy additionally rejects writes, batches, bad IDs/params and
   mismatched response IDs. Real catalog tests cover CAS, encrypted storage,
   replacement, revocation, retained reload and rollback; outputs contain no key.
2. **Rendered UI + actual API:** desktop/mobile journey saves key/app/rule with
   no response-field interaction; secrets clear before awaiting submission and
   on navigation/error; no secret browser storage/downloads; unsupported
   capabilities fail closed; uncertainty never auto-replays. Real API/SQLite
   proof is distinct from browser route mocks.
3. **Ordinary SDK → real proxy → isolated TLS fixture:** each pinned Node,
   Python and Go client completes the supported lookup using the downloaded CA
   and normal SDK call. Keep the provider hostname fixed with synthetic DNS and
   no external route. Receiver independently proves the injected synthetic key,
   exact target/body and arrival count; the workload sees only dummy credentials.
   Prove wrong app/dummy/username/chain/method and revoked access have zero
   forbidden arrivals. Verify JSON errors, bounds/reflection, ordinary audit,
   policy loading and both TLS legs. Explicit test retry settings are not a claim
   about unchanged SDK defaults. Test the real buffered preparation path, not
   only an isolated request validator.
4. **Optional real-provider check:** separately authorized, least-privilege key,
   one read-only lookup and bounded output. Local synthetic acceptance does not
   prove provider entitlement, billing, token validity or a live GitHub Actions
   run. Never turn source/UI completion into these claims.

The X projects have passed the isolated through-proxy gate; this is not permission
to deploy or proof that a deployment has the paired preset. Alchemy is implemented
and component-verified, but its guide-only UI must not imply completed proxy/TLS
acceptance. Offline SDK checks, isolated proxy/TLS acceptance, deployment
acceptance and real-provider access remain separate results. Keep existing
GitHub/npm/Google and manual workflows unchanged while adding each complete slice.
