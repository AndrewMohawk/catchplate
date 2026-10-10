# Alchemy and X operator presets: bounded implementation plan

Status (2026-10-10): **X source implemented; through-proxy acceptance pending.
Alchemy remains design only.** X now has a separate adapter, catalog/API, guided
UI and pinned Node/Python/Go examples. Local checks are recorded in
[the X verification record](operator-x-username-verification.md). Neither a live
X request nor deployment acceptance is claimed. X controls require a fresh
matching gate capability; an older gate cannot implicitly enable the preset.
The Alchemy names below remain proposed contracts, not usable API endpoints.

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

Prefer small isolated `x.app_read.v1` and `alchemy.rpc_read.v1` adapters, using
the existing static-custody, bounded-response and final-dispatch machinery. This
keeps compatibility changes out of legacy X OAuth and generic rules. If a smaller
named generic profile is chosen instead, it must prove the same exact contract
and keep the existing unmarked-profile behavior unchanged.

## Fixed X contract and proposed Alchemy contract

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
Propose success HTTP 200 only, X up to 1 MiB and Alchemy up to 64 KiB; supported
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

## Required integration seams and ownership

Assign one owner to each shared-file group; do not split the two providers across
agents editing the same catalog or UI dispatch chain. No registry framework or
general adapter refactor is needed for these two slices.

| Owner | Exact proposed files and work |
| --- | --- |
| Python contract/catalog | New `serverware/x_app_read.py`, `alchemy_rpc_read.py`, `operator_catalog_x.py`, `operator_catalog_alchemy.py`; modify `operator_catalog_inputs.py`, `operator_catalog_schema.py`, `operator_catalog_mutations.py`, `operator_catalog_policy.py`, `adapters.py`, `policy_bundle.py`. Own strict inputs, closed connection dispatch, derived rules, signed policy rendering, parser parity and public capabilities. |
| Rust/schema | New `data-plane/decision-gate-rs/src/x_app_read.rs`, `alchemy_rpc_read.rs` and focused tests; narrow joins in `main.rs` and `buffered_response.rs`; new schemas under `schemas/adapters/` plus `schemas/policy-bundle.v1.schema.json`. Own startup embedded-schema compilation, request normalization, typed operation fields/read classification, response profile/finalizer joins and actual no-body/body preparation paths. |
| API admission | `serverware/operator_catalog_api.py`, `operator_demo.py`: add only the four named POST paths below using existing admin, exact Origin, strict JSON, no-store, bounded-worker and fixed-error behavior. Coordinate optional closed timing labels; unknown timing operations must not affect mutation results. |
| UI | New `serverware/operator_demo_web/workspace_x.js`, `workspace_alchemy.js`; narrow updates to `workspace_core.js`, `workspace_connect.js`, `workspace_resources.js`, `workspace_proxy_audit.js`, `index.html`. Own exact DTO projection, guided controls, write-only secret clearing, saved-rule recovery, compatibility copy and public example links. |
| Runnable examples | New `examples/x-username-{node,python,go}/` and `examples/alchemy-chain-status-{node,python,go}/`, with pinned dependency files, README, tests and Node GitHub Actions example. Own ordinary SDK configuration, not a replacement HTTP implementation masquerading as the SDK. |
| Acceptance | New focused catalog/API/browser/provider-fixture tests, reusing the existing GitHub/npm isolated fixture architecture. Rust tests stay with the Rust owner. One runtime owner executes frozen source and records results; source authors do not imply execution. |

Proposed API base is `/api/operator-demo`:

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

The catalog seams that are easy to miss are `_public`'s current npm/otherwise-
GitHub provider label, `replace_credential_key`'s validator selection,
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
dummy credential. Dependencies listed here are candidates, not accepted pins:

- Node: official `@xdevplatform/xdk`; official `alchemy-sdk` with keyless `url`,
  dummy bearer in `connectionInfoOverrides.headers`, and batching disabled.
  The X client uses native fetch; Alchemy's ethers-v5 path uses `https.request`.
  Node 25.5's documented `--use-env-proxy` supports both global transports.
  Keep TLS verification and `NODE_EXTRA_CA_CERTS`; clear conflicting proxy/bypass
  configuration. X uses `retry: false` for bounded testing, not `maxRetries: 0`.
  Alchemy's current `maxRetries || default` also needs an actually supported
  bounded retry setting; zero must not be described as working without proof.
- Python: official `xdk` and `web3.py`, using explicitly configured Requests
  sessions/proxy/trust. Web3.py supports disabling exception retries. XDK calls
  its exposed session; establish a bounded request timeout with a documented
  session/adapter hook or report the gap, rather than claiming a timeout argument
  it does not expose. Avoid ambient `.netrc`, token discovery and proxy fallback.
- Go: `go-twitter/v2` (community, not an official X SDK) with fixed `Host`, dummy
  `Authorizer` and configured `http.Client`; `go-ethereum/rpc` with
  `WithHTTPClient` and `WithHeader`. Use context deadlines, explicit HTTPS proxy,
  a CA pool retaining required public roots, and no redirects.

Source references: [X SDKs](https://docs.x.com/tools-and-libraries),
[X TS client](https://raw.githubusercontent.com/xdevplatform/xdk-typescript/main/src/client.ts),
[X Python client](https://raw.githubusercontent.com/xdevplatform/xdk-python/main/xdk/client.py),
[Alchemy configuration](https://raw.githubusercontent.com/alchemyplatform/alchemy-sdk-js/master/src/api/alchemy-config.ts),
[Alchemy provider](https://raw.githubusercontent.com/alchemyplatform/alchemy-sdk-js/master/src/api/alchemy-provider.ts),
[Node 25.5 proxy support](https://nodejs.org/download/release/v25.5.0/docs/api/http.html#built-in-proxy-support),
[Web3.py providers](https://web3py.readthedocs.io/en/stable/providers.html),
[Go Twitter](https://raw.githubusercontent.com/g8rswimmer/go-twitter/master/v2/client.go),
[Go Ethereum RPC options](https://raw.githubusercontent.com/ethereum/go-ethereum/master/rpc/client_opt.go).

GitHub Actions stores only the scoped **Serverware application token** as a
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

Until the through-proxy gates are recorded, label the projects **proxy acceptance
pending** and do not deploy/enable the new paired preset. Offline SDK checks must
remain distinct from proxy/TLS and provider acceptance. Keep existing
GitHub/npm/Google and manual workflows unchanged while adding each complete slice.
