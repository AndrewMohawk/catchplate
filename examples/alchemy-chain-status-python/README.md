# Alchemy chain status with web3.py

Status: **current isolated SDK-through-proxy/TLS acceptance passed** with web3.py
7.15.0 on Python 3.12.14, source `dcf70631` and normal Rust SHA-256 prefix
`0908732386fa`. The **10 offline SDK tests** are separate component evidence.
No deployment, Actions, native-pilot acceptance, real Alchemy request or provider
entitlement is claimed. This example uses the
ordinary `Web3.eth.chain_id` and `Web3.eth.block_number` properties, not a custom
JSON-RPC client. It does not request wallets, transactions, balances, NFT APIs,
WebSockets, batching or `web3_clientVersion`.

Use Python 3.12 and install the exact direct SDK/transport requirements in a
private virtual environment:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -B -m unittest -v test_chain_status
```

The requirements pin web3.py 7.15.0, Requests 2.34.2, urllib3 2.8.0, certifi
2026.7.22 and Pydantic 2.13.4. They are direct pins, not a complete transitive
lock. The executable verifies these installed versions before launching.
The recorded Python 3.12.14 component run resolved and installed 40 packages from
wheels and tested the real SDK. The current proxy acceptance reused that repaired
cache, checked the installed direct-version metadata, and bound its repair and
resolver records; it did not rehash the full installed payload or create a
complete transitive lock. A fresh environment must still resolve and install the
transitive dependencies. This is
not a stdlib-only example: web3.py also requires its Ethereum libraries,
aiohttp and websockets, while Pydantic requires its matching native core.
Use an interpreter that works without an ambient `LD_LIBRARY_PATH`: the child
inherits only the explicit application configuration below, not shell settings.

Version 7.15.0 fixes the maintainer's
[CCIP Read advisory GHSA-5hr4-253g-cpx2](https://github.com/ApeWorX/web3.py/security/advisories/GHSA-5hr4-253g-cpx2).
This example's two chain-status calls do not invoke `eth_call` or CCIP Read;
the dependency update and regression tests are not an exploit-reachability test.

## Configure one saved permission

First save the Alchemy key privately in Serverware, approve the exact provider
destination and save a chain-status permission for one application. Wait for
the matching gate/policy to load. The application must have **Basic proxy
authentication enabled**; a bearer-only proxy application is not sufficient.

Set the variables illustrated in `.env.example` through your secret manager or
private shell environment. The program does not load `.env` automatically.
`SERVERWARE_PROXY_TOKEN` is only the scoped **Serverware application token**.
Never configure an Alchemy key, wallet secret or key-containing provider URL in
this client. Keep real environment files and CA material out of commits.

```sh
.venv/bin/python chain_status.py
```

`SERVERWARE_ALCHEMY_CHAIN` is exactly `eth-mainnet` or `eth-sepolia`. The program
constructs only `https://eth-mainnet.g.alchemy.com/v2` or
`https://eth-sepolia.g.alchemy.com/v2`, without a key path or query. The inner
Authorization value is the public dummy
`Bearer serverware-alchemy-placeholder-v1`; the paired gate replaces it with
the saved provider key. Requests applies application-ID/password Basic
authentication to **CONNECT**, never to the inner provider request.

`SERVERWARE_CA_FILE` is the downloaded public interception CA, added to certifi
for the inner destination TLS connection. Outer HTTPS-proxy TLS uses its own
verified context with certifi roots. Supply `SERVERWARE_PROXY_CA_FILE` only when
the proxy needs an additional public CA. Both paths must be absolute; private
keys are refused. DNS/IPv4 HTTPS proxy origins are supported. TLS and hostname
verification remain enabled on both legs; no ambient proxy, `.netrc`, bypass,
CA-bundle or provider-credential discovery is used.

## Bounds and results

There are two sequential ordinary SDK calls, with empty parameter arrays and
integer request IDs `0` (`eth_chainId`) and `1` (`eth_blockNumber`), and no probe
or fallback call. A failed first call stops before the second. SDK request caching and
exception retries are explicitly disabled. The Requests adapter also has zero
retries, refuses redirects/unexpected destinations and permits at most two
dispatches. It leaves SDK request bytes/headers unchanged and buffers each
uncompressed JSON response up to 64 KiB. Connect/read timeouts are 5/10 seconds;
the normal launcher kills its isolated child after 60 seconds. `--child` is an
internal launcher entrypoint, not a separate deployment recipe.

The two RPCs share one Requests session. Its ordinary keep-alive behavior may
reuse one CONNECT tunnel; two RPCs do not imply two CONNECT establishments.

Success prints only `chain`, numeric `chain_id`, and numeric `block_number`.
The returned chain ID must match the configured chain. HTTP or JSON-RPC errors
are not success and are not retried. Errors print one fixed diagnostic, without
exception text, response bodies, URLs, tokens or request objects. This is an
observed read result, not proof of provider ownership or future availability.

The 10 passing offline tests use the actual pinned web3.py/Requests preparation path and
synthetic responses at `HTTPAdapter.send`, with sockets forbidden. They inspect
separate TLS policies but do not perform a TLS handshake, CONNECT, proxy
credential replacement or provider request. The separate **current 7.15.0
proxy acceptance** completed two mainnet reads and wrong-application, wrong-chain
and revoked-grant denials through normal Rust with a synthetic provider. The
joined Node/Python/Go run passed all **12 SDK phases**, exact key replacement,
separate TLS roots, response controls and audit-chain verification. Python's two
successful calls shared one pooled tunnel, not an extra retry.
The [current verification record](../../docs/operator-alchemy-verification.md#current-dependency-graph-acceptance)
binds receipt `alchemy-current-acceptance.bHL9ONTf/result.json` and preserves the
earlier `062180fe`/7.13.0 pass and both preceding failures. This remains synthetic
proxy evidence, not real-provider or deployed-instance acceptance.

## Primary implementation references

- [Pinned web3.py HTTPProvider](https://raw.githubusercontent.com/ethereum/web3.py/v7.15.0/web3/providers/rpc/rpc.py): explicit session and `exception_retry_configuration=None`.
- [Pinned web3.py provider base](https://raw.githubusercontent.com/ethereum/web3.py/v7.15.0/web3/providers/base.py): request IDs, serialization and opt-in caching.
- [Pinned Requests adapter extension](https://raw.githubusercontent.com/psf/requests/v2.34.2/src/requests/adapters.py): `proxy_manager_for`, retry and TLS settings.
- [urllib3 HTTPS proxies](https://urllib3.readthedocs.io/en/2.8.0/advanced-usage.html#https-proxies): a separate `proxy_ssl_context` for TLS-in-TLS.
- [Alchemy header authentication](https://www.alchemy.com/docs/how-to-use-api-keys-in-http-headers): bearer authentication at a keyless `/v2` endpoint.
