# X username lookup with the official Python XDK

**Isolated SDK-through-proxy acceptance passed.** On 2026-10-10, this actual
entrypoint passed through the genuine Rust proxy to a network-isolated synthetic
X service, with separate verified outer and inner TLS roots and server-side
token replacement. Wrong application, username and revoked-grant controls were
refused. The run used source `eb5d12e5` and contacted no provider; real X access,
provider entitlement and deployment acceptance remain unverified. See the
[verification record](../../docs/operator-x-username-verification.md).

Separately, all 11 offline tests passed with Python 3.12 and the pinned
SDK/transport packages. Their substituted Requests transport is not a real
proxy or TLS handshake.

Look up one explicitly permitted lowercase username with the official
[xdk 0.10.6](https://pypi.org/project/xdk/0.10.6/). The normal SDK call is
`client.users.get_by_username(username=...)`. There is no search, pagination,
posting, direct message, OAuth exchange or token refresh.

## Operator setup

Use only a deployment that advertises the complete `x_username_read_v1` preset:

1. Separately approve `https://api.x.com` as a proxy destination.
2. Save the real X app-only bearer token using **X app bearer** (`x_app_bearer_v1`).
   Saving it makes no provider request and grants no application access.
3. Create an application with Basic proxy authentication enabled. Save its ID and
   one-time Serverware application token.
4. Grant **X username: read** for exactly the lowercase username used below, and
   confirm that the proxy has loaded the saved policy.
5. Download the interception CA through the authenticated operator interface.
   Obtain any separate private CA for the outer proxy from a trusted operator.

The program never receives the real X token. XDK uses the public bearer dummy
`serverware-x-placeholder-v1`; Serverware replaces it after admission. An OAuth
credential, generic bearer grant or existing `x.v2` rule is not this preset.

## Run when the paired preset is available

Python 3.10+ on Linux/macOS, from this directory:

After installing the requirements, download **Private client configuration**
and the interception CA from **Proxy setup**. The shortest invocation is:

```sh
.venv/bin/python -B username.py --config /private/path/serverware-client.private.json
```

The complete download selects the exact permitted lowercase username. Relative
CA paths resolve beside the JSON file. Keep it private: it contains the scoped
Serverware application token. Expired tokens and mismatched permissions are
refused; commands, headers and bodies in the file are inert. No X token is needed
on the client. The environment-only invocation remains available:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

export SERVERWARE_PROXY_URL='https://your-proxy-host:443'
export SERVERWARE_APP_ID='your-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
export SERVERWARE_X_USERNAME='example'
# Optional, only for a private outer proxy certificate:
# export SERVERWARE_PROXY_CA_FILE='/absolute/path/proxy-ca.pem'
read -rsp 'Serverware application token: ' SERVERWARE_PROXY_TOKEN; echo
export SERVERWARE_PROXY_TOKEN

.venv/bin/python -B username.py
unset SERVERWARE_PROXY_TOKEN
```

Use the actual saved username: `[a-z0-9_]{1,15}`, without `@`. Input is not silently
lowercased. The proxy URL must be HTTPS with no credentials, path, query or
fragment. `.env.example` is a reference, not an automatically loaded file.
No provider token environment variable is used or forwarded.

For configuration/CLI checks without installing SDK dependencies, run
`python3 -B test_username.py --config-only ConfigurationTests -v`.
This uses import-only stubs and does not test SDK transport or provider access.

Output is one JSON object containing `id`, `username` and `name`. The returned
username can have the provider's capitalization but must match the selected name
case-insensitively. Missing data, error envelopes or a different username fail.
Errors print only fixed text. Do not turn on HTTP/SDK debug logging or paste
request objects into logs to diagnose failures; inspect the operator audit.

## Transport boundary

The [release source](https://github.com/xdevplatform/xdk-python/blob/1eb87aecea2d8b5ea340558fbe7426bc98e3a25b/xdk/client.py)
exposes a Requests session. The
[username method](https://github.com/xdevplatform/xdk-python/blob/1eb87aecea2d8b5ea340558fbe7426bc98e3a25b/xdk/users/client.py)
performs one GET and has no SDK timeout parameter. This example mounts a small
[documented Requests transport adapter](https://requests.readthedocs.io/en/latest/user/advanced/#transport-adapters)
on that session, setting a 5-second connect timeout, 10-second read timeout and
zero transport retries. It does not replace SDK methods, rewrite outgoing
requests or invent a timeout option. Redirects are refused before another request.

Those timeouts are not wall-clock limits. The launcher starts one isolated Python
child with a 60-second deadline and does not retry. Its environment contains only
the explicit Serverware inputs. Requests `trust_env=False` additionally prevents
ambient proxies, bypass lists, CA overrides and `.netrc` authentication. No HOME,
Python path or TLS-key-log setting is inherited or reassigned.

Both TLS connections verify certificates and hostnames:

- Inner destination TLS: a temporary client-only bundle combines certifi public
  roots and `SERVERWARE_CA_FILE`; it is removed after the SDK session closes.
- Outer proxy TLS: a separate verified context uses certifi roots and, only when
  supplied, `SERVERWARE_PROXY_CA_FILE`. The interception CA is not automatically
  trusted for this connection. This uses urllib3's documented
  [proxy TLS context](https://urllib3.readthedocs.io/en/stable/advanced-usage.html#http-and-https-proxies),
  whose [pinned implementation](https://github.com/urllib3/urllib3/blob/2.8.0/src/urllib3/connection.py)
  keeps that context separate from destination CA parameters.

Requests constructs Basic CONNECT authentication from an in-memory proxy URL
containing percent-encoded application ID/token. The URL is never printed, saved
or passed in command arguments or child environment. The separate application
token is nevertheless present in the child's environment and memory; same-user
inspection/debugging can expose it. Use a scoped revocable token on a trusted
workstation. No system or certifi trust store is modified.

## Offline verification

```bash
.venv/bin/python -B test_username.py -v
```

The 11 source-authored groups invoke actual XDK response parsing and Requests
serialization with synthetic responses at the final send boundary. They cover
the exact GET/dummy, no retries or redirects, no ambient credentials, separate
verified TLS settings, temporary public CA handling and redacted output. A socket
audit hook follows dependency imports, which may probe local IPv6 support.
The TLS policy test is configuration inspection, not a handshake.

These offline tests are not proxy/provider acceptance. The separate isolated
run above exercised the actual entrypoint through the genuine Rust gate and
both TLS legs. Its wrong-dummy, method, query and hostile-response probes were
raw protocol controls, not additional SDK cases. Real-provider checks require
separate authorization.

All six SDK/direct transport dependencies are pinned in `requirements.txt`,
including the SDK's Pydantic and requests-oauthlib dependencies. This is not a
hash-locked inventory of every transitive distribution. PyPI links the XDK release
to publishing commit `1eb87aecea2d8b5ea340558fbe7426bc98e3a25b`; its wheel SHA-256 is
`89859f02e2365a3edceb04340f1902ba5d975a3e22e469bb9bfd8bfdf557e587`.
