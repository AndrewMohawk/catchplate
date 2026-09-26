# Workload identity over an HTTPS proxy

Status: source-only, unbuilt and unexecuted. This applies to ordinary services,
scheduled jobs and applications as well as agents. It documents the implemented
identity/handoff boundary and narrow Python client API, not a verified production
quickstart or a universal SDK adapter. Production trust installation and
enrollment still require the
[full acceptance chain](security-review.md#production-acceptance-gates).

## Keep the two TLS layers separate

```text
application -- outer TLS + workload client certificate --> Serverware
            -- CONNECT, then inner provider-name TLS ----> Serverware
                                                         -- upstream TLS --> provider
```

| Material | Purpose | Where it belongs |
| --- | --- | --- |
| Workload certificate and private key | Authenticate the workload to Serverware. | Outer HTTPS-proxy client identity only. |
| Independently verified proxy CA | Authenticate Serverware's outer TLS name and certificate. | HTTPS-proxy trust configuration. |
| Verifier-installed interception CA | Verify the provider-name leaf inside CONNECT. | That workload's inner HTTPS trust configuration. |
| Provider API key or OAuth token | Authorize the permitted upstream operation. | Serverware's credential-use boundary, never the workload. |

The two CA roles may use the same admitted certificate in a particular deployment,
but neither role follows merely from possessing a PEM file. Do not put the
workload private key in the provider-facing TLS client-certificate setting or a
global trust store. Do not share one workload identity across unrelated services.

## Signed policy and enrollment

A certificate-only principal needs no synthetic principal header or bearer token:

```json
{
  "id": "billing-reader",
  "mtls": {
    "verifiedByTrustedIngress": true,
    "sanSpiffeIds": ["spiffe://example.invalid/services/billing-reader"]
  }
}
```

This is a principal fragment, not a complete policy or certificate issuance
request. Routes, credentials and constraints must separately authorize its
operations. Optional source, header and token selectors are additional required
conditions, not alternatives. Native VSOCK ingress has no authenticated client
IP; adding source-CIDR selectors to this principal therefore denies it.

The Rust ingress derives private certificate identity only after actual mandatory
TLS client authentication. A forwarded certificate/SPIFFE header is not evidence.
The current enrollment producer now preserves configured public selectors in
signed `identity.mtls`, rejects a plaintext proxy URL, and renders separate
outer-TLS provisioning requirements before canaries. Authenticated packet
consumers reject malformed mTLS selectors and incompatible proxy URLs before
publishing instructions, CA output or receipts. An absent field retains the
legacy handoff; a present null field is not a valid mTLS contract.

This adds no certificate issuer, private-key delivery, outer-CA admission or
proof that the client actually used those settings. The signed packet contains
requirements, not client secrets or a new production receipt assurance. Generic
`HTTPS_PROXY` and CA environment variables alone do not configure an outer mTLS
client identity. Python applications can explicitly call the API below. This is
not a drop-in `requests`, Node or provider-SDK adapter: an SDK without separate
proxy TLS settings still needs a supported integration. Do not bypass the proxy.

## Explicit Python workload client

The source [WorkloadProxyClient](../serverware_agent_trust/workload_client.py)
supports synchronous, buffered HTTP(S) calls on Linux with Python 3.11 or newer.
It uses Python's standard TLS implementation and the package's existing pinned
`cryptography==50.0.0`; no additional dependency is introduced. Use an independently
authenticated package/dependency closure, not an unauthenticated source install.

This unexecuted template uses documentation-only addresses and deliberately
invalid digest placeholders. Replace each `sha256:` placeholder with that file's
independently admitted 64-character lowercase digest, not a digest learned from
the untrusted file being checked. Provision the workload identity and admit both
CA roles before constructing the client; `PinnedFile` is not an admission result.

```python
from serverware_agent_trust.workload_client import (
    PinnedFile, WorkloadClientError, WorkloadProxyClient,
)

try:
    with WorkloadProxyClient(
        proxy_ip="192.0.2.10",             # fixed literal address; no proxy DNS
        proxy_port=8443,
        proxy_server_name="proxy.example.invalid",  # independently expected TLS name
        proxy_ca=PinnedFile(
            "/run/workload/proxy-ca.pem", "sha256:<PROXY_CA_64_HEX>"),
        client_certificate=PinnedFile(
            "/run/workload/client-chain.pem", "sha256:<CLIENT_CHAIN_64_HEX>"),
        client_private_key=PinnedFile(
            "/run/workload/private/client-key.pem", "sha256:<CLIENT_KEY_64_HEX>"),
        interception_ca=PinnedFile(
            "/run/workload/interception-ca.pem", "sha256:<INTERCEPTION_CA_64_HEX>"),
        proxy_headers={
            "X-Serverware-Enrollment-Session": "SESSION_FROM_VERIFIED_PACKET",
        },
        timeout_ms=30_000,
        max_response_bytes=1024 * 1024,
    ) as client:
        response = client.request(
            "GET", "https://api.example.invalid/approved-read",
            headers={"Accept": "application/json"},  # provider request fields
        )
        if response.phase == "connect":
            raise RuntimeError(f"Proxy tunnel denied: HTTP {response.status}")
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Request returned HTTP {response.status}; no automatic retry")
        application_bytes = response.body
except WorkloadClientError:
    raise RuntimeError("Serverware transport failed; dispatch outcome may be unknown") from None
```

Use the signed handoff's actual required proxy headers; omit `proxy_headers` if
none are required. For HTTPS, they appear on CONNECT only, while `request(headers=...)`
appears inside the provider-name TLS session. Provider headers cannot contain
`proxy-*` or `X-Serverware-Enrollment-Session`. Plain HTTP uses absolute-form HTTP
inside outer mTLS; proxy and provider header names must not overlap, even with
equal values. No provider API key or OAuth token is supplied to this client.
The example logs neither private paths/material nor response bodies; keep those
out of application diagnostics as well.

`WorkloadResponse` exposes `phase`, `status`, ordered `headers`, `body` and
`trailers`; repeated ordinary header fields remain separate tuples. A CONNECT
denial is not a provider response. Non-2xx responses, including `428`, are returned
without replay; approval and any deliberate subsequent request belong to the
separately authorized workflow. A transport error after dispatch does not prove
that the upstream operation had no effect.

Limits and lifetime are explicit:

- Methods are uppercase `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`;
  `HEAD` requires an empty request body. Request and response bodies are buffered
  and limited to 8 MiB each; `max_response_bytes` can lower the response limit.
- Construction and each request use a separate 100–30,000 ms budget. One request
  budget covers outer TLS, CONNECT, inner TLS and response framing without renewal.
  Checks cannot interrupt every blocked filesystem/OpenSSL call; a hard watchdog
  is a separate deployment requirement.
- Each request opens a fresh connection. The client retains its TLS contexts and
  belongs to its creating thread and process; it is not reentrant or usable after
  close/fork. Close it and construct a new client with newly admitted pins when
  rotating identity or trust. Python/OpenSSL key erasure is not guaranteed.
- There are no redirects, retries, direct-network fallback, ambient proxy/root
  settings, response decompression or signed response-proof verification.
  Responses require bounded Content-Length or chunked framing (or bodyless
  semantics); close-delimited bodies, chunk extensions, interim responses and
  protocol upgrades are unsupported.

This is transport integration in source, not native quote verification,
enrollment completion, CA-install authorization or a passed production gate.

## Explicit client configuration example

After independent provisioning and enrollment, a curl build with HTTPS-proxy
support separates `--proxy-cacert`, `--proxy-cert` and `--proxy-key` from the inner
`--cacert`. These option roles are defined by the
[curl manual](https://curl.se/docs/manpage.html#--proxy-cert).
The following is an unexecuted bodyless-GET template with deliberately unusable
example endpoints and paths, not automatic acceptance evidence:

```bash
curl --disable --fail-with-body --noproxy '' --proto '=https' \
  --connect-timeout 3 --max-time 30 \
  --proxy https://proxy.example.invalid:8443 \
  --proxy-cacert /workload/verified-proxy-ca.pem \
  --proxy-cert /workload/client-chain.pem \
  --proxy-key /workload/private/client-key.pem \
  --cacert /workload/verified-interception-ca.pem \
  --proxy-header 'X-Serverware-Enrollment-Session: SESSION_FROM_VERIFIED_PACKET' \
  https://api.example.invalid/approved-read
```

Use the signed packet's actual proxy, permitted read URL, enrollment header and
any additional identity headers. Preserve its egress restrictions and canaries.
No provider credential, insecure verification switch, redirect or retry is added.
The Serverware ingress requires TLS 1.3; the chosen curl/TLS build must support
that negotiation. Curl's `--proxy-tlsv1` means TLS 1.0 or newer, not a TLS 1.3
requirement; it is intentionally absent. See its
[documented semantics](https://curl.se/docs/manpage.html#--proxy-tlsv1).
Pin and verify the actual client closure in the later consolidated phase.

## Certificate expiry on reused connections

The Rust gate retains the actual verified leaf's validity interval and a fixed
monotonic expiry bound anchored at admission. New request admission and CONNECT
inner-request identity revalidation reject expired evidence, a process mismatch
or a wall clock earlier than admission. Even a principal selected through a
token cannot extend an already expired mandatory-mTLS transport identity.
The fixed expiry is not renewed when a connection is reused.

This does not revalidate intermediate certificates or revocation lists on every
request, refresh trust roots, revoke an already dispatched operation or interrupt
an in-flight response at the expiry instant. Renew the workload identity through
its independent issuer and establish a new authenticated connection. Production
time, revocation and off-host authority remain separate requirements.

## Remaining integration

The narrow Python API above is implemented in source; drop-in `requests`, Node
and provider-SDK adapters are not. An independently admitted client-identity
issuer/delivery mechanism, complete native public-evidence/enrollment join and
real allow/deny/expiry/rotation flows remain open. The native ingress and
response capture tools remain local evidence, not permission to install a CA or
start an application. No source change here passes a README production gate.
