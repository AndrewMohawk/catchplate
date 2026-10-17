# Workload identity over an HTTPS proxy

Status: source-only, unbuilt and unexecuted. This applies to ordinary services,
scheduled jobs and applications as well as agents. It documents the implemented
identity/handoff boundary and narrow Python client API, not a verified production
quickstart or a universal SDK adapter. Production trust installation and
enrollment still require the
[full acceptance chain](security-review.md#production-acceptance-gates).

## Keep the two TLS layers separate

```text
application -- outer TLS + workload client certificate --> Catchplate
            -- CONNECT, then inner provider-name TLS ----> Catchplate
                                                         -- upstream TLS --> provider
```

| Material | Purpose | Where it belongs |
| --- | --- | --- |
| Workload certificate and private key | Authenticate the workload to Catchplate. | Outer HTTPS-proxy client identity only. |
| Independently verified proxy CA | Authenticate Catchplate's outer TLS name and certificate. | HTTPS-proxy trust configuration. |
| Verifier-installed interception CA | Verify the provider-name leaf inside CONNECT. | That workload's inner HTTPS trust configuration. |
| Provider API key or OAuth token | Authorize the permitted upstream operation. | Catchplate's credential-use boundary, never the workload. |

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

The [persistent native workload sidecar](native-workload-sidecar.md) is the
separate source implementation for ordinary HTTPS libraries without outer-proxy
mTLS support. It accepts local authenticated CONNECT in an explicitly admitted
workload network namespace and owns each actual native mTLS connection. The
application still needs its scoped local token and independently installed
inner interception CA. This sidecar is not yet compiled or deployed; it does
not silently change the Python client's existing identity or retry behavior.

## Explicit Python workload client

The source [WorkloadProxyClient](../catchplate_agent_trust/workload_client.py)
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
from catchplate_agent_trust.workload_client import (
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
            "X-Catchplate-Enrollment-Session": "SESSION_FROM_VERIFIED_PACKET",
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
    raise RuntimeError("Catchplate transport failed; dispatch outcome may be unknown") from None
```

Use the signed handoff's actual required proxy headers; omit `proxy_headers` if
none are required. For HTTPS, they appear on CONNECT only, while `request(headers=...)`
appears inside the provider-name TLS session. Provider headers cannot contain
`proxy-*` or `X-Catchplate-Enrollment-Session`. Plain HTTP uses absolute-form HTTP
inside outer mTLS; proxy and provider header names must not overlap, even with
equal values in the explicit constructor. Signed-handoff mode below handles
the packet's equal duplicated identity headers separately. No provider API key
or OAuth token is supplied to this client.
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

## Construct from an authenticated signed handoff

`WorkloadProxyClient.from_signed_handoff(...)` derives settings from the pinned
original signed enrollment packet. It verifies that packet against a separately
pinned, independently admitted signer public-key PEM and the caller's expected
principal and enrollment nonce. It rejects a `verificationReceipt`-decorated
packet: a copied receipt flag is not a substitute for original signature
verification. Packet and signer originals are bounded to 8 MiB and 64 KiB,
respectively, and rechecked before construction returns.

This shorter, unexecuted template reuses the four `PinnedFile` values from the
preceding example as `proxy_ca_pin`, `client_certificate_pin`,
`client_private_key_pin` and `interception_ca_pin`. The new digest placeholders
are deliberately unusable. The nonce and any proxy authorization must come from
their independent enrollment/provisioning workflow, not from untrusted packet
fields or this example:

```python
with WorkloadProxyClient.from_signed_handoff(
    packet=PinnedFile(
        "/run/workload/enrollment.json", "sha256:<PACKET_64_HEX>"),
    packet_signing_key=PinnedFile(
        "/run/workload/enrollment-signer.pem", "sha256:<SIGNER_PEM_64_HEX>"),
    expected_principal="billing-reader",
    expected_nonce=independently_held_enrollment_nonce,
    proxy_ip="192.0.2.10",  # independently selected literal transport address
    proxy_ca=proxy_ca_pin,
    client_certificate=client_certificate_pin,
    client_private_key=client_private_key_pin,
    interception_ca=interception_ca_pin,
    proxy_authorization=provisioned_proxy_authorization,  # None when not required
) as client:
    response = client.request("GET", independently_authorized_read_url)
```

There are no caller overrides for proxy TLS name, port or proxy headers in this
mode. Required provider headers are injected from the authenticated packet;
request headers cannot change their values. HTTPS preserves the separate
CONNECT/provider header copies. Plain HTTP emits equal signed copies once in
its single absolute-form request head; unrelated caller-created overlaps still
fail. A required proxy authorization is separately provisioned, not supplied as
a provider credential or recovered from the packet.

Before reading the private key, the factory checks the actual retained client
chain against the signed mTLS selectors: every configured selector family must
match, with any-match semantics within each SAN list. Leaf-certificate and SPKI
hashes cover exact original DER, not PEM or reconstructed keys. The actual leaf
must currently be valid. DNS/SPIFFE/URI matching is bounded; the local URI profile
is a conservative canonical ASCII subset and rejects ambiguous normalization
and `file:` URI SANs. An issuer selector requires a genuine leaf signature and
one unique matching issuer SPKI from the supplied client chain, never either
unrelated proxy/interception trust store. These are local compatibility checks,
not proof that trusted ingress authenticated the workload or admitted its issuer.

Signed mode also requires exactly one interception-CA certificate, whose original
SPKI matches both signed CA pins; additional trust anchors are rejected. Outer
proxy trust remains a separately admitted role. Matching a packet signature,
certificate or CA pin is not fresh attestation, enrollment completion or
permission to install a CA globally.

Packet, proxy-token and optional install-session expiry cap one retained
nonrenewing monotonic lifetime, with wall time forbidden from moving before
admission. Each request's budget is clipped to that lifetime. Expiry requires
renewed enrollment/provisioning and a new client; it does not authorize retries
or retract already dispatched effects. The factory does not run packet scripts,
firewall changes or canaries, and does not turn listed URLs into local route
authorization. The gate still enforces its current policy; independent enrollment,
egress, attestation and response-proof acceptance remain separate.

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
  --proxy-header 'X-Catchplate-Enrollment-Session: SESSION_FROM_VERIFIED_PACKET' \
  https://api.example.invalid/approved-read
```

Use the signed packet's actual proxy, permitted read URL, enrollment header and
any additional identity headers. Preserve its egress restrictions and canaries.
No provider credential, insecure verification switch, redirect or retry is added.
The Catchplate ingress requires TLS 1.3; the chosen curl/TLS build must support
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
