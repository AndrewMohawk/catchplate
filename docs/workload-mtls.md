# Workload identity over an HTTPS proxy

Status: source-only, unbuilt and unexecuted. This applies to ordinary services,
scheduled jobs and applications as well as agents. It documents the implemented
identity/handoff boundary, not a working production quickstart or a universal SDK
adapter. Production trust installation and enrollment still require the
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
client identity. An SDK without separate proxy TLS settings must stay stopped
until a supported workload-scoped connector is provided; do not bypass the proxy.

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

An independently admitted client-identity issuer/delivery mechanism, supported
ordinary-SDK outer-mTLS adapter, complete native public-evidence/enrollment join
and real allow/deny/expiry/rotation flows remain open. The native ingress and
response capture tools remain local evidence, not permission to install a CA or
start an application. No source change here passes a README production gate.
