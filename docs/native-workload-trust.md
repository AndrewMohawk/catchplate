# Native workload trust verification

Status: source-only, unbuilt and unexecuted. This is partial N04 integration,
not a provisioned identity, tested pilot or production enrollment receipt.

A workload needs to know both **which proxy it reached** and **which credential
issuers that proxy actually trusts**. An operator-supplied manifest or a matching
hash alone cannot establish the latter. The native session profile exports the
runtime's retained public trust certificates and authenticates their commitment
through a genuine fresh Nitro quote bound to the actual client TLS connection.
The client separately pins its chosen issuer; it never adopts one from the response.

```mermaid
flowchart LR
  R[Runtime-held ordered DER roots] --> Q[Fresh role-3 Nitro quote]
  T[Actual TLS exporter + client challenge] --> Q
  Q --> V[Independent original-evidence verification]
  P[Pinned issuer + exact configured client chain] --> V
  V --> C[Same-connection trust check]
```

## Explicit versions, no silent upgrades

| Surface | Existing profile | Opt-in profile |
| --- | --- | --- |
| Startup public evidence | `nativeIngressPublicEvidence/v1` | Unchanged |
| Session request | No evidence selector | `x-serverware-ingress-evidence: client-trust-v2` |
| Session outer/nested evidence | `nativeIngressSessionEvidence/v1` / `nativeIngressPublicEvidence/v1` | Both `/v2`; mixed versions fail |
| Standalone native client | `nativeIngressClient/v1` and `/v2` | [`nativeIngressClient/v3`](../schemas/native-ingress-client.v3.schema.json) |
| Proof-client pre-CONNECT admission | `nativeProxyIngress/v1` | [`nativeProxyIngress/v2`](../schemas/native-proxy-ingress.v2.schema.json) |

The v3 client configuration is exactly the existing nonce-free v2 configuration
plus a required `workloadIssuer` artifact with an independently admitted absolute
path and exact SHA-256 pin. The artifact is one canonical public certificate PEM,
at most 64 KiB, with DER at most 16 KiB. It remains held and rechecked alongside
the original startup evidence, scope, Nitro roots, client chain and private key.
Existing configurations retain their meanings and never fall back after a v3
verification failure. No private key is added to public evidence or output.

The proof-client v2 configuration likewise adds only `workloadIssuer` to its
existing pinned ingress configuration. Its transport retains the exact public
chain selected by the existing client-certificate resolver for the actual full
TLS handshake; it does not reopen a certificate path or trust a submitted chain
claim. The resolver still delegates signing/key selection to its original owner.
Genuine selected-issuer/path/session verification must finish before CONNECT on
that same socket. A missing or inconsistent selected-chain capture rejects v2.
The standalone client instead publishes a bounded local-only capture after
authenticated TLS close; it never sends CONNECT or an application operation.

The separate [principal preflight](native-principal-preflight.md) adds explicit
`nativeProxyIngress/v3` to the proof client. It uses the target's actual issued
identity and authentication headers, joins current runtime principal policy to
a new statement-bound role-3 nonce, and retains the independent result through
the same transport. It does not change the v1/v2 evidence contracts below or
the standalone client. Normal CONNECT and provider authorization still run.

## What is actually verified

The runtime encoder uses the exact ordered DER root vector held by its generated
mTLS configuration, not desired configuration, a new filesystem read or the
standard-ingress diagnostic projection. The nested v2 `ingress` adds only:

- `clientTrustProfile: "native-framed-der-v1"`;
- `clientTrustCertificatesDerBase64url`, an array of those original DERs.

The existing role-3 user data already commits to the root-set digest. Its recipe
is unchanged, including order and framing:

```text
SHA256("serverware/mutual-tls-client-trust/v1\0"
       || root_count:u32BE
       || each (root_length:u64BE || original_root_DER))
```

The independent verifier recomputes that digest and joins it to the independently
pinned session scope and authenticated original Nitro COSE/PKI/PCR/nonce binding.
The role-3 binding also includes the actual ingress leaf and CA/key identities.
The caller's challenge and actual retained TLS exporter's derived nonce, plus
the presented server chain, must match. Public echoes and local result JSON are
never accepted as substitute authority.

The selected issuer must be an exact DER member of the authenticated inventory;
its SPKI identity is derived from that same certificate. Only that independently
pinned issuer is installed in the workload-chain verifier's private trust store.
The exact configured client chain remains 1–8 certificates (64 KiB PEM total,
16 KiB DER each), including intermediate-chain support. The selected anchor may
be omitted or occur once at the tail, but cannot be the leaf. Repeated
certificates fail. Genuine WebPKI verification checks the current clientAuth path
under that selected anchor; the fixed TLS client configuration uses the same
certificate-chain original and retained key. The successful mTLS handshake
provides possession proof for that connection, not permission to perform an API
operation. Normal principal, route and request-policy checks remain separate.

## Bounds and failure behavior

The runtime root inventory retains its existing limits: 1–32 roots, 64 KiB per
root and 1 MiB aggregate. Those are **not larger public-output allowances**.
The nested evidence remains at most 64 KiB including LF; the outer response
remains at most 96 KiB. The producer checks the encoded-size budget before
allocating the exported inventory and refuses oversized output. Some otherwise
valid native root sets therefore cannot use this bounded v2 export. There is no
automatic fallback or truncation.

Unknown or repeated evidence selectors fail closed. Actual originals, process
and original deadlines are retained; there is no retry, challenge redraw or
lifetime renewal. Startup evidence must still be fresh under its pinned
1–300-second age limit. This is an initial bootstrap/session check, not a
long-running renewal protocol. The [session guide](native-ingress-session.md)
describes the retained transport, quote and continuation deadlines.

## Scope still open

The [standard single-issuer trust publisher](workload-identity-trust-distribution.md)
and this native path have different hash contracts. A canonical PEM artifact
digest, native ordered framed-DER digest and `.233` diagnostic projection are
not interchangeable. This change does not import the standard signed trust
authorization into native startup or claim trust rotation/retirement support.

Production enrollment still needs genuine production original acquisition,
authorized enrollment-signer and same-runtime/policy association, and an explicit
packet/SDK integration. The legacy Python enrollment route's development-only
attestation helper is not repaired by flattening these verified native fields
into its packet. Ordinary workload/sidecar transport, issuer lifecycle, latest
revocation/witness state and independent release admission remain separate.

Before the consolidated verification freeze, cover unchanged v1/v2 behavior,
v3 intermediate and direct chains, wrong issuer/path/key, reordered or changed
roots, paired-version rejection, duplicate selectors, output limits, stale
startup, expired identity/deadline, actual-session mismatch, selected-chain
capture and refusal before CONNECT. These are
required future checks, not reported test results. Production remains **0/6**.
