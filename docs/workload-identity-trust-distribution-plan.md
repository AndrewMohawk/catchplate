# Workload issuer trust distribution: source and remaining boundary

The [independently authorized publisher and standard Rust startup admission](workload-identity-trust-distribution.md)
now connect the initial single-issuer profile in source. They remain unbuilt,
unexecuted and unprovisioned; this is not rotation or deployment evidence.
The local identity client and issuer still do not install workload trust.
N04 and production acceptance remain open. No deployed trust files, keys,
policies or running services were changed for this source work.

## Existing source and distinct pins

The standard Rust ingress path in `data-plane/decision-gate-rs/src/main.rs`
calls `load_proxy_ingress_config` once from `main`. It reads
`SERVERWARE_PROXY_TLS_CERT`, `SERVERWARE_PROXY_TLS_KEY` and
`SERVERWARE_PROXY_CLIENT_CA_BUNDLE` through bounded, no-follow, stable startup
file snapshots. The admitted client CA certificates populate a `RootCertStore`
and mandatory `WebPkiClientVerifier`; the server permits TLS 1.3. The retained
TLS configuration and client CA vector are immutable `Arc` values.

These identities are different and must not be substituted:

| Pin | What it identifies |
| --- | --- |
| Standard `ProxyIngressAttestation.client_trust_bundle_sha256` | Exact PEM bundle file bytes actually read at startup, including the complete configured bundle |
| Native `native-mtls-v1` trust commitment | The native owner's framed-DER trust representation; not the standard PEM file digest |
| Policy `mtls.issuerSpkiSha256` | One exact DER SubjectPublicKeyInfo digest of the genuine leaf issuer |
| Packet `caIntermediateSpkiSha256` | The separate interception CA; not workload client-issuer distribution authority |

`verified_leaf_issuer_spki_sha256` derives an issuer only from the actual leaf
signature and presented/admitted certificates, rejecting a non-unique issuer
digest. `MtlsIdentityPolicy::matches` checks every configured SAN category and
optional leaf/key/issuer digest against genuine ingress evidence. A principal's
issuer selector is a single value, not an implicit old/new trust list.

`serverware/enrollment.py:_identity_block` includes the current signed principal
`mtls` selectors in the packet. Its required enrollment pins do not separately
name the workload ingress bundle hash. The independently pinned issuer used by
the local CSR and certificate-admission client is therefore not evidence that
the proxy has loaded that issuer.

## Chosen initial implementation

The initial source connects independently authorized, immutable **public bundle
publication and explicit startup/restart admission**, using the existing
standard ingress snapshot boundary. No live trust replacement is implemented.
The publisher/admitter joins:

- The genuine configured workload issuer CA original and its DER/SPKI identity.
- The exact independently authorized PEM bundle contents and resulting digest.
- The signed principal SAN and issuer-SPKI selectors, plus the client-held
  issuer identity needed to admit the issued certificate. Client-facing loaded
  trust-pin/enrollment integration is still separate remaining work.
- The actual restarted ingress's retained bundle digest and mandatory mTLS
  profile, rather than merely the desired file or policy configuration. Actual
  restarted behavior still requires later frozen-source execution evidence.

The authorization's configuration scope binds the actual running binary rather
than a self-referential runtime-manifest digest. It also binds the loaded server
key, independently selected deployment ID, exact bundle and signed policy hash.
The source verifies the actual policy key's separation from the trust authorizer.
Its complete mTLS principal inventory is bounded to 64 canonical ASCII entries
and every issuer selector must match the one authorized CA. Original trust
authority lasts at most 24 hours, within CA validity; processing uses a separate
bounded original window. Neither policy refresh nor artifact republication
renews that original authority.

The worker's CA private key and the grant authorizer remain outside this public
distribution operation. Neither a CSR, issuance reply, CA-install capability
nor an unsigned destination path supplies trust-installation authority.

`refresh_policy_snapshot` updates the signed policy snapshot and related
lease/grant state; it does **not** rebuild or replace the live TLS configuration
or client CA vector. Replacing the bundle file and triggering policy reload is
not live ingress trust rotation.

## Transition and acceptance still required

A bundle containing both old and new issuers is not by itself a compatible
rotation: the current single issuer-SPKI selector may permit only one, and
clients retain an independently pinned issuer. Policy/client compatibility,
explicit cutover ordering, connection draining and the disposition of existing
certificates require a separately authorized transition. Do not silently widen
selectors or assume overlap support. Preserve the durable principal/nonce
issuance namespace across issuer renewal.

Rotation, revocation, retirement, rollback protection and real restart/draining
behavior remain pending. Acceptance must establish the actual loaded public
trust, correct client authentication and wrong-issuer/key/SAN/expiry rejection,
without weakening inner provider TLS or egress controls. Source plans and
attestation field definitions are not deployed or handshake evidence.
