# Native principal preflight verification

The explicit `principal-v3` receiver joins a fresh role-3 Nitro quote to the
actual outer TLS connection and a source-constructed principal-authentication
statement. This is source-only implementation, not a runtime acceptance result.
The existing session v1/v2 profiles remain closed and unchanged; neither accepts
a principal field or silently selects this new profile.

## Exact originals and independent expectations

`nativeIngressSessionEvidence/v3` has exactly the six existing outer fields plus
`principalPreflightBase64url`, with the same 96 KiB including final LF ceiling.
Its nested public identity remains `nativeIngressPublicEvidence/v2`, admitting
the exact held client-root inventory and server leaf/CA originals. The statement
is at most 4096 bytes of sorted compact UTF-8 JSON without LF, with exactly:

- `apiVersion: catchplate.nativePrincipalPreflight/v1` and `principalId`;
- `identityPolicySha256`, `policySha256`, `clientCertificateSha256`,
  `clientSpkiSha256`, `requestBindingSha256`;
- `sourceAddress`, a canonical IP string or null.

The receiver independently expects the principal and identity-policy digest and
joins the statement's policy hash to its pinned session scope. It genuinely
verifies the selected client chain under only the independently pinned issuer,
requires that issuer's exact membership in authenticated native roots, and
matches the statement's client leaf DER/SPKI hashes to the actual selected chain.
The source-address field is quote-authenticated server evidence, not a
caller-selected source address or a separate egress/namespace permission.

The exact sent preflight request is canonical `method`, `target`, `httpVersion`
and lower-case `headers`, at most 32 KiB. The shared recipe permits only the
fixed GET `/attestation` HTTP/1.1 profile and bounded original headers. A separate
secret TLS exporter, with the raw challenge as context, keys its HMAC-SHA256.
Only that request commitment is public: raw headers/tokens and the secret
exporter are never emitted. The receiver recomputes the HMAC over the actual
sent original, not a response-supplied request description. The new nonce domain
binds the original statement to the actual normal exporter and challenge, and
the receiver verifies that nonce inside the genuine Nitro document. An unsigned
principal or successful JSON diagnostic cannot satisfy these checks.

## Retained owner and caller boundary

`verify_ingress_principal_preflight` receives only original evidence/scope/roots,
challenge, actual `ClientConnection`, independent issuer DER, actual selected
client-chain PEM, expected principal/identity-policy digest, sent request original
and the caller's inherited `Instant` deadline. It returns a private-field,
non-Clone `PrincipalSession`, never a serialized verdict or generic permission.
Principal expectations support the native UTF-8 byte bound of 1024 without
silently narrowing the native identity profile.

`PrincipalSession::check(actual_client, selected_client_pem)` remains on that
transport through CONNECT and output. It rechecks the full TLS 1.3 handshake,
exact peer pair, selected client PEM, normal exporter and private request-exporter
association. Its original wall/BOOTTIME/PID and inherited monotonic deadline are
sticky on failure. The deadline can only narrow to the already verified server,
client/issuer/intermediate, selected Nitro signing-chain and quote-age bounds;
no new timeout or certificate/quote lifetime is minted by checking.

A raw `ClientConnection` cannot reveal whether its configuration used an unsafe
custom verifier. The owning proof-client transport must therefore retain the
reviewed configuration, actual certificate resolver/selected chain and original
inputs; the low-level verifier is not a substitute for that provenance. It must
check this owner before and after I/O and still let the normal CONNECT/request
path perform its own current authentication and route checks.

Preflight proves the exact authenticated principal decision under the quoted
policy at that session, not future policy freshness, CONNECT authorization,
upstream route/credential permission, installation, firewall/Kubernetes ownership,
canary authority or completed enrollment. Independent signed setup/allowlists and
any separately authorized canary remain mandatory; incoming-client and upstream
route CIDRs never become proxy-egress permission. No retry, reconnection or
success-DTO fallback follows from failure or expiry. Blocking kernel I/O still
needs an external watchdog.
