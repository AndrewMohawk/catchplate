# Native outer-TLS session quotation

Status: source-only, unbuilt and unexecuted. The native outer-mTLS path can
obtain a fresh original role-3 NSM quote for its **same retained ingress key**,
bound to a caller challenge and that connection's TLS exporter. This is a
session quotation producer, not automatic client bootstrap, verified CA
installation, runtime readiness, principal authorization or production admission.

An explicit [workload-trust v2 profile](native-workload-trust.md) now exports the
actual retained ordered client-root DER inventory under the same genuine role-3
commitment. Request it with `x-catchplate-ingress-evidence: client-trust-v2`.
Absent selector preserves the v1 wire below; unsupported or repeated selectors
fail. The [v2 outer schema](../schemas/native-ingress-session-evidence.v2.schema.json)
requires a paired v2 nested original, with `clientTrustProfile` and
`clientTrustCertificatesDerBase64url` added to `ingress`. Startup stays v1, the
quote domains and 64/96 KiB output limits are unchanged, and there is no downgrade.

The explicit [principal-v3 preflight](native-principal-preflight.md) adds actual
runtime principal authentication and a separate statement-bound nonce domain.
Its seven-field outer v3 contains the unchanged client-trust nested v2 plus the
exact authenticated statement original. A separate secret TLS exporter binds the
sent identity request without publishing header or token values. Existing v1/v2
recipes below are unchanged; neither preflight nor a quote grants CONNECT or
provider permission.

## Exact request and shared challenge

The request is exactly `GET /attestation`, with no query or body. The fixed
`x-catchplate-ingress-challenge` header carries canonical unpadded URL-safe
base64 of a nonzero 32-byte caller challenge. The actual TLS 1.3 handshake and
mandatory client-certificate verification precede this request. The route does
not bypass mTLS, add a public unauthenticated management listener or convert a
parent CID/source address into client identity.

The [handler](../data-plane/decision-gate-rs/src/native_ingress_attestation.rs)
rejects malformed challenge/target/body input with `400`; unavailable, busy or
failed quote/owner checks use a generic `503`. Expired request/cohort checks
withhold success. The ordinary one-shot response uses `application/json`, exact
Content-Length, `Cache-Control: no-store` and connection close. The explicit
single-CONNECT continuation below is separate; neither flow opens a persistent
management session or falls back to raw/development handling.

The [shared recipe](../data-plane/decision-gate-rs/src/native_ingress_challenge_v1.rs)
exports `EXPORTER_LABEL`, `CHALLENGE_HEADER` and
`derive_nonce(challenge: [u8; 32], exporter: [u8; 32])`. The actual TLS owner
obtains exactly 32 exporter bytes using:

```text
label   = "EXPORTER-Catchplate-Native-Ingress-v1"
context = raw caller challenge[32]

quote nonce = SHA256("catchplate/native-ingress-session-challenge/v1\0"
                     || raw challenge[32] || actual exporter[32])
```

Both all-zero inputs are rejected. Fixed lengths make the preimage unambiguous;
the header's encoded text and its digest are not substituted for raw challenge
bytes. Calling this pure helper with arrays does not prove that an exporter
came from TLS, that a challenge is fresh, or that any caller is authorized.

## One explicit CONNECT continuation

An opt-in proof client can request `x-catchplate-ingress-continuation: connect-v1`
and `Connection: keep-alive` on this same challenge-bearing GET. The successful
response has exactly four headers: `Content-Length`, `Connection: keep-alive`,
`Content-Type: application/json`, and `Cache-Control: no-store`, with the unchanged
evidence body. After emitting that bounded response, the native server permits
exactly one next CONNECT, without a request body or prefetched bytes, on the same
owned outer TLS connection. The quote/write phase keeps its existing two-second
bound. Continuation has a fixed 120-second transport cap measured from handler
entry, clipped to the original native runtime's remaining lifetime and retained
through CONNECT and inner I/O. Neither deadline is renewed. It does not create a
reusable attestation-management loop,
accept another arbitrary request as a continuation, or renew the serving scope.
Normal CONNECT parsing, mTLS-derived principal matching, route/policy checks and
upstream authorization still run; a quote is not permission to proxy traffic.

The [proof-client opt-in](native-proof-client.md#opt-in-ingress-attestation-before-connect)
uses a separately pinned
[catchplate.nativeProxyIngress/v1 configuration](../schemas/native-proxy-ingress.v1.schema.json).
It verifies still-fresh startup evidence before reading the outer client private
key, joins the actual outer CA/name/peer, and generates one fresh challenge.
The evidence response is framed by its exact bounded Content-Length rather
than EOF. Genuine Nitro verification and actual same-connection exporter/peer
joins must succeed **before** the client sends CONNECT through that retained
socket. A reconnect is not equivalent to this exchange, and there is no fallback
after a failed quote check.

Without this explicit continuation request, the existing one-shot response and
authenticated TLS EOF remain unchanged. Both clients still require startup
evidence inside the configured 1–300-second age limit: this initial path does
not refresh an old startup pin or implement long-running enrollment renewal.
For the default v1 request, the public evidence wire shape, caller challenge
recipe and local-only verdict below are unchanged. No durable replay reservation, full public-evidence flow,
release/KMS/witness authority, or production/action admission is added.

## Same key, new original quote

[`EnclaveRuntimeIdentityV1::quote_retained_ingress`](../data-plane/decision-gate-rs/src/enclave_runtime_identity_v1.rs)
joins the actual retained
leaf/CA, public key, complete role-3 binding, original process/deadline and
certificate validity around a real NSM call. It preserves the original ingress
key, rustls configuration and constructor quote; it does not generate a new key
or renew any lifetime. The session encoder
[`encode_native_ingress_quote_public_evidence_v1`](../data-plane/decision-gate-rs/src/enclave_public_identity_v1.rs)
retains that fresh document
and exact binding bytes in a bounded public original.

The role-3 data still commits to release/policy/configuration references,
actual CA certificate/SPKI, actual leaf SPKI and the leaf/client-root commitment.
This does not turn supplied references into independently admitted authority.
The actual TLS owner is responsible for deriving and supplying the session
nonce, not the NSM or encoding helper.

```text
actual outer TLS 1.3 + mandatory verified client certificate
    -> exact request + caller challenge
    -> same-session exporter -> fixed derived nonce
    -> retained ingress key + fresh original NSM quote
    -> unverified public response -> separate client-owned verification
```

## Closed public response

The [session evidence schema](../schemas/native-ingress-session-evidence.v1.schema.json)
has exactly six fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | `catchplate.nativeIngressSessionEvidence/v1` |
| `evidenceScope` | `unverified-session-public-material` |
| `okForAction` | `false` |
| `clientChallengeBase64url` | Echo of the nonzero raw 32-byte caller challenge. |
| `tlsExporterBase64url` | Echo of the nonzero actual 32-byte exporter under the fixed label/context. |
| `publicIdentityBase64url` | Canonical unpadded base64url of the exact nested public-identity line, including its final LF. |

The outer body is compact JSON plus one LF, at most 96 KiB. The nested line is
at most 64 KiB and retains `catchplate.nativeIngressPublicEvidence/v1`, but its
scope is explicitly `unverified-session-public-material`. Its quote nonce is
the derived session nonce above, not the startup nonce. The
[startup stdout export](native-public-identity.md) keeps its separate
`unverified-startup-public-material` scope and unchanged launch quote.

The default v1 nested original carries only the actual public certificate chain/SPKI,
client-root commitment and quote originals. It exports no private keys,
client-root DER inventory or configuration secrets. Schema conformance does
not decode/admit the nested quote or verify any cryptography. Matching public
echoes is not a substitute for independently retained client observations.

## Actual-client verification API

The crate-internal source [verifier entrypoints](../data-plane/decision-gate-rs/src/native_verifier/mod.rs)
keep the pinned-challenge v1 API and add an explicit-challenge v2 API:

```text
verify_ingress_session(raw, expectations_raw, trust_roots_raw,
                       client: &rustls::ClientConnection)
    -> Result<Vec<u8>, String>

verify_ingress_session_with_challenge(raw, scope_raw, trust_roots_raw,
                       challenge: [u8; 32], client: &rustls::ClientConnection)
    -> Result<Vec<u8>, String>
```

Both require the actual completed, full outer TLS 1.3 handshake, with or without
HelloRetryRequest; resumed handshakes are rejected. Each derives that
connection's exporter with the fixed label and raw independently expected
challenge, derives the quote nonce, and checks both response echoes only for
equality. It verifies the fresh-scope nested original and joins its leaf/CA
exactly to the actual peer chain, alongside the independent certificate,
role-3 and Nitro checks. There is no session CLI taking an asserted exporter
or accepting the server's echo as its own expectation.

Challenge ownership is explicit; the verifier does not generate randomness:

| Entrypoint | Independently held challenge input |
| --- | --- |
| [Startup offline verifier CLI](native-ingress-verifier.md) | The original startup quote nonce. |
| V1 `verify_ingress_session` | `nonceBase64url` in the pinned expectations is the raw caller challenge. |
| V2 `verify_ingress_session_with_challenge` | The explicit raw challenge is separate from pinned `catchplate.nativeIngressSessionScope/v1`, which has no nonce field. |

Both session APIs derive the quote nonce from that challenge and the actual
exporter. The nonce-free [scope schema](../schemas/native-ingress-session-scope.v1.schema.json)
retains the existing 11 static scope fields plus its own version, with no
peer-derived expectations or synthetic insertion of a nonce into the original.

The separate source-selected v2-evidence API is
`verify_ingress_session_client_trust_with_challenge(raw, scope_raw, trust_roots_raw,
challenge, client, issuer_der, client_certificate_pem)`. It takes original
evidence, independently retained scope/issuer, actual client connection and
the same configured or handshake-selected client chain—not a prior JSON verdict.
It requires paired v2 evidence, authenticates the framed DER inventory and
selected issuer, and genuinely checks the current clientAuth chain before
returning a local-only v3 verification result. Legacy APIs remain strict v1.

Startup and session evidence scopes are not interchangeable. The session API
does not rewrite the expectation original or learn a replacement challenge from
the response. Caller-owned freshness and one-use reservation remain separate.

This API does not open/connect/read a network stream. Its network-owning caller
must send and frame/read the response on this retained connection, bound the
body/deadline, retain the exact originals and reject transport/framing errors.
It must independently configure trust and client credentials; a connection
object is not evidence of their provenance. This API cannot inspect whether
the caller installed a dangerous custom certificate/handshake verifier. The
caller must use a reviewed verifier that checks `CertificateVerify`; the result
joins quote/exporter/certificate observations on the supplied connection,
not blanket approval of its handshake policy. The separate
[bounded native ingress client](native-ingress-client.md) now supplies a fixed
network owner and standard private-CA TLS configuration for this API. It still
requires independently pinned, still-fresh startup inputs and matching static
session scope. Its v1 retains the supplied challenge; its v2 makes one raw
32-byte `SystemRandom` draw before private-key/network use, aborting on failure,
zero or startup-nonce equality. It never regenerates that challenge at final
recheck. Neither version installs a CA or completes production enrollment.

The returned compact JSON is fewer than 4096 bytes, without a framing LF, and
has exactly eight fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `catchplate.nativeIngressSessionVerification/v1` or `catchplate.nativeIngressSessionVerification/v2`, matching the API. |
| `resultScope` | `local-ingress-session-and-quote-only` |
| `okForAction` | `false` |
| `evidenceSha256` | SHA-256 of the exact outer evidence original, including its LF. |
| `clientChallengeBase64url` | The actual caller-owned raw client challenge. |
| `tlsExporterSha256` | SHA-256 of the actual 32 exported bytes. |
| `peerCertificateSha256` | SHA-256 of the actual peer leaf DER. |
| `quoteVerification` | The existing 18-field local quote-only result for the nested original. |

In both nested results, `nonceBase64url` is the derived quote nonce. V1 preserves
`catchplate.nativeIngressAttestationVerification/v1` and `expectationsSha256`,
hashing the exact original that contains the raw caller challenge. V2 uses
`catchplate.nativeIngressAttestationVerification/v2` with the same 18 fields
except `sessionScopeSha256` replaces that hash field: it hashes the exact pinned
nonce-free scope, not a reconstructed expectation containing the challenge.
Neither result is a transferable session-admission or action token. The server's
six-field session evidence and nested public-identity wire versions stay v1;
the new versions distinguish client configuration and local verification only.

## Acceptance boundary

The session API itself does not supply network bootstrap or a CA installer.
The [production trust flow](../goal.md#attestation-goal) still requires independent
release/source/EIF/policy/configuration mapping, key/KMS Recipient custody,
trusted time, current off-host witness/CAS/revocation state, one-use challenge
handling and the complete required TLS/request/response proof. There is no
principal, provider-operation or action authorization claim in this response.
Verifier-mediated, agent-scoped CA installation remains a separate gate.
In-process randomness does not provide durable one-use reservation/consumption.
This GET/header protocol is still not the goal's full public-evidence flow or
its final external nonce authority, signed request/response and action gates.

Local lifetime checks cannot interrupt a blocked NSM ioctl, filesystem access
or kernel I/O. Quotation can fail or expire without producing usable evidence;
cooperative bounds are not a hard syscall watchdog or proof of complete remote
termination. Independent outer watchdog and cleanup ownership remain required.
No builds, tests, runtime traffic, hardware evidence or deployment were produced
for this source slice.
