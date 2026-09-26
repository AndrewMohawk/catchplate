# Native outer-TLS session quotation

Status: source-only, unbuilt and unexecuted. The native outer-mTLS path can
obtain a fresh original role-3 NSM quote for its **same retained ingress key**,
bound to a caller challenge and that connection's TLS exporter. This is a
session quotation producer, not automatic client bootstrap, verified CA
installation, runtime readiness, principal authorization or production admission.

## Exact request and shared challenge

The request is exactly `GET /attestation`, with no query or body. The fixed
`x-serverware-ingress-challenge` header carries canonical unpadded URL-safe
base64 of a nonzero 32-byte caller challenge. The actual TLS 1.3 handshake and
mandatory client-certificate verification precede this request. The route does
not bypass mTLS, add a public unauthenticated management listener or convert a
parent CID/source address into client identity.

The [handler](../data-plane/decision-gate-rs/src/native_ingress_attestation.rs)
rejects malformed challenge/target/body input with `400`; unavailable, busy or
failed quote/owner checks use a generic `503`. Expired request/cohort checks
withhold success. The response uses `application/json`, exact Content-Length,
`Cache-Control: no-store` and connection close; it does not open a persistent
management session or fall back to raw/development handling.

The [shared recipe](../data-plane/decision-gate-rs/src/native_ingress_challenge_v1.rs)
exports `EXPORTER_LABEL`, `CHALLENGE_HEADER` and
`derive_nonce(challenge: [u8; 32], exporter: [u8; 32])`. The actual TLS owner
obtains exactly 32 exporter bytes using:

```text
label   = "EXPORTER-Serverware-Native-Ingress-v1"
context = raw caller challenge[32]

quote nonce = SHA256("serverware/native-ingress-session-challenge/v1\0"
                     || raw challenge[32] || actual exporter[32])
```

Both all-zero inputs are rejected. Fixed lengths make the preimage unambiguous;
the header's encoded text and its digest are not substituted for raw challenge
bytes. Calling this pure helper with arrays does not prove that an exporter
came from TLS, that a challenge is fresh, or that any caller is authorized.

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
| `apiVersion` | `serverware.nativeIngressSessionEvidence/v1` |
| `evidenceScope` | `unverified-session-public-material` |
| `okForAction` | `false` |
| `clientChallengeBase64url` | Echo of the nonzero raw 32-byte caller challenge. |
| `tlsExporterBase64url` | Echo of the nonzero actual 32-byte exporter under the fixed label/context. |
| `publicIdentityBase64url` | Canonical unpadded base64url of the exact nested public-identity line, including its final LF. |

The outer body is compact JSON plus one LF, at most 96 KiB. The nested line is
at most 64 KiB and retains `serverware.nativeIngressPublicEvidence/v1`, but its
scope is explicitly `unverified-session-public-material`. Its quote nonce is
the derived session nonce above, not the startup nonce. The
[startup stdout export](native-public-identity.md) keeps its separate
`unverified-startup-public-material` scope and unchanged launch quote.

The nested original carries only the actual public certificate chain/SPKI,
client-root commitment and quote originals. It exports no private keys,
client-root DER inventory or configuration secrets. Schema conformance does
not decode/admit the nested quote or verify any cryptography. Matching public
echoes is not a substitute for independently retained client observations.

## Actual-client verification API

The crate-internal source [verifier entrypoint](../data-plane/decision-gate-rs/src/native_verifier/mod.rs)
is:

```text
verify_ingress_session(raw, expectations_raw, trust_roots_raw,
                       client: &rustls::ClientConnection)
    -> Result<Vec<u8>, String>
```

It requires the actual completed, full outer TLS 1.3 handshake, with or without
HelloRetryRequest; resumed handshakes are rejected. It derives that
connection's exporter with the fixed label and raw independently expected
challenge, derives the quote nonce, and checks both response echoes only for
equality. It verifies the fresh-scope nested original and joins its leaf/CA
exactly to the actual peer chain, alongside the independent certificate,
role-3 and Nitro checks. There is no session CLI taking an asserted exporter
or accepting the server's echo as its own expectation.

The same independently pinned expectation format has two explicit entrypoints:

| Entrypoint | Meaning of `nonceBase64url` |
| --- | --- |
| [Startup offline verifier CLI](native-ingress-verifier.md) | The original startup quote nonce. |
| `verify_ingress_session` with the actual client connection | The raw caller challenge; the function derives the quote nonce from this and the actual exporter. |

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
not blanket approval of its handshake policy. An automatic network bootstrap
client is not supplied in this slice.

The returned compact JSON is fewer than 4096 bytes, without a framing LF, and
has exactly eight fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressSessionVerification/v1` |
| `resultScope` | `local-ingress-session-and-quote-only` |
| `okForAction` | `false` |
| `evidenceSha256` | SHA-256 of the exact outer evidence original, including its LF. |
| `clientChallengeBase64url` | The independently expected raw client challenge. |
| `tlsExporterSha256` | SHA-256 of the actual 32 exported bytes. |
| `peerCertificateSha256` | SHA-256 of the actual peer leaf DER. |
| `quoteVerification` | The existing 18-field local quote-only result for the nested original. |

In `quoteVerification`, `nonceBase64url` is the derived quote nonce, while
`expectationsSha256` still hashes the exact supplied expectation original whose
nonce field contains the raw client challenge. Neither result is a transferable
session-admission or action token.

## Acceptance boundary

This slice does not supply an automatically bootstrapped client or CA installer.
The [production trust flow](../goal.md#attestation-goal) still requires independent
release/source/EIF/policy/configuration mapping, key/KMS Recipient custody,
trusted time, current off-host witness/CAS/revocation state, one-use challenge
handling and the complete required TLS/request/response proof. There is no
principal, provider-operation or action authorization claim in this response.
Verifier-mediated, agent-scoped CA installation remains a separate gate.

Local lifetime checks cannot interrupt a blocked NSM ioctl, filesystem access
or kernel I/O. Quotation can fail or expire without producing usable evidence;
cooperative bounds are not a hard syscall watchdog or proof of complete remote
termination. Independent outer watchdog and cleanup ownership remain required.
No builds, tests, runtime traffic, hardware evidence or deployment were produced
for this source slice.
