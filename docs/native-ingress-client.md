# Bounded native ingress client

Status: source-only, unbuilt and unexecuted. The Linux/amd64
`serverware-native-ingress-client` composes the existing startup and session
verifiers with one fixed-endpoint TLS 1.3/mTLS exchange. It verifies startup
evidence before trusting its single CA in a private connection configuration,
then verifies fresh evidence on that actual connection. It never installs a
global CA, dispatches an application operation or grants action authority.

## Exact invocation and configuration

The only arguments are the two required pairs, in either order:

```text
serverware-native-ingress-client --configuration /absolute/client.json \
  --configuration-sha256 sha256:<independently-pinned-lowercase-digest>
```

The digest notation above is a placeholder, not a usable configuration or pin.
Unknown, repeated or missing arguments fail; no environment fallback, DNS,
proxy selection or interactive secret input is provided. Independently admit
the executable, configuration and referenced pins before use. Hash equality
alone does not establish that admission.

The [closed configuration schema](../schemas/native-ingress-client.v1.schema.json)
and [parser](../data-plane/decision-gate-rs/src/native_ingress_client/config.rs)
require exactly nine fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressClient/v1` |
| `endpoint` | Canonical literal `SocketAddr`, with a nonzero port. |
| `timeoutMilliseconds` | Integer from 100 through 30000. |
| `startupEvidence` | Pinned original startup public-identity line. |
| `startupExpectations` | Pinned ingress expectations with the startup quote nonce. |
| `sessionExpectations` | Pinned ingress expectations with the raw client challenge. |
| `trustRoots` | Pinned native Nitro trust-root configuration. |
| `clientCertificate` | Pinned client certificate-chain PEM. |
| `clientPrivateKey` | Pinned client PKCS8 private-key PEM. |

Each of the six artifacts is exactly `{"path": "/absolute/path", "sha256":
"sha256:<digest>"}`. Pins are nonzero lowercase SHA-256 values. Paths are at
most 4096 bytes and use exact absolute spelling without dot/traversal components,
repeated or trailing separators. The actual loader additionally requires
canonical filesystem equality, no-follow opens of every component and a
nonempty regular file. It retains descriptors, compares bytes/hash and named/held
metadata, and rechecks the originals before publication. These local checks
are not hostile-host isolation or independent storage provenance.

Endpoint parsing excludes unspecified, multicast and broadcast addresses,
including IPv4-mapped exclusions, and IPv6 scope/flow selection. Loopback and
private literals are allowed. There is one literal TCP connection and an actual
peer-address join, not hostname resolution, redirects or fallback targets.
This is a transport configuration check, not independent proof of the remote
network location; TLS authenticates the separately expected ingress identity.

## Original bounds and private material

| Original | Maximum |
| --- | --- |
| Top-level configuration | 16 KiB |
| Startup public-identity line, including LF | 64 KiB |
| Each expectations original | 16 KiB |
| Native Nitro trust-root original | 1 MiB |
| Client certificate-chain PEM | 64 KiB; 1–8 certificates, each DER at most 16 KiB |
| Canonical PKCS8 private-key PEM | 16 KiB |

The private-key file must have no group/other permission bits, exactly one
link, and owner root or the effective caller. These are local POSIX checks,
not encryption, ACL/mount provenance, hardware custody or a guarantee of total
memory erasure. No private-key bytes, separately exposed private-key digest or
input paths are published. Do not place key material in command arguments or
examples.

## One verification and connection sequence

```text
held pinned originals + still-fresh startup verification
    -> private single-CA TLS 1.3/mTLS configuration
    -> one literal endpoint + verified server name and CertificateVerify
    -> exact GET /attestation + independently held client challenge
    -> bounded response + authenticated TLS close_notify
    -> actual-connection session verification + final input rechecks
    -> public local-only capture
```

Both expectation sets use the
[ingress expectation contract](native-ingress-verifier.md): scope, host,
instance, complete PCR inventory, module and age/skew limits must match.
Only their nonces differ, and equality of the two nonces is rejected. The
startup evidence must **still satisfy its independently pinned age limit**
(`maxAgeSeconds` is 1–300). This is an initial fresh-bootstrap exchange, not
renewal from a stale startup quote or a general long-running client.

The supplied session nonce is a raw, nonzero 32-byte caller challenge. The
client does not generate a new random challenge or maintain a durable replay
ledger. An external owner must arrange freshness, independent pinning and
one-use reservation/consumption. The
[shared session recipe](native-ingress-session.md) derives the quote nonce from
that challenge and the actual TLS exporter, and verifies exact peer leaf/CA
originals, role-3 scope and the genuine Nitro document.

The private TLS configuration has only the startup-verified CA, standard
certificate/name and handshake-signature verification, TLS 1.3 and the supplied
client certificate/key. System roots, a dangerous custom verifier, resumption
and early data are not enabled. Full handshakes, including HelloRetryRequest,
are supported. The client certificate is sent only after server CA/name and
handshake-signature verification, but before the subsequent fresh session
quote is obtained. It is not withheld until that later quote verdict.

The [HTTP exchange](../data-plane/decision-gate-rs/src/native_ingress_client/http.rs)
sends only `GET /attestation HTTP/1.1`, `Host`, the fixed challenge header and
`Connection: close`: no query, body or arbitrary dispatch headers. It requires
`200 OK`, a header block at most 8 KiB, the exact four unique response headers
(`Content-Type: application/json`, `Cache-Control: no-store`,
`Connection: close`, canonical positive `Content-Length`), and a body at most
96 KiB. Surplus bytes and bare TCP closure are denied: the exact body is accepted
only after authenticated TLS `close_notify` and EOF.

## Public result and lifetime

Success publishes one compact JSON line, at most 144 KiB, with exactly nine
fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressClientCapture/v1` |
| `resultScope` | `local-fixed-endpoint-session-and-quote-only` |
| `okForAction` | `false` |
| `configurationSha256` | Hash of the exact top-level configuration original. |
| `endpoint` | The canonical configured literal socket address. |
| `clientCertificateSha256` | Hash of the exact public client-chain PEM original, not a DER hash. |
| `sessionEvidenceBase64url` | Canonical unpadded base64url of the exact HTTP body, including its LF. |
| `startupVerification` | Existing 18-field local startup quote verdict. |
| `sessionVerification` | Existing eight-field actual-session/quote verdict. |

The total original `Instant` budget includes input loading after entry,
verification, connection, exchange and final file rechecks. Initial TCP connect
is additionally clipped to three seconds. The transport bounds individual I/O
and buffered data; these are cooperative acceptance limits, not hard real-time
guarantees. Blocking filesystem operations, kernel I/O and stdout publication
still require an outer watchdog and cleanup owner. Require a complete bounded
line and successful process exit; partial stdout or a failed flush is not a
result to accept.

The capture proves neither independent configuration/release admission nor
current witness/CAS/revocation state, KMS Recipient custody, principal/action
authorization, protected installation or complete application response proof.
It does not activate a deployed service or relax the
[production acceptance boundary](../goal.md#attestation-goal).

## Packaging and deferred validation

The [static packaging recipe](../data-plane/decision-gate-rs/Dockerfile.production)
uses the existing pinned offline Cargo/vendor/musl inputs without new
dependencies or an image entrypoint change. It requires no ELF interpreter or
dynamic `NEEDED` entries and at most 64 MiB. Target
`native-ingress-client-artifact` exports `/serverware-native-ingress-client`;
the runtime copy is `/usr/local/libexec/serverware-native-ingress-client`,
root-owned and mode 0555. No artifact has been built or independently admitted
by this source slice.

Frozen validation remains deferred: static build checks; genuine startup and
fresh-session Nitro positives over actual mTLS; wrong roots/host/key/scope,
expired or repeated challenges, altered originals, malformed HTTP, surplus
bytes, missing `close_notify`, timeout and partial-output failures. This guide
does not turn source checks into successful runtime or hardware evidence.
