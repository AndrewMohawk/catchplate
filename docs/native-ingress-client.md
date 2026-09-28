# Bounded native ingress client

Status: source-only, unbuilt and unexecuted. The Linux/amd64
`serverware-native-ingress-client` composes the existing startup and session
verifiers with one fixed-endpoint TLS 1.3/mTLS exchange. It verifies startup
evidence before trusting its single CA in a private connection configuration,
then verifies fresh evidence on that actual connection. It never installs a
global CA, dispatches an application operation or grants action authority.

The additive [v3 workload-trust profile](native-workload-trust.md) retains the
nonce-free v2 inputs and adds one independently pinned `workloadIssuer` public
PEM artifact. It explicitly requests v2 session evidence, authenticates the
actual runtime's ordered DER trust inventory, and verifies the same configured
client chain under only the selected issuer. Existing v1/v2 remain unchanged.
See the [closed v3 schema](../schemas/native-ingress-client.v3.schema.json) for
the tenth field; the issuer is at most 64 KiB PEM / 16 KiB DER. Its local capture
and verification use distinct v3 result versions with `okForAction=false`.
The existing bounds and sequence below apply, with this extra held original and
same-session trust verification before publication, not a new CONNECT capability.

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

The closed [v1](../schemas/native-ingress-client.v1.schema.json) and
[v2](../schemas/native-ingress-client.v2.schema.json) schemas and
[parser](../data-plane/decision-gate-rs/src/native_ingress_client/config.rs)
each require exactly nine fields; the version selects one session-input form:

| Field | Contract |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressClient/v1` or `serverware.nativeIngressClient/v2`. |
| `endpoint` | Canonical literal `SocketAddr`, with a nonzero port. |
| `timeoutMilliseconds` | Integer from 100 through 30000. |
| `startupEvidence` | Pinned original startup public-identity line. |
| `startupExpectations` | Pinned ingress expectations with the startup quote nonce. |
| `sessionExpectations` (v1 only) / `sessionScope` (v2 only) | Pinned caller-challenge expectations / pinned nonce-free scope. |
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

V1 remains unchanged: `sessionExpectations` contains the caller's challenge.
V2 instead pins [session scope v1](../schemas/native-ingress-session-scope.v1.schema.json),
an exact 12-field object: `apiVersion: serverware.nativeIngressSessionScope/v1`,
`releaseRecordSha256`, `policyHash`, `configurationSha256`,
`clientTrustBundleSha256`, `expectedPcrs`, `expectedEif`, `expectedModuleId`,
`maxAgeSeconds`, `futureSkewSeconds`, `ingressHost` and `serverInstanceId`.
It has no `nonceBase64url`. Every static scope value must equal the startup
expectations; neither the server nor randomness supplies replacement scope.

To migrate, explicitly select the v2 configuration version, replace the
`sessionExpectations` artifact with a separately pinned `sessionScope` original,
and repin the changed configuration. Mixed fields and a `challengeSource` input
are rejected. Existing v1 files and result meanings do not change implicitly.

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
| Each expectations or session-scope original | 16 KiB |
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
held pinned public originals
    -> v1: retain supplied challenge / v2: generate one challenge
    -> still-fresh startup verification against exact pinned scope
    -> private single-CA TLS 1.3/mTLS configuration
    -> one literal endpoint + verified server name and CertificateVerify
    -> exact GET /attestation + same retained client challenge
    -> bounded response + authenticated TLS close_notify
    -> actual-connection session verification + final input rechecks
    -> public local-only capture
```

Both versions preserve the [ingress expectation contract](native-ingress-verifier.md):
scope, host, instance, complete PCR inventory, module and age/skew limits must
match. The session challenge must differ from the startup nonce. Startup
evidence must **still satisfy its independently pinned age limit**
(`maxAgeSeconds` is 1–300). This is an initial fresh-bootstrap exchange, not
renewal from a stale startup quote or a general long-running client.

V1 retains its independently supplied nonzero raw 32-byte challenge. V2 calls
the existing locked `ring::rand::SystemRandom` exactly once for 32 bytes after
loading the pinned public originals and before loading the client private key
or contacting the network. RNG failure, all-zero output or equality with the
startup nonce aborts: there is no retry or regeneration, including at the final
startup recheck. The same owned challenge drives the request and verification;
the pinned scope is never rewritten to pretend it contained that challenge.

Neither version supplies a durable one-use reservation or consumption ledger.
V2's CSPRNG supplies a fresh local challenge, not independent final nonce
authority; required off-host replay/finalization gates remain separate. The
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

Success publishes one compact JSON line, at most 144 KiB. V1 has exactly nine
fields; v2 retains them and adds `challengeSource: "client-csprng"` (ten fields):

| Field | Meaning |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressClientCapture/v1` or `serverware.nativeIngressClientCapture/v2`, matching configuration. |
| `resultScope` | `local-fixed-endpoint-session-and-quote-only` |
| `okForAction` | `false` |
| `configurationSha256` | Hash of the exact top-level configuration original. |
| `endpoint` | The canonical configured literal socket address. |
| `clientCertificateSha256` | Hash of the exact public client-chain PEM original, not a DER hash. |
| `sessionEvidenceBase64url` | Canonical unpadded base64url of the exact HTTP body, including its LF. |
| `startupVerification` | Unchanged 18-field v1 local startup quote verdict. |
| `sessionVerification` | Eight-field session verdict v1 or v2, matching configuration. |

V2 uses `serverware.nativeIngressSessionVerification/v2`; its nested
`quoteVerification` uses `serverware.nativeIngressAttestationVerification/v2`
and replaces only `expectationsSha256` with `sessionScopeSha256`, the hash of
the exact pinned nonce-free scope original. The actual challenge appears in
the session verdict and session evidence, not inside that scope hash. V1's
capture, session verdict and quote verdict remain unchanged.
`challengeSource` describes the actual client's local branch; this unsigned
capture does not independently authenticate RNG authorship or confer authority.

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
Both versions still use the narrow role-3 `GET /attestation`/challenge-header
protocol, not the full goal's public-evidence request/response and final nonce
authority flow. Neither activates a deployed service or relaxes the
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
