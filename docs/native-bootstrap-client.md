# Fixed native bootstrap acquisition client

`serverware-native-bootstrap-client` performs one fixed HTTPS POST to
`/_serverware/native-enrollment/bootstrap`. It verifies the returned original
bootstrap signatures, quotes and session against the same held TLS connection.
Its public output is a local diagnostic capture with `okForAction: false`, not
an enrollment, installation, issuer grant or production acceptance receipt.
Existing native-ingress client v1/v2/v3 profiles are unchanged.

This is source-connected implementation, not a build, execution, deployment or
pilot result. See the [fixed server exchange](native-enrollment-bootstrap-exchange.md)
and [bootstrap evidence receiver](native-enrollment-bootstrap-verification.md)
for their separate authority boundaries.

## Explicit inputs

The binary accepts exactly two flags, once each, in either order:

```text
serverware-native-bootstrap-client --configuration /absolute/client.json --configuration-sha256 sha256:<independent-64-lowercase-hex-pin>
```

There are no environment defaults, arbitrary HTTP options, proxy settings,
redirects, alternate endpoints, reconnects, automatic retries or CONNECT mode.
The [closed configuration schema](../schemas/native-bootstrap-client.v1.schema.json)
is `serverware.nativeBootstrapClient/v1`, at most 16 KiB, with all 18 fields required:

| Field | Original or expectation |
| --- | --- |
| `apiVersion` | Exact profile above |
| `endpoint` | Canonical literal unicast IP socket address with nonzero port; no DNS selection |
| `timeoutMilliseconds` | 100–30000, measured from before configuration reads |
| `startupEvidence` | Genuine native startup evidence, at most 64 KiB |
| `startupExpectations` | Independent startup scope and nonce, at most 16 KiB |
| `sessionScope` | Independent nonce-free native session scope, at most 16 KiB |
| `trustRoots` | Independent Nitro attestation roots original, at most 1 MiB |
| `clientCertificate` | Existing bootstrap caller certificate chain PEM, at most 64 KiB |
| `clientPrivateKey` | Existing caller PKCS8 private PEM, at most 16 KiB |
| `callerIssuer` | Independent single caller-issuer PEM, at most 64 KiB / 16 KiB DER |
| `delegationAuthorizer` | Independent dedicated delegation public PEM, at most 16 KiB |
| `setupAuthorizer` | Independent separate setup public PEM, at most 16 KiB |
| `request` | Exact pinned bootstrap request original, at most 192 KiB |
| `clientChallengeBase64url` | Preselected nonzero raw32 challenge, canonical unpadded base64url |
| `expectedCallerPrincipal` | Independent exact caller identity, printable non-space ASCII, 1–256 bytes |
| `expectedTargetPrincipal` | Independent exact target identity, nonempty UTF-8, at most 1024 bytes |
| `expectedTargetNonce` | Independent target request nonce, 32–256 URL-safe characters |
| `expectedTargetRequestSha256` | Independent SHA-256 of the exact target request original |

Every artifact field is exactly `{ "path": "/absolute/original", "sha256":
"sha256:<64-lowercase-hex>" }`. Paths and nonzero pins are independently supplied;
the client does not learn trust roots, expected identities or pins from the
response. It retains no-follow opened files and rechecks names, metadata and
exact bytes through final publication. This is not hostile-host isolation or
atomic storage. The private key additionally must be an owner-only single-link
regular file owned by root or the effective caller. Temporary PEM storage is
zeroized; no claim covers every copy inside TLS/crypto libraries.

The bootstrap caller already has an independently provisioned certificate/key.
The prospective target needs its original request-first CSR/PoP, not a target
certificate or a copy of its private key. Caller and target are distinct roles.
The signed delegation and setup must already bind the selected challenge and
original target request. The client neither mints these authorizations nor
regenerates a challenge after a failure. Startup and session scope must agree;
the session challenge must differ from the startup nonce.

## One original exchange

An original process/Instant/BOOTTIME/wall-clock guard starts before argument or
configuration reads. The configured timeout only narrows that opening window;
no parsing, verification, connect, response or output step receives a fresh
allowance. Clock reversal, expiry or process change is terminal. Source-owned
startup admission completes before private-key bytes are read or a socket is
opened. Standard host-manifest or PEM-bundle diagnostics cannot substitute for
native role-3 evidence or the ordered framed-DER root inventory.

The private transport constructs its reviewed one-CA configuration from the
verified startup originals and the actual caller key/chain. It captures the
certificate chain actually selected by rustls, requires a full TLS 1.3 handshake
without resumption/early data, and compares the actual peer leaf plus CA to the
verified originals before sending the request. Its actual observed peer endpoint,
selected caller chain and exporter feed the original-only receiver; callers
cannot inject a `ClientConfig`, copied verifier result or asserted endpoint.

The request is the exact [four-field original](../schemas/native-enrollment-bootstrap-request.v1.schema.json):
canonical ASCII JSON plus one LF, containing signed delegation/setup originals
of at most 32 KiB each and the target request of at most 64 KiB. The client checks
the target request pin and sends the pinned wrapper without re-encoding it.
The response must be exactly `200 OK`, `application/json`, `Cache-Control:
no-store`, `Connection: close`, and one positive canonical `Content-Length` at
most 1 MiB. Unsupported/repeated headers, chunking, trailers, surplus plaintext
and bare TCP EOF fail closed. Successful framing requires TLS `close_notify`.
The bootstrap-only transport caps encrypted bytes at 2 MiB in each direction;
per-call I/O is also bounded. Legacy clients retain their previous caps.

The receiver independently replays both authorization roots, target CSR/PoP,
quoted installed issuer membership, role-3 session and role-5 packet signatures.
It compares all three returned packet component originals to those actually
sent, in addition to independent caller/target/nonce/request expectations.
Original certificate, quote and authorization validity narrows the same clock
through final output. Policy commitments are not a claim that every prospective
target selector, install capability or egress requirement has been completed.

## Output and failures

Exit zero emits one public JSON line, at most 1.5 MiB:
`serverware.nativeBootstrapClientCapture/v1`, scope
`local-fixed-endpoint-bootstrap-originals-only`, `okForAction: false`,
configuration/request hashes, fixed endpoint, `challengeSource:
"independently-pinned"`, exact evidence bytes in `evidenceBase64url`, and the
bounded local receiver `verification` diagnostic. The capture can contain
public identity and policy information; it contains no private-key bytes or
install token. It is not independently authenticated as a receipt.

Any error exits nonzero with fixed safe text. A server may already have durably
claimed/completed signing before an HTTP, verification or publication failure;
the outcome can therefore be unknown. Do not automatically resubmit or replace
the setup/challenge to evade that uncertainty. Cross-session recovery remains a
separate unfinished purpose. A partial line or even a complete line followed by
nonzero exit is not successful acquisition.

The invoker owns stdout and must prevent destructive redirection onto inputs,
retain the exit status, and apply an external watchdog: deadline checks reject
late results but cannot cancel already-blocked filesystem, stdout or kernel
operations. No files are installed, trust stores changed, certificates issued,
provider traffic dispatched or production gates closed by this client.
