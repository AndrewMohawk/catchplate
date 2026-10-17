# Native response capture profile

Status: source-only, unbuilt and unexecuted. The proof client has an explicit
native capture profile, separate from its legacy vendor-verifier profile. It
combines actual client-side HTTP/TLS capture checks with a separately configured
verifier of the original signed statement and fresh native quote. It does not
classify the result as production, establish current witness state, authorize
an action or activate native serving.

## Independently configured verifier and session

For the protected Setup empty-body GET, use the [fixed operator caller](native-pilot-request-collection.md)
to consume the exact portal bundle and retain/export its capture with a local
durable no-rerun fence. It invokes this existing native path, not another proof
format. Its optional `--expected-collector-key-id` is checked against the actual
admitted collector key before contact; `--native-capture-max-bytes` (1–524288)
checks the full signed output bytes before publication. Both flags require
explicit native verification and do not widen an old profile or grant a request.

The [client source](../data-plane/decision-gate-rs/src/bin/catchplate-proof-client.rs)
requires these six options together:

```text
--native-verifier /approved/native-verifier
--native-verifier-sha256 sha256:<exact-executable-digest>
--native-expectations /approved/response-expectations.json
--native-expectations-sha256 sha256:<exact-expectation-original-digest>
--native-trust-roots /approved/native-trust-roots.json
--native-trust-roots-sha256 sha256:<exact-trust-original-digest>
```

Paths and digests are independently supplied configuration, not values learned
from the server response. The executable profile is a static x86-64 ELF with no
interpreter or dynamic dependency. The Python
[response verifier](../scripts/verify_native_response_attestation.py) is not
itself an executable admitted by this profile. The
[standalone Rust verifier and static packaging recipe](native-verifier.md) now
supply the source producer for that artifact, with an explicit fixed native
profile rather than blanket Python parity. A built, independently admitted
executable, its digest and complete source/dependency closure remain
prerequisites; the source recipe has not been built or runtime-validated. There
is no shell/interpreter fallback.
The [invocation adapter](../data-plane/decision-gate-rs/src/proof_client_native_verifier_v1.rs)
bounds the executable original to 64 MiB, expectations to 16 KiB and trust roots
to 1 MiB; verifier input/result caps remain 512 KiB/4 KiB.

The expectation/trust formats and their genuine Nitro verification are described
in the [proof-custody guide](enclave-proof-custody.md#separate-response-verifier-and-explicit-client-profile).
The client requires explicit `--nonce` with exactly 32 raw bytes in unpadded
base64url, equal to the independently pinned expectation's original client
nonce before network work. It does not replace the pin using a returned quote.
Freshness and one-use reservation remain caller responsibilities; observation
nonces also retain their existing expiry-prefix checks.

Native mode requires explicit `--expected-server-instance-id` and
`--expected-principal-id`, and authenticated outer mTLS proxy transport through
`--proxy-ca`, `--proxy-client-cert` and `--proxy-client-key`. Existing inner
`--ca`, pinned `--control-plane-response-key`, `--collector-key`, HTTPS `--url`,
`--proxy` and agent-identity proxy-header requirements remain. Native options
cannot be combined with `--verifier-key` or `--proxy-raw-development`.
Native `--ca` must contain exactly one certificate whose DER and SPKI hashes
match the independently pinned native expectations, joining the actual inner
TLS trust anchor to the quoted runtime CA rather than trusting an unrelated
locally supplied CA bundle. Native inner TLS is explicitly TLS 1.3-only. The
actual control-plane response key must also match the independently pinned
key ID; metadata equality does not replace its signature checks.

Buffered collection remains the default. `--stream --body-out <path>` selects
streaming; `--observation --body-out <path>` selects observation, with its
existing method/request-body controls. Those modes remain mutually exclusive.
Native input admission rejects an empty `--request-body` file; omit that flag
for an empty request body.
No environment switch silently selects native evidence or falls back to legacy
verification when native verification fails.

### Explicit native principal response profile

The [native-principal response profile](native-response-principal-profiles.md)
adds independently pinned expectations v2 with the fixed
`statementProfile=catchplate.nativeResponseStatements/v1`. It selects only the
new native statement families, runtime-proof v2, verifier verdict v2 and capture
v2. Expectations v1 still requires the old statement families and cannot accept
these new versions. Neither a server response nor a successful ingress preflight
can change the independently selected response profile.

Only principal text changes to the native 1024-byte UTF-8 bound. All actual
request/response, signature, control-plane receipt, TLS-exporter and original
Nitro checks remain, as do the existing bounds on other identifiers. For wider
principal arguments the separately pinned ingress v3 is also required. The
[explicit native credential-lease path](native-credential-leases.md) separately
connects the actual quoted recipient, broker authority and encrypted material
under matching native profiles. Preflight and response compatibility never grant
credential access; the original policy, one-use issuance and retained lifecycle
bounds still apply. Legacy lease contracts are unchanged. This source integration
is not executed credentialed onboarding or production acceptance.

## Retained native proxy connection

Native mode now requires `--proxy` to name a literal, concrete unicast IP and
nonzero port. Private/loopback addresses are permitted; DNS, unspecified,
multicast, broadcast and IPv6 scope selection are not. Use
`--proxy-server-name` for an independently expected DNS certificate name when
the connection address is an IP. Typed URL host handling keeps one IPv6 bracket
pair in the socket address and passes the unbracketed IP to TLS. Non-native
vendor/development connection selection is otherwise unchanged.

The native session constructs its actual outer TLS configuration from the
admitted, retained CA/client-certificate/private-key bytes, rather than reopening
those paths later to create a different configuration. It retains ordinary
WebPKI name and handshake-signature verification, mandatory client identity,
TLS 1.3, disabled resumption/early data and the original input rechecks. This
does not by itself attest the outer proxy CA. The explicit ingress option below
adds a separate genuine startup and same-connection quote check before CONNECT;
it is not enabled implicitly by native response verification.

The [native proxy transport](../data-plane/decision-gate-rs/src/proof_client_native_transport_v1.rs)
uses one fixed-address connect, capped at the lesser of three seconds and the
session's remaining original deadline. It verifies the connected peer address,
requires a full TLS 1.3 handshake and retains the creating process identity.
The shared TCP owner recomputes timeouts before every actual call and rejects
late results; each call is at most 16 KiB, with at most 2 GiB of encrypted bytes
per direction over the complete capture. The wire limit includes both TLS
layers and HTTP framing; existing, smaller application-body limits still apply.
Pathological framing overhead may exhaust the wire bound before the body bound.
The outer TLS application-output buffer is capped at 64 KiB.

Cheap process/deadline checks also bracket inner plaintext reads/writes for
buffered, streaming and observation capture. Thus already-buffered inner TLS
data does not bypass the original acceptance deadline. These checks do not
re-read input files per byte. No raw socket/descriptor accessor, resolver,
alternate-address retry or new forwarding capability is exported.

## Opt-in ingress attestation before CONNECT

Only the native verifier mode accepts this additional pair, and both options
are required together:

```text
--native-ingress-configuration /approved/native-proxy-ingress.json
--native-ingress-configuration-sha256 sha256:<exact-configuration-original-digest>
```

The [closed configuration schema](../schemas/native-proxy-ingress.v1.schema.json)
has exactly five fields: `apiVersion=catchplate.nativeProxyIngress/v1`,
`startupEvidence`, `startupExpectations`, `sessionScope`, and `trustRoots`.
Each artifact is exactly `{path, sha256}`: an independently supplied canonical
absolute path and nonzero lowercase SHA-256 pin, not a value learned from the
server. The configuration is at most 16 KiB; startup evidence is at most 64 KiB,
each expectation/scope original at most 16 KiB, and trust roots at most 1 MiB.
The existing proxy endpoint, TLS client files and original capture deadline
remain authoritative; this configuration adds no endpoint, private key or
timeout override.

Before reading the outer client private key or opening a connection, the client
verifies the original startup Nitro evidence against the pinned expectations and
roots. Every static field in the nonce-free session scope must match startup.
The retained ingress and response-verifier expectations must also agree on
release, policy, configuration, complete PCR inventory, EIF, module, maximum age
and future skew; the independently expected server instance and exact trust-root
original digest must match. Equivalent-looking files cannot substitute for
those original-byte joins.
The actual outer CA and expected server name are joined to that startup, and the
completed full TLS 1.3 handshake must present the exact expected leaf/CA chain.
Ordinary WebPKI/name verification and mandatory client authentication remain.

The client draws one fresh nonzero 32-byte CSPRNG challenge, distinct from the
startup nonce, and retains it without regeneration. It sends `GET /attestation`
with `x-catchplate-ingress-challenge`, the explicit
`x-catchplate-ingress-continuation: connect-v1` header and
`Connection: keep-alive`. The
[retained ingress owner](../data-plane/decision-gate-rs/src/proof_client_native_ingress_v1.rs)
consumes the exact evidence response, bounded to 96 KiB,
verifies the genuine Nitro quote and challenge/exporter/peer joins using that
actual connection, and only then sends CONNECT through the **same owned TLS
socket**. It does not treat an echoed exporter or copied successful verdict as
its observation. Any failure ends this path without reconnecting or falling
back to an unattested CONNECT. Normal CONNECT, policy, principal, response-proof
and publication checks are unchanged.
The server keeps its two-second quote/write bound and caps the opted-in
connection at 120 seconds from handler entry, additionally clipped to native
runtime lifetime; the client's original capture deadline can be shorter.

This is an **initial freshness** path: the pinned startup quote must still be
within its configured 1–300-second maximum age. A fresh session quote neither
renews stale startup inputs nor supplies long-running enrollment renewal. Held
originals and startup freshness are rechecked through final publication. The
standalone one-shot ingress GET/EOF flow remains unchanged; see the
[session protocol and continuation boundary](native-ingress-session.md#one-explicit-connect-continuation).
The option does not supply the goal's full public-evidence protocol, durable
replay consumption, current release/KMS/witness authority, or production/action
admission. Native capture retains `environment=native-unadmitted` and
`okForAction=false`.

## Actual capture before signed publication

The native entrypoints `verify_native_runtime_proof`,
`verify_native_stream_runtime_proof` and
`verify_native_observation_runtime_proof` reuse the actual capture cores. They
retain server signature and typed-statement checks, actual client nonce and
request/principal joins, policy and pinned control-plane receipt checks, age,
the exporter from the same TLS session, peer SPIFFE/leaf identity, and the
captured response headers/body/counts. Streaming retains its framing, trailers
and normal-completion checks; observation retains its request/emitted-response
commitments and limited upstream/delivery claims. The uniform native
`server_statement` name does not change a statement family's signed bytes or
substitute for these checks.
The [native session](../data-plane/decision-gate-rs/src/proof_client_native_session_v1.rs)
also rejoins the bounded original header/trailer envelope to canonical unpadded
base64url, exact canonical JSON bytes and the declared digest. It does not accept
a parsed object as a substitute for those original-byte checks.

```text
held caller nonce/configuration + actual HTTP/TLS response
    -> shared full capture checks
    -> pinned native signature/quote verifier
    -> collector signs distinct native artifact
    -> verified output publication
```

The separate native verifier must succeed before collector signing or output
publication. It does not supply the capture checks itself. Conversely, matching
HTTP bytes or a valid server signature does not substitute for verification of
the original native quote. The legacy production/vendor path keeps its own
signed-verifier and revocation assertions; native capture invents neither.

## Distinct artifact and file custody

The [artifact schema](../schemas/native-response-capture.v1.schema.json) is
`catchplate.nativeResponseCapture/v1`, kind
`CatchplateNativeResponseCapture`. Its fixed labels are
`resultScope=local-capture-and-native-quote-only`, `okForAction=false` and
`environment=native-unadmitted`. `captureMode` is `buffered`, `streaming` or
`observation`; `external_capture`, the complete native `runtime_proof` object and
`native_verification` remain distinct fields. `collector_signature` signs the
canonical entire artifact excluding that signature field, not merely a copied
verifier verdict, and includes the corresponding `capture_digest`. Schema
conformance alone establishes no cryptographic or hardware admission. This
collector statement is evidence of its scoped capture, not independent
production/release approval.

Native output admission protects both `--out` and `--body-out` from aliasing
the verifier executable, expectation/trust originals, CA/key inputs, proxy TLS
files or request body. Configured inputs are retained and rechecked before
publication. The native buffered path uses a retained resolved target in an
owner-owned exact-mode 0700 directory and publishes without replacement.
Streaming/observation retain their private staging and verified body/proof
publication, including a shared owner-owned exact-mode 0700 output directory,
distinct destinations, retained directory descriptors, publication lock,
body size/hash revalidation and no-replacement proof publication. These local
filesystem controls trust same-UID writers; they are not hostile-host isolation
or a transactional pair visible atomically to every reader.

## Acceptance deadline is not a hard watchdog

The native session starts its acceptance deadline before admitting inputs and
before network work, and rechecks retained inputs/deadline before signing and
publication. Native socket and inner-plaintext operations now share that original
nonrenewing deadline, with no native DNS call. This is still not a hard watchdog:
blocking filesystem, kernel, process-execution or reap operations can return
late, and already performed side effects cannot be undone by a post-check. An
outer watchdog that owns cleanup remains required; this source profile makes
no hard real-time completion guarantee.

The native PKI profile supplies no vendor-CRL revocation proof. Independent
configuration and release/PCR mapping, trust currentness, trusted time, nonce
reservation, latest off-host witness/rollback custody, executable packaging and
full native deployment remain separate requirements. Source-level capture
acceptance is not a production-readiness or runtime-success claim.

## Enrollment is a separate integration boundary

The additive [native workload-trust profile](native-workload-trust.md) selects
`catchplate.nativeProxyIngress/v2` and a separately pinned `workloadIssuer`.
It authenticates actual held runtime trust roots and verifies the client chain
selected by the actual outer TLS handshake under only that issuer **before
CONNECT on the same socket**. V1 remains unchanged; v2 cannot silently fall back.
This closes a source-level initial session/issuer join, not the enrollment
boundary below or long-running renewal, rotation, revocation and witness proof.

Neither this signed response-capture profile nor the separate
[native ingress capture](native-ingress-client.md) replaces a production
enrollment receipt. Existing enrollment additionally binds a signed packet,
assignment, install-session nonce, trust profile, independently signed launcher
egress evidence and an authorized receipt signer. Its legacy query-nonce
attestation transport is not interchangeable with native challenge-header mTLS.
Ordinary application/service handoff still needs an explicit supported outer
mTLS transport and client-identity provisioning; proxy/CA environment variables
alone do not provide that configuration. The native captures remain supporting
local evidence, not permission to install trust or start a workload.
