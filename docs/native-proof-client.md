# Native response capture profile

Status: source-only, unbuilt and unexecuted. The proof client has an explicit
native capture profile, separate from its legacy vendor-verifier profile. It
combines actual client-side HTTP/TLS capture checks with a separately configured
verifier of the original signed statement and fresh native quote. It does not
classify the result as production, establish current witness state, authorize
an action or activate native serving.

## Independently configured verifier and session

The [client source](../data-plane/decision-gate-rs/src/bin/serverware-proof-client.rs)
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
`serverware.nativeResponseCapture/v1`, kind
`ServerwareNativeResponseCapture`. Its fixed labels are
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
publication. These checks reject late evidence; they do not make blocking filesystem,
DNS, socket, process-execution or reap operations interruptible, nor turn socket
I/O timeouts into a hard total-time guarantee against stalled progress. An outer
watchdog that owns cleanup is still required; this source profile makes no hard
real-time completion guarantee.

The native PKI profile supplies no vendor-CRL revocation proof. Independent
configuration and release/PCR mapping, trust currentness, trusted time, nonce
reservation, latest off-host witness/rollback custody, executable packaging and
full native deployment remain separate requirements. Source-level capture
acceptance is not a production-readiness or runtime-success claim.
