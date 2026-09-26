# Native response-proof key custody

Status: source-only, unbuilt and unexecuted. This adds actual generated Ed25519
key custody, fresh original NSM response quotation and a separate local native
verification path behind the existing response-proof protocol. The existing
proof-client CLI does not accept the new native envelope. This is not independent
admission of hardware, a production key-release or rollback service, or completed
native startup.

## Keep authorization in the existing operation owner

The [custody runtime](../data-plane/decision-gate-rs/src/custody_protocol.rs)
already owns five closed operations: `hello/v1`, `responseProof.sign/v2`,
`streamingResponseProof.sign/v1`, `responseObservationProof.reserve/v1` and
`responseObservationProof.sign/v1`. The native backend retains these operations
and their exact canonical request/statement formats; it does not add a generic
signing endpoint or accept a caller's verified-result dictionary.

Request frames remain bounded to 256 KiB. Signing/reservation requests consume
one of at most 65,536 request IDs per boot and require the actual current boot
ID. Serialized validation preserves the existing statement age and shape
checks. Response and streaming statements require a genuinely signed
control-plane authorization receipt under the configured, independently pinned
control-plane response key. The receipt binds the fixed dispatch request,
nonce, original request/response commitments, authorized dispatch state,
principal, route, credential, attempt, policy and dispatch/reservation lifetime.

The statement policy is `policy_digest` for response/streaming statements and
`policy.digest` for observation statements. Authorized cases retain the exact
join to `authorization_binding.policy_hash`; native signing additionally joins
every statement family to the held key's policy scope, including observations
that legitimately have no release-authorization receipt. Policy completion,
request aggregate, emitted/upstream response and channel/server-instance checks
remain the existing typed protocol's responsibility.

Control-plane and proxy runtime measurements remain distinct. The signed
control-plane receipt's policy/provenance context must match the statement's
policy/release context; its runtime-manifest digest is not relabeled as the
proxy runtime's measurement. Signing validates the supplied protocol evidence;
it does not independently observe network I/O or prove execution merely because
the new key signed it.

## Generated key and original role-4 quote

The [key owner](../data-plane/decision-gate-rs/src/enclave_response_proof_key_v1.rs)
is prepared by `EnclaveRuntimeIdentityV1::prepare_response_proof_key(deadline)`.
Its opaque `PendingResponseProofKeyV1` exposes checked public bytes, allowing
the runtime to construct its real boot/key/control-plane-key commitment before
quotation. `quote_response_proof_key(pending, request_binding, nonce, deadline)`
consumes that same generated key and returns `QuotedResponseProofKeyV1`.

`CustodyRuntime::generate_native_with_control_plane_response_public_key`
takes the actual mutable runtime identity, a control-plane verifying key and
its expected SPKI key ID, an exact 32-byte nonce, the existing ledger directory
and an absolute deadline. It opens the ledger, generates the actual boot ID and
proof key, and quotes this fixed binding:

```text
SHA256("serverware/native-proof-custody-boot/v1\0"
       || actual_boot_id_32
       || SHA256(actual_proof_key_SPKI_DER)
       || SHA256(actual_pinned_control_plane_key_SPKI_DER))
```

The NSM public-key field is the actual raw 32-byte Ed25519 public key. Role `4`
uses the existing runtime-key-binding domain and seven-field scope described in
the [identity guide](enclave-runtime-identity.md); its final field binds the
actual custody boot and public-key identities. The custody protocol's key ID is
separately SHA-256 over the actual Ed25519 SPKI DER, not over raw public bytes.
Quotation does not change existing role `1`/`2`/`3` encodings.

The owner exposes original public quotation material and checked key/lifetime
views, with no secret export/import, Clone or Debug API. Its signing method is
crate-private and used only after the runtime's authorization and ledger gates.
`verify_identity` rejoins the actual runtime CA and complete role-4 scope and
permanently clips the local deadline. PID/deadline checks and private fields
are not hostile-process isolation, and original quote bytes are not an
independent quote-verification verdict.

```text
actual generated key + boot + pinned control-plane key
    +-- original role-4 quote -> caller-owned verifier (not wired into startup)
    +-- retained key owner -> closed authorization + ledger gates -> signature
```

`native_quote()` exposes public originals, including after expiry; it cannot
authorize key use. `verify_native_live()` checks the actual owner, and
`verify_native_identity()` joins it to the bootstrap identity and permanently
narrows its lifetime. Native requests, including hello and reservation, remain
bracketed by actual owner checks. No late failure resets an already committed
ledger operation.

## Ledger and reservation behavior is preserved

Before returning a signature, the runtime durably binds the actual attempt ID
to the exact canonical statement digest. The same attempt/digest is idempotent
within its retained window; a different digest is rejected. Observation nonce
reservation is exclusive, happens before upstream work, and commits the request
aggregate. Observation signing requires that live reservation and durably binds
it to the final statement. Native expiry or another late signing failure does
not undo a committed claim.

The existing ledger must already be explicitly initialized. Ordinary runtime
construction does not invent a fresh manifest when one is missing. The local
backend checks normalized, non-symlink directory ancestry, owner UID/GID and
0700 directory/0600 file modes, holds an exclusive advisory lock, and joins
bounded records to its checksummed manifest/active-set inventory. Binding and
manifest publication retain file and directory synchronization before signing;
write failure poisons the ledger.

This remains **filesystem-development rollback protection**, not production
anti-rollback authority. Wall-clock high-water checks operate against the
retained local store. Expired records can be pruned and recognized interrupted
temporary files can be cleaned during existing recovery; this is neither an
append-only permanent history nor indefinite replay retention. Restoring an
older complete filesystem image is not defeated by its own checksums. Protected
off-host freshness/witness custody and trusted time remain required. Synchronous
filesystem work is not bounded by a hard watchdog merely because the key has an
original deadline.

## Separately configured role-4 verification

[verify_native_response_proof_key.py](../scripts/verify_native_response_proof_key.py)
accepts exactly `apiVersion`, `attestationDocumentB64` and
`responseProofPublicKey` under `serverware.nativeResponseProofKeyEvidence/v1`.
The original quote and raw 32-byte Ed25519 key use canonical unpadded URL-safe
base64; evidence cannot supply trusted boot, policy, challenge or verdict claims.
Stdin is capped at 32 KiB and the original quote at 12 KiB.
`CustodyRuntime::native_key_evidence()` constructs those exact three fields
from its actual retained quote/key and checks native liveness before and after;
development custody returns no native evidence. It does not copy verified
claims or create a successful verifier result.

Four required arguments, `--expectations`, `--expectations-sha256`,
`--trust-roots` and `--trust-roots-sha256`, pin exact file originals before
strict parsing. Expectations use `serverware.nativeResponseProofKeyExpectations/v1`
and add independently expected boot ID, proof SPKI key ID, control-plane SPKI
key ID and nonce to the existing pinned release/policy/configuration/CA/PCR/EIF/
module/age scope. Trust uses `serverware.nativeResponseProofKeyTrustRoots/v1`
and the fixed native PKI profile with an empty CRL inventory. Expectation and
trust originals are capped at 16 KiB and 1 MiB respectively.

The adapter reconstructs the exact Rust boot binding and role-4 bytes and calls
the existing genuine COSE, certificate-chain, complete-PCR, nonce, age and scope
verification. RSA/KMS and raw-X25519 lease profiles are unchanged. The shared
`expectedBinaryDigest` is pinned configuration metadata, not a separate signed
field in this quote; independent release/PCR admission must establish its
meaning. Native PKI does not supply vendor-CRL revocation proof.

Successful output is bounded to 4 KiB and explicitly labels
`serverware.nativeResponseProofKeyVerification/v1`, `resultScope=local-verifier-only`
and `okForAction=false`. It is not a transferable admission, response proof,
live witness or key-possession proof. The caller still owns expectation
provenance/currentness, fresh one-use challenge reservation, trusted time and
watchdog enforcement. No default verifier activation or runtime readiness is
enabled by adding this script.

## Fresh quotation of an actually signed response

The [native response producer](../data-plane/decision-gate-rs/src/native_response_attestation.rs)
is called by the actual buffered, streaming and v1 observation producers immediately
after their existing authorization/ledger-gated signatures. For an actual native
signer it obtains fresh original evidence from the retained runtime identity;
failure cannot fall back to an external command. Non-native and UDS paths retain
their existing command-produced `vendor_tee` format. Native context readiness
uses the actual live backend, and native bootstrap rejects an external
proof-attestation command rather than requiring one.

`CustodyRuntime::quote_native_signed_statement` accepts the exact canonical
statement, its existing signature and the actual client nonce. It admits only
the existing three typed statement families, rejoins canonical bytes, nonce,
policy and statement age, and verifies the signature under its own held key.
It neither signs again nor reclaims an attempt or observation reservation. The
fresh NSM challenge is:

```text
SHA256("serverware/native-response-attestation-challenge/v1\0"
       || u8(length(raw_client_nonce)) || raw_client_nonce
       || SHA256(canonical_statement) || raw_Ed25519_signature_64)
```

Buffered nonces retain their existing 32–64-byte range; streaming and observation
nonces remain exactly 32 bytes. This challenge is distinct from the client's
nonce. `QuotedResponseProofKeyV1::quote_fresh` quotes the same actual role-4 key
and boot/scope binding with that challenge. It does not replace the constructor
quote, regenerate a key, renew either owner's lifetime, extend statement age or
renew authorization. Checks discard late originals, but a deadline alone cannot
interrupt a blocked NSM ioctl or mutex wait.

The distinct envelope is `serverware.nativeResponseRuntimeProof/v1`, kind
`ServerwareNativeResponseRuntimeProof`, with exactly `apiVersion`, `kind`,
`server_statement`, `server_statement_sha256`, `server_signature` and
`native_attestation`. All three families use these outer names while preserving
their original signed statement versions and canonical bytes. `server_signature`
keeps its existing algorithm/key-ID/public-PEM/signature fields;
`native_attestation` contains only the existing three original role-4 evidence
fields. No successful verifier claims or `trusted_verifier` signature are
invented. Producer output is capped at 128 KiB; the existing streaming encoder's
96 KiB bound remains narrower.

Closed shapes are recorded in the [native key-evidence schema](../schemas/native-response-proof-key-evidence.v1.schema.json)
and [native response-envelope schema](../schemas/native-response-runtime-proof.v1.schema.json).
Schema conformance alone is not cryptographic verification, independent response
observation, current-witness evidence or action admission.

### Separate response verifier; existing client remains closed

[verify_native_response_attestation.py](../scripts/verify_native_response_attestation.py)
accepts the exact six-field native envelope. It checks the closed outer and
statement-family fields, actual Ed25519 signature, independently pinned proof
key, actual client nonce, policy/binary commitments and statement age. It derives
the challenge above and calls the genuine role-4 verifier on the original Nitro
document, joining the same boot, proof key, control-plane key and pinned scope.
A signed binary-digest claim still requires an independently admitted mapping
from release/PCR expectations to that binary; the quote adds no separate binary
measurement field.

Its four required pinned-file arguments are the same names as the key verifier.
The expectation version is `serverware.nativeResponseAttestationExpectations/v1`;
its `nonce` is the independently held **original client nonce**, not a challenge
copied from the quote. The remaining boot/key/control-plane-key and release/
policy/configuration/CA/PCR/EIF/module/age expectations remain independent of
evidence. Trust uses `serverware.nativeResponseAttestationTrustRoots/v1` and the
same fixed native PKI profile with empty CRLs. Exact expectation/trust originals
remain capped at 16 KiB/1 MiB. Input is bounded to 512 KiB, the canonical statement
to 256 KiB, JSON depth to 64 and nodes to 100,000; producer bounds remain narrower.

Output is at most 4 KiB, version
`serverware.nativeResponseAttestationVerification/v1`, with
`resultScope=local-signature-and-native-quote-only` and `okForAction=false`.
This is unsigned local output, not full nested statement-schema validation,
control-plane receipt/authorization verification, independent HTTP response or
TLS-exporter observation, release admission or current witness evidence. A
fresh quote does not prove that the attested key's signed network claims happened.
Nonce freshness/reservation, expectation provenance/currentness, trusted time
and watchdogs remain caller responsibilities.

The existing `serverware-proof-client` production path requires its separately
signed `serverware.vendorTeeVerification/v1` envelope, exact verified claims and
the existing HTTP/TLS/request/body joins before capture publication. It does
**not** accept this distinct native proof. In particular, the local result is
not a substitute for that verifier signature, and the native PKI profile cannot
truthfully manufacture its legacy `revocation_checked=true` assertion. Native
client trust-profile admission and full HTTP/TLS capture integration remain
missing; neither parser fallback nor a copied success verdict is introduced.

## Gate integration and remaining boundary

The [gate adapter](../data-plane/decision-gate-rs/src/native_proof_signer.rs)
consumes the actual native runtime through
`initialize_native_response_proof_signer(runtime)`, rejecting a development
runtime. `CustodySignerTransport::Native` retains it in an opaque owner, bounded
to the existing 32 concurrent operations, and uses the same canonical exchange,
strict hello/signature-result checks, probes and health reporting. Dispatch
also checks actual native liveness before and within its existing permit.

The native bootstrap requires this native transport, not a UDS signer. Before
sharing state it joins the actual retained proof key to the consumed runtime
identity's CA, complete role-4 scope and original deadline. Metadata/key-ID
equality alone does not substitute for that join. The runtime is in the gate's
address space: this does not provide Unix-peer or separate-process isolation.
The legacy UDS path and its different-UID requirement remain separate.

The actual mode is `custody-native`. Hello and metadata keep
`hardwareProof=false`; the quote digest is labeled `unverified-original`, and
rollback protection is labeled `filesystem-development`. These labels cannot
be upgraded merely because native quotation or local verification succeeds.

Independently admitted verifier configuration and role-4 expectations,
release/configuration/key admission, external checkpoint/witness freshness,
KMS release, protected persistence, provisioning and complete enclave startup
remain missing. The native producer replaces the external attestation command
only on its actual native path; it does not supply independent client acceptance
or response-observation-v2 admission. No daemon, environment mode, hardware proof
or production activation is supplied by this source work. See the
[bootstrap guide](enclave-bootstrap.md) for actual initial policy/state custody
and its remaining admission requirements.
