# Standalone native response verifier

Status: source-only, unbuilt and unexecuted. The Rust
[entrypoint](../data-plane/decision-gate-rs/src/bin/serverware-native-response-verifier.rs)
and [verification modules](../data-plane/decision-gate-rs/src/native_verifier/mod.rs)
implement an offline verifier of the original native response envelope, not an
interpreter launcher or an adapter that trusts copied verification claims. The
static build recipe is present; a built, independently admitted executable and
its digest are still prerequisites for the [native proof client](native-proof-client.md).
No native service activation or production approval follows from this source.

## Fixed originals and invocation

The executable accepts exactly these four required options, with no duplicates,
additional arguments or environment configuration:

```text
serverware-native-response-verifier \
  --expectations /approved/response-expectations.json \
  --expectations-sha256 sha256:<exact-original-digest> \
  --trust-roots /approved/native-trust-roots.json \
  --trust-roots-sha256 sha256:<exact-original-digest>
```

Standard input is one original `serverware.nativeResponseRuntimeProof/v1`
envelope, bounded to 512 KiB. Its six fields are `apiVersion`, `kind`,
`server_statement`, `server_statement_sha256`, `server_signature` and
`native_attestation`; the latter carries only the original quote and public key
under the existing three-field role-4 evidence schema. No evidence-supplied
roots, expected identity or successful verifier verdict is admitted.

The [CLI](../data-plane/decision-gate-rs/src/native_verifier/cli.rs) opens absolute
regular-file paths without following a final symlink. Expectations are at most
16 KiB and trust roots at most 1 MiB. It checks SHA-256 against the independently
supplied pins before parsing, retains the descriptors, then rereads and rehashes
them and rejoins the named file identities before publishing success. These
checks do not establish pin provenance or protect against a hostile root; the
CLI does not claim no-follow traversal of every ancestor. The proof client's
separate input custody and alias checks remain required.

Success is one compact JSON verdict plus a newline, at most 4 KiB in total.
No success bytes are written before verification and final input checks. The
entrypoint emits a fixed error and exits unsuccessfully on failure; the caller
must reject partial output or a failed exit, including output-write failures.
The verifier has no network request, subprocess, private key or output-file API.
It samples the local system clock rather than accepting a caller-provided time.
Trusted time, nonce reservation and an outer watchdog for blocking I/O remain
independent requirements. The invoking proof client retains its original
acceptance deadline, sealed executable, bounded process I/O and cleanup rules.

## Verification scope

The pinned expectations use
`serverware.nativeResponseAttestationExpectations/v1`: release, policy,
configuration, runtime CA certificate/SPKI and binary digests; complete PCR
inventory, EIF, module identity and freshness bounds; and the independently
expected boot, proof-key ID, control-plane response-key ID and client nonce.
The PCR inventory contains 3–32 canonical `PCR0`–`PCR31` entries, including
nonzero PCR0/1/2; additional explicitly pinned zero values are permitted.
`expectedEif` must equal PCR0. Module identity is bounded printable ASCII.

Trust originals use `serverware.nativeResponseAttestationTrustRoots/v1`, with
1–16 distinct certificates and the fixed
`aws-nitro-attestation-pki-native-v1` profile. Its CRL inventory must be empty:
successful verification makes no vendor-CRL revocation assertion. Independent
trust currentness and application revocation remain separate gates.

The implementation verifies the existing buffered, streaming or observation
statement's canonical bytes and Ed25519 signature, joins the expected client
nonce, key, boot, policy, binary and age, and reconstructs the exact fresh
challenge from the nonce, canonical-statement digest and signature. It verifies
the original Nitro document and the same-key role-4 binary binding, including
the independently pinned release/configuration/runtime-CA commitments. The
[proof-custody guide](enclave-proof-custody.md) records the challenge and boot
binding recipes. A binary digest's meaning still depends on independently
admitted release/PCR mapping; metadata equality does not supply that authority.

This is a fixed native Rust profile, not a claim that every input accepted by
the Python verifier is accepted here. JSON rejects duplicate keys and floating
point values, with depth 64 and 100,000-node bounds; statement canonicalization
uses the Rust producer's UTF-8 semantics. Certificate algorithms, critical
extensions and bounded binary decoding are deliberately closed profiles. The
supported-profile comparison must be validated against genuine originals, not
assumed from implementing similarly named operations.

Native CBOR permits order-independent maps, while rejecting duplicate semantic
keys, indefinite encodings and non-minimal lengths/integers. It accepts tagged
18 or untagged four-element COSE Sign1, exact ES384 protected headers and an
empty unprotected map; signature verification uses the original protected and
payload bytes. The document cap is 12 KiB; decoding has depth 64 and 100,000-item
and aggregate reservation bounds. AWS's public
[AttestationDoc helper](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/src/api/mod.rs)
derives serialization and uses `serde_cbor::to_vec`; that source does not justify
requiring sorted payload maps or substituting reserialized bytes for the signed
originals. It is helper-source evidence, not validation against a live Nitro
document.
The Python `verify_nitro_tee` common verifier applies the same unordered
integer/text map rule only to `native_profile=True`; its legacy canonical
profile remains unchanged.

Certificate verification supports RSA PKCS#1 v1.5 with SHA-256/384/512 and
2048–8192-bit issuer keys, or ECDSA with SHA-256/384 and P-256/P-384. Other
algorithms, including RSA-PSS, SHA-1 and P-521, are not accepted. The attestation
signature itself is exclusively P-384 ES384. The selected chain checks genuine
signatures, times, CA/leaf roles, path lengths, key usages and the root's
self-signature, with exact bundle coverage and unique issuer selection. Critical
extensions are limited to basic constraints, key usage and independently pinned
leaf EKU; unsupported name/policy constraints and CA EKU restrictions are also
rejected. These are intentional acceptance restrictions, not a general-purpose
X.509 or arbitrary Nitro-client compatibility claim.

The exact 19-field result remains
`serverware.nativeResponseAttestationVerification/v1`, with
`resultScope=local-signature-and-native-quote-only`, `okForAction=false` and
`debug=false`. It reports the verified signature/statement/quote identities and
expected scope. It is a local process result, not a signed verifier envelope,
current witness, release approval or action authorization. Full nested receipt,
HTTP capture, TLS exporter, body/framing and request/principal checks remain the
proof client's job; this verifier does not replace them.

## Static packaging and remaining validation

[Dockerfile.production](../data-plane/decision-gate-rs/Dockerfile.production)
builds `serverware-native-response-verifier` in the existing digest-pinned
Rust 1.88 / Alpine 3.22 stage using the reviewed vendored Cargo and musl inputs,
offline networking and `cargo --frozen`. No dependency, feature or Cargo
manifest change is needed. The recipe rejects an ELF interpreter, dynamic
`NEEDED` entries and an executable larger than 64 MiB. The proof client's
independent Linux/x86-64 ELF and exact-digest checks still apply.

The scratch export target is `native-response-verifier-artifact`, containing
`/serverware-native-response-verifier`. The production image installs that
static-stage binary root-owned, mode 0555, at
`/usr/local/libexec/serverware-native-response-verifier`. The ordinary glibc
build output is not the static artifact. Neither installation nor a local build
constitutes independent executable admission or source/dependency freeze.

Deferred consolidated validation must cover:

- The frozen musl build, exported original and actual static ELF constraints.
- Genuine original Nitro documents and all three statement families through
  the actual proof-client capture path, retaining its independent checks.
- Order-independent genuine payload acceptance, with duplicate and key-alias
  rejection controls.
- Invalid signatures, roots, PCRs, keys, nonces and times; duplicate JSON/CBOR
  and unsupported critical-extension rejection.
- Input drift, output failures and the actual caller's process cleanup limits.
- Supported-profile comparisons with the Python verifier, without asserting
  blanket parser or certificate-policy parity.

No builds, fixtures, tests or runtime validation were performed for this source
slice. Independent trust/configuration admission, current hardware/release
approval, latest off-host witness/rollback custody and full native deployment
remain outside this verifier.
