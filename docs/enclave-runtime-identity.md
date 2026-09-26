# Native runtime identity and private key ownership

Status: source-only, unbuilt and unexecuted. These owners are computation and
native-device prerequisites for the [production enclave boundary](../goal.md),
not a complete enclave proxy, production admission or hardware-custody proof.
No new serving mode or environment switch activates that boundary.

## Three concrete owners

| Owner | Source responsibility | Boundary |
| --- | --- | --- |
| `CredentialRecipientV1` | Generate a fresh X25519 key using `ring::rand`, retain its `StaticSecret`, expose public bytes and consume the owner to derive one shared key | Existing credential-lease envelope/KDF only; not KMS RSA Recipient or CMS decryption |
| `TlsAuthorityV1` | Generate an in-memory CA and issue rustls leaf configurations without a private-key export API | Certificate generation does not authenticate a release or prove where the process runs |
| `NsmDeviceV1` | Submit bounded attestation requests to the actual native NSM device and retain the original returned document | A device response is not independent verification of certificate trust, PCRs, release identity or current authorization |

The [recipient](../data-plane/decision-gate-rs/src/credential_recipient_v1.rs)
rejects creator-PID drift. Its generation temporary and returned shared bytes
are zeroizing containers; derivation explicitly rejects an all-zero,
non-contributory result. `derive_shared_key(self, peer)` consumes the recipient.
The result is raw X25519 material, not an AEAD key: the existing authenticated
lease's nonce, associated-data and HKDF rules remain mandatory. PID checks and
private fields do not isolate memory from the parent host.

The [TLS authority](../data-plane/decision-gate-rs/src/tls_authority_v1.rs)
has separate generated and development-PEM constructors. Generated CA validity
is retained, and leaf issuance cannot extend that interval. Its public
certificate/SPKI and `leaf_server_config` API do not export a private key.
`from_development_pem` preserves the existing host compatibility behavior; it
does not turn a mounted PEM key into enclave custody or production admission.
No complete backend-memory-erasure claim follows from this interface.

The [native NSM owner](../data-plane/decision-gate-rs/src/enclave_nsm_v1.rs)
opens only `/dev/nsm`, retaining its root-owned misc-character-device identity,
creator process and original boottime deadline. It sends only the fixed
attestation operation: public key, nonce and user data are each capped at
1024 bytes, the request at 4096 bytes and the response at 12,288 bytes. Any
failed attestation permanently poisons the owner. The returned COSE document
is unverified original data. Before/after deadline checks do not interrupt a
blocked synchronous ioctl; a hard wall-time bound still needs an independently
owned watchdog.

## Composition and actual gate reuse

[EnclaveRuntimeIdentityV1](../data-plane/decision-gate-rs/src/enclave_runtime_identity_v1.rs)
combines the generated TLS authority with native NSM access. It opens the
device before generating the CA and admits only a positive CA interval of at
most 24 hours. It does not import a private key or manufacture a host fallback.

The native NSM `user_data` is a fixed binary original: the NUL-terminated
domain `serverware/enclave-runtime-key-binding/v1`, one role byte, then seven
32-byte SHA-256-sized fields in this order:

1. Supplied release-record commitment.
2. Supplied policy commitment.
3. Supplied configuration commitment.
4. SHA-256 of the actual CA certificate DER.
5. SHA-256 of the actual CA public-key SPKI DER.
6. SHA-256 of the actual key placed in the NSM public-key field.
7. Original credential-request binding, or all zero bytes for the TLS-root role.

Role `1` quotes the TLS-root SPKI; role `2` quotes the raw X25519 public key and
requires a nonzero request binding. The nonce is a separate exact 32-byte NSM
field. `RuntimeKeyQuoteV1` retains the original document, exact `user_data`,
public key and nonce. Those bytes allow independent checking; neither a
supplied commitment nor the returned quote is release/policy admission.

Lease quotation is deliberately two-phase. `prepare_lease_recipient(deadline)`
creates an opaque `PendingCredentialRecipientV1`; its `public_key_bytes()`
allows the caller to construct the real request, whose digest includes that
key through `recipientKeyId`, the SHA-256 identity of its public bytes.
`quote_lease_recipient(pending, request_binding, nonce, deadline)` consumes
that **same** key, checks its private CA-identity binding and clips the operation
to its original pending deadline. It returns `QuotedCredentialRecipientV1`,
which retains the key and quote until one consuming derivation. Regenerating a
recipient after computing the request digest would break this binding; no
caller-created pending record or replacement-key argument is accepted.

The ordinary Rust gate reuses the recipient and TLS owners at its existing
credential-lease and MITM-CA seams. Its existing optional external recipient
attestation command remains unchanged; that path does not automatically select
the native composition or put these new quotes into a lease request. That reuse
does not relocate the gate into
an enclave, authenticate NSM claims, change the credential-lease KDF, or replace
the existing proof signer and rollback policy. This batch generates no new
proof-signing identity and supplies no caller-dictionary signing API.

A generated `Arc<rustls::ServerConfig>` can outlive the identity owner. Future
serving must enforce active scope, session revocation and connection closure;
key/config construction alone does not enforce those runtime transitions.

## Deferred verification

The consolidated frozen phase must cover the real gate call sites as well as
the new owners: unchanged authenticated envelope/KDF results and leaf-cache
behavior; rejected non-contributory peers and process drift; generated CA/leaf
validity bounds; exact CBOR field/framing/size rejection and permanent poison;
pending-key substitution, deadline clipping and request/public-key joins.

Actual Nitro checks then need a fresh independent challenge, the original COSE
document and genuine certificate/PCR/nonce/public-key/user-data verification
against independently accepted releases. Existing production quote consumers
are unchanged: this new internal binding is not a compatibility path into their
acceptance. Device access or a locally parsed document cannot replace that work.
The fixed transport follows the [Linux NSM UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/nsm.h)
and [AWS request/response types](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/src/api/mod.rs).

## Still required for the production boundary

The full Rust TLS, policy, credential acquisition, injection, upstream TLS,
response-validation and proof path must execute inside the admitted enclave.
The parent must handle ciphertext and public evidence only. Still missing are
the complete enclave serving composition, authenticated parent/enclave
transport, real KMS RSA/`CiphertextForRecipient`/CMS integration, and removal of
the host control-plane `keyB64`/plaintext-key paths. Native NSM access by itself
does not close any of those gaps.

Production also requires independently admitted release/configuration roots,
fresh challenge and PCR/TLS-key verification, actual EIF deployment,
non-exportable authority keys, rollback-resistant external state, and the
independent [release chain](release-stages.md). The required Coder controller,
source-freeze, preparation and sequential no-build verification gates remain
unchanged. No build, test, runtime or hardware evidence was produced here.
