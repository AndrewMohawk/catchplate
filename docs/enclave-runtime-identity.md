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

`mutual_tls_server_config` is a separate generated-only outer-server path: it
rejects development-PEM authorities, issues a fresh leaf/key within the original
CA interval, and installs TLS 1.3 only with mandatory `WebPkiClientVerifier`
client authentication and HTTP/1.1 ALPN. `GeneratedMutualTlsV1` retains the actual
configuration, leaf/CA DER chain, leaf SPKI and exact installed client-root DERs.
Its certificate/key-byte accessors expose public material; the opaque rustls
configuration is a serving capability. Roots must number 1..32, each at most
64 KiB and together at most 1 MiB. Empty, duplicate, malformed or trailing-DER
originals are rejected. This does not independently admit root provenance,
host/SPIFFE authorization, supplied validity times or a CRL/revocation policy.

The client-root commitment preserves caller order and original DER bytes:

```text
SHA256("serverware/mutual-tls-client-trust/v1\0"
       || root_count:u32BE || (DER_length:u64BE || DER)* )
```

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
7. Role-specific binding described below.

Role `1` quotes the TLS-root SPKI; role `2` quotes the raw X25519 public key and
requires the original nonzero credential-request binding. The seventh field is
zero for role `1`. Role `3`, produced by `quote_mutual_tls_ingress`, quotes the
actual fresh outer leaf SPKI and uses this seventh field:

```text
SHA256("serverware/native-tls13-mandatory-client-auth/v1\0"
       || SHA256(actual_leaf_DER) || client_trust_sha256)
```

The original role `1`/`2` encodings are unchanged. The nonce is a separate exact
32-byte NSM field. `RuntimeKeyQuoteV1` retains the original document, exact
`user_data`, public key and nonce; `QuotedMutualTlsIngressV1` also retains the
actual generated configuration and its original process/deadline scope. Those
bytes allow independent checking; neither a supplied commitment nor the
returned quote is release/policy admission.

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
does not relocate the gate into an enclave, authenticate NSM claims, change the
credential-lease KDF, or replace the existing proof signer and rollback policy.
This batch generates no new proof-signing identity and supplies no
caller-dictionary signing API.

### Retained native inner TLS authority

The gate now distinguishes `MitmAuthority::Pem` from `MitmAuthority::Native`;
the latter retains the actual `EnclaveRuntimeIdentityV1`, not just its public
CA bytes. Leaf-cache entries carry both the variant and SHA-256 of the actual
CA DER. `mitm_server_config` holds that authority while selecting a matching
entry and checks native process/poison/deadline and CA-time scope before
returning any cache hit and after new issuance. Native
`runtime_leaf_server_config` uses the exact retained original CA validity
interval, not a sliding `now + 24 hours` interval. Existing PEM behavior stays
separate. A local UTC sample is an observation, not independent trusted-time
or rollback admission.

`prepare_native_tls_gate_state` consumes unshared `GateState`, the actual native
identity and its quoted outer ingress. It rejects an existing MITM authority
or nonempty leaf cache, joins the actual CA identities, and installs native
custody before sharing state through `Arc`. Its opaque `NativeTlsGateV1`
retains the minimum caller/identity/quote deadline. `restrict_deadline` also
permanently narrows the native owner to that bound, so subsequent inner-leaf
cache checks cannot fall back to a longer original identity lifetime.

A generated `Arc<rustls::ServerConfig>` can outlive the identity owner. The
private serving join below retains the quoted owner through its workers;
independent active-scope admission and revocation remain required. Key/config
construction alone does not enforce those runtime transitions.

## Bounded vsock ingress, not activation

The [native vsock owner](../data-plane/decision-gate-rs/src/enclave_vsock_v1.rs)
provides retained nonblocking inbound `AF_VSOCK` streams, exact configured peer
CID comparison, original boottime deadlines, at most 64 KiB per I/O operation,
and explicit shutdown custody. It has no outbound connector or generic raw-FD
export. CID is routing scope, not client authentication: AWS Nitro's parent is
CID `3`, distinct from Linux's generic `VMADDR_CID_HOST` value `2`.
See the [AWS networking contract](https://docs.aws.amazon.com/enclaves/latest/user/enclave-networking.html)
and [Linux vsock API](https://man7.org/linux/man-pages/man7/vsock.7.html).

In the [gate](../data-plane/decision-gate-rs/src/main.rs),
`materialize_native_proxy_ingress` derives the configuration and evidence roots
from the same quoted owner. Its distinct `native-mtls-v1` metadata is not an
accepted environment mode or external-verifier profile. The chain commitment
uses SHA-256 over `serverware/native-tls-server-chain/v1` plus NUL, a `u32BE`
count and each `u64BE` length plus original DER, in chain order. Leaf/SPKI hashes
remain raw SHA-256; the client-root commitment is the framed digest above.
`serve_native_vsock_proxy` consumes the prepared `NativeTlsGateV1`, rechecks
the retained native authority/outer-quote join and time scope, requires exact
state metadata equality, and retains the owners until all scoped handlers
join. Accepted streams inherit the prepared deadline. It does not admit the
other supplied gate state as enclave-owned.

The private gate serving composition requires actual mutual TLS before HTTP
handling, rejects management/development-raw use, and feeds genuine verified
client-certificate evidence into the existing request path. Client IP remains
unknown; CID is never translated into a parent or loopback IP identity. A
bounded worker/queue inventory retains shutdown custody for queued
and active sessions. Shutdown closes inbound sessions and joins workers, but
that join may await existing bounded upstream HTTP/DNS I/O. It is **not** a
hard syscall/whole-process watchdog or a proof that all work stops at the exact
deadline. No CLI/environment mode activates this private composition.

## Deferred verification

The consolidated frozen phase must cover the real gate call sites as well as
the new owners: unchanged authenticated envelope/KDF results and leaf-cache
behavior; rejected non-contributory peers and process drift; generated CA/leaf
validity bounds; exact CBOR field/framing/size rejection and permanent poison;
pending-key substitution, deadline clipping and request/public-key joins;
mandatory outer client authentication, TLS-version/root-bundle rejection and
exact role `3` joins; unknown-IP handling, bounded queues and session shutdown.
Native inner-TLS coverage must also reject authority/cache substitution and
deadline extension, including cache hits after the prepared bound expires.

Actual Nitro checks then need a fresh independent challenge, the original COSE
document and genuine certificate/PCR/nonce/public-key/user-data verification
against independently accepted releases. Existing production quote consumers
are unchanged: this new internal binding is not a compatibility path into their
acceptance. Device access or a locally parsed document cannot replace that work.
In particular, the existing
[Nitro verifier](../scripts/verify_nitro_tee.py) requires an RSA DER recipient for
its KMS profile, while native role `2` carries a raw 32-byte X25519 key and the
binary binding above. Connecting native credential leases needs a distinct
genuine verifier profile and original-request/nonce/key joins, without
relaxing RSA/KMS verification or treating a raw NSM response as accepted
evidence. The existing external recipient-verifier gate remains mandatory.
The fixed transport follows the [Linux NSM UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/nsm.h)
and [AWS request/response types](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/src/api/mod.rs).

## Still required for the production boundary

The full Rust TLS, policy, credential acquisition, injection, upstream TLS,
response-validation and proof path must execute inside the admitted enclave.
The parent must handle ciphertext and public evidence only. Still missing are
the independently admitted complete enclave serving composition and parent/enclave
transport, real KMS RSA/`CiphertextForRecipient`/CMS integration, and removal of
the host control-plane `keyB64`/plaintext-key paths. Native NSM access by itself
does not close any of those gaps.

Production also requires independently admitted release/configuration roots,
fresh challenge and PCR/TLS-key verification, actual EIF deployment,
non-exportable authority keys, rollback-resistant external state, and the
independent [release chain](release-stages.md). The required Coder controller,
source-freeze, preparation and sequential no-build verification gates remain
unchanged. No build, test, runtime or hardware evidence was produced here.
