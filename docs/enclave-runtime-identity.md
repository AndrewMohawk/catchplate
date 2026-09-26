# Native runtime identity and private key ownership

Status: source-only, unbuilt and unexecuted. These owners are computation and
native-device prerequisites for the [production enclave boundary](../goal.md),
not a complete enclave proxy, production admission or hardware-custody proof.
No new serving mode or environment switch activates that boundary.

## Concrete owners

| Owner | Source responsibility | Boundary |
| --- | --- | --- |
| `CredentialRecipientV1` | Generate a fresh X25519 key using `ring::rand`, retain its `StaticSecret`, expose public bytes and consume the owner to derive one shared key | Existing credential-lease envelope/KDF only; not KMS RSA Recipient or CMS decryption |
| `TlsAuthorityV1` | Generate an in-memory CA and issue rustls leaf configurations without a private-key export API | Certificate generation does not authenticate a release or prove where the process runs |
| `NsmDeviceV1` | Submit bounded attestation requests to the actual native NSM device and retain the original returned document | A device response is not independent verification of certificate trust, PCRs, release identity or current authorization |
| `PendingResponseProofKeyV1` / `QuotedResponseProofKeyV1` | Retain a freshly generated Ed25519 key and its original role-4 quote behind the existing custody runtime | No generic signing endpoint, independently admitted hardware or production rollback witness |

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

Role `4` now quotes the actual raw Ed25519 response-proof key. Its seventh
field commits the actual custody boot ID and the SHA-256 identities of the
proof-key and pinned control-plane-key SPKI originals. The
[proof-custody guide](enclave-proof-custody.md) gives the fixed domain/recipe,
same-key preparation/quotation, closed authorization/ledger gates and
in-process isolation limitations. Existing role `1`/`2`/`3` encodings stay intact.

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
credential-lease and MITM-CA seams. Its optional external recipient attestation
command remains the standalone path; only a retained `MitmAuthority::Native`
selects native quotation. Neither reuse relocates the gate into an enclave,
authenticates NSM claims locally or changes the credential-lease KDF. The later
[native proof-custody composition](enclave-proof-custody.md) generates a fresh
role-4 proof identity behind the existing authorization, replay and reservation
protocol. It supplies no caller-dictionary signing endpoint or production
rollback authority.

### Native credential-lease fetch

The actual `fetch_scoped_credential_lease` path prepares a native pending key,
constructs the unchanged credential request with that key, computes its
existing request-binding digest, then quotes that same pending key. It sends
only this exact three-field `recipientAttestation` evidence object:

| Field | Original value |
| --- | --- |
| `apiVersion` | `serverware.nativeCredentialRecipientEvidence/v1` |
| `attestationDocumentB64` | Original NSM document, URL-safe base64 without padding |
| `recipientPublicKey` | Actual raw 32-byte X25519 public key, in the same encoding |

The closed [evidence JSON schema](../schemas/native-credential-recipient-evidence.v1.schema.json)
describes this wire shape and encoding bounds only; schema conformance is not
Nitro verification or key admission.

The retained native identity must match the active snapshot's policy
commitment. Policy and original process/deadline checks bracket the blocking
broker HTTP operation and run again after decryption. The private
`LeaseRecipientOwner::Native` retains the actual quoted recipient until
`decrypt_credential_lease_envelope_with_owner` consumes it. The existing
standalone decrypt API delegates to that same body; envelope shape, scope,
nonce, associated data, HKDF and authenticated-decryption rules are unchanged.
No response-supplied key replaces the recipient.

Native setup and recipient preparation reject an external recipient-attestation
command mixed with the native owner. Failure does not fall back to a standalone
key or command. No new environment/profile switch selects this path. Original
deadline checks reject late results but do not interrupt blocking HTTP or NSM
ioctls; the existing three-second HTTP client timeout is not a hard native
whole-operation watchdog.

### Separate raw-X25519 verifier adapter

[`verify_native_lease_recipient.py`](../scripts/verify_native_lease_recipient.py)
is an explicit adapter for the existing broker verifier input, not a locally
successful quote flag or automatic application activation. Its required CLI
inputs are independently provisioned files and their exact byte digests:

```text
python3 /absolute/path/to/verify_native_lease_recipient.py \
  --expectations /absolute/path/to/expectations.json \
  --expectations-sha256 sha256:<hex> \
  --trust-roots /absolute/path/to/trust-roots.json \
  --trust-roots-sha256 sha256:<hex>
```

The adapter accepts at most 64 KiB on standard input and the exact evidence
object above, including at most 12,288 original document bytes. It reconstructs
the fixed role-2 binding from independently pinned runtime expectations and the
actual request/nonce/key scope. It does not obtain expected release, PCR, CA or
configuration commitments from the unverified quote, nor accept an override
clock or substitute defaults for missing pinned configuration.

The expectations file is at most 16 KiB with schema
`serverware.nativeCredentialRecipientExpectations/v1`. Its closed fields pin
release record, policy, configuration, CA certificate/SPKI and binary digests;
the complete expected locked-PCR inventory, EIF equal to PCR `0`, module ID,
maximum age of 1..300 seconds and future skew of 0..30 seconds. The inventory
has 3..32 entries at indices `0`..`31`, includes nonzero PCRs `0`/`1`/`2`, and
must exactly match the document's keys and values. Additional reserved zero
values are permitted only when explicitly pinned; no reported PCR is ignored.
The separate trust file is at most 1 MiB with schema
`serverware.nativeCredentialRecipientTrustRoots/v1`. It retains the fixed
root-certificate, CRL and certificate-profile fields, but this native profile
requires an **empty** `awsNitroCrlsDerBase64url` list and certificate profile
`aws-nitro-attestation-pki-native-v1`. Original file digests are checked before
parsing. These files need independent admission and provisioning, not values
copied from the presented quote.

The broker must supply its independently reconstructed full request digest and
scope to the adapter; the adapter input is not itself the complete original
credential request. Only after genuine verification does the adapter return
`ok: true`, `debug: false` and exact request-scope echoes, under a 64 KiB output
bound. That unsigned process-local verdict is not reusable signed authority or
a replacement for the broker's request/authorization checks. Age checking uses
the local clock; this is not trusted-time or rollback proof.

The dedicated `verify_native_recipient_nitro_document` profile in
[`verify_nitro_tee.py`](../scripts/verify_nitro_tee.py) accepts a COSE Sign1 array
either untagged or with tag `18`, while verifying its original signed bytes.
It enforces signature, certificate-chain/time/role/EKU/P-384, exact complete
PCR/EIF, module, nonce and age checks, then joins the exact nonzero raw 32-byte
key and complete fixed role-2 user data. Its raw-key result is distinct from
DER/RSA recipient evidence. The existing RSA/KMS profile, including its
mandatory CRL policy, is unchanged.

This native-only distinction follows the [AWS attestation specification,
sections 2.2, 3.1 and 3.2.4](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md):
the document contains all locked PCRs, COSE tagging is optional, and AWS's
attestation PKI does not use CRLs. Consequently **vendor CRL revocation is not
proved** by this native path. Independently current local trust pins, release
admission/revocation and application nonce reservation remain separate duties.
The verifier does not reserve a nonce or establish rollback-resistant time.
These source paths still require genuine deployment verification; they neither
perform KMS recipient decryption nor prove possession merely by returning
public evidence.

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
and explicit shutdown custody. Its separate outbound connector permits only
fixed Nitro parent CID `3`; it has no arbitrary-CID connector or generic raw-FD
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
`serve_native_vsock_proxy` consumes the prepared `NativeTlsGateV1` through the
[owned native lifecycle](native-runtime-lifecycle.md), with actual scoped
background workers, readiness checks and shared stop/join ownership. It rechecks
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

The [native outbound transport](enclave-outbound-transport.md) now provides
source-level provider and credential-broker HTTPS routing through retained,
fixed-authority loopback CONNECT owners and preassigned parent vsock ports.
The existing Reqwest client keeps genuine upstream TLS/hostname verification;
local CONNECT headers and authentication are not sent to the parent. Static
endpoint assignments and their address inventory are not independently admitted
merely by constructing these owners. The [service transport integration](enclave-service-transport.md)
now covers shared audit/grant/rate/release clients, retained trust refresh and
bounded parent serving. Neither integration activates native startup or
independently admits proof authority. The separate
[proof-custody adapter](enclave-proof-custody.md) now retains the actual native
signer in-process; this is not a new isolated service or production admission.

The separate [native bootstrap](enclave-bootstrap.md) now consumes these actual
owners before initial policy acquisition, fetches trust through retained native
transport, compiles bounded original signed-policy bytes and assembles fresh
state. Supplied checkpoint, configuration and proof-owner consistency remain
distinct from independent currentness/provenance admission; no CLI or complete
enclave startup is activated.

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
Native lease coverage must join the prepared key, unchanged request digest,
original quote and consumed key; deny native/command mixing, policy drift and
late broker/decrypt results; and reject adapter input/pin/profile substitution,
missing or extra PCRs, unsupported COSE tags and nonempty native CRLs without
relaxing the existing RSA/KMS tests. Both supported COSE forms still need
genuine signature verification over their original signed bytes.

Actual Nitro checks then need a fresh independent challenge, the original COSE
document and genuine certificate/PCR/nonce/public-key/user-data verification
against independently accepted releases. Existing production quote consumers
are not automatically reconfigured to accept this internal binding. Device
access or a locally parsed document cannot replace that work. The new explicit
native recipient adapter is separate from the existing RSA DER KMS profile;
its source availability is not broker provisioning or production admission.
The existing external recipient-verifier gate remains mandatory.
The fixed transport follows the [Linux NSM UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/nsm.h)
and [AWS request/response types](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/src/api/mod.rs).

## Still required for the production boundary

The full Rust TLS, policy, credential acquisition, injection, upstream TLS,
response-validation and proof path must execute inside the admitted enclave.
The parent must handle ciphertext and public evidence only. The provider/broker
and shared control-plane transport source above is implemented, but full native
startup, independently admitted endpoint/CID assignments, parent service
provisioning, independent proof-authority admission and complete enclave serving
admission are still required. Real KMS RSA/`CiphertextForRecipient`/CMS integration and removal
of the host control-plane `keyB64`/plaintext-key paths also remain open. Native
NSM access or a local tunnel by itself does not close those gaps.

Production also requires independently admitted release/configuration roots,
fresh challenge and PCR/TLS-key verification, actual EIF deployment,
non-exportable authority keys, rollback-resistant external state, and the
independent [release chain](release-stages.md). The required Coder controller,
source-freeze, preparation and sequential no-build verification gates remain
unchanged. No build, test, runtime or hardware evidence was produced here.
