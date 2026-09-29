# Native shadow encrypted local-role keys

This is an additive source implementation, not a launched native custody
service or a real AWS verification result. Legacy guest construction remains
`TrustedHostNoTee`. Legacy native key configuration v1 still reads its exact
final-role originals; it does not silently select encrypted delivery.

## Owners and order

1. Independently provision the complete18 public assignment and the actual
   local subset (at most16; never verifier or supervisor keys). The offline
   `encrypt_native_shadow_local_keys.py` consumes separate sealed root:root0600
   zero-link memfds: FD3 inventory, FD4 existing assigned seed bundle, FD5 KEK32.
   It validates public associations and emits only the encrypted inventory.
   It generates no authority key or signature. Run only the pinned isolated
   Python3.11 closure with no arguments. Plaintext seed files are not inputs.
2. C9 signed guest delivery includes `shadow-encrypted-role-inventory`, a
   roleUID:roleGID0400, single-link, protected original of at most32768 bytes,
   with `signing:null`. Its digest is independently pinned. No legacy local
   `shadow-key-*` credential may coexist in this encrypted profile.
3. Under the SAME actual root C9 preparation and original startup interval,
   `PreparedNativeCustodyKeys::open_encrypted(key_configuration_v2,
   encrypted_configuration, assignment, trust, time, &delivery)` verifies both
   purpose signatures, full18/local roots, actual ciphertext original and
   current supervisor/revocation bindings. It retains NSM device originals and
   prepares the fixed helper before role drop or service threads.
4. The launcher installs the real admitted shadow root and permanently drops
   to its signed service role. The real closure owner installs its independently
   admitted filter. Existing `bind` requires this SAME C9/closure origin and
   production configuration. It creates a fresh process-held X25519 recipient.
   No numeric PID, ready boolean or deserialized result constructs this owner.
5. The private helper generates RSA2048. Only its retained image/process/channel
   produces `ShadowKeyRecipient`; NSM accepts that opaque owner, not public-key
   bytes. A separate one-shot recipient quote binds the actual RSA DER and full
   request. Only then is one ciphertext-only parent/KMS request made.
6. The helper decrypts closed AWS CMS using the existing pinned cryptography
   primitives, requires the independently signed full KEK digest, authenticates
   the encrypted inventory, and validates every derived assigned public key.
   It emits only ciphertext to the actual final-role X25519 recipient and exits.
   Successful `bind` requires its genuine successful exit/reap inside the SAME
   startup deadline. Rust decrypts directly into non-exporting local key owners,
   independently rechecks keys and all original authority/closure bindings.
7. Only after actual keys exist does the separate C8 possession phase run.
   Its local-root `public_key` remains a commitment, never a KMS key. The external
   Nitro verifier must independently verify the original quote and sign its
   unchanged result. No admission is inferred from KMS, helper completion or
   possession alone.

## Exact profiles and crypto

`nativeShadowRoleKeys/v2` retains the18-field assignment shape but requires
`nativeShadowRoleKeyAssignment/v2`, `preassigned-encrypted-local-v1`, and
`serverware.nativeShadowRoleKeyAssignment.signature/v2`. Old signatures cannot
authorize it. The independently pinned verifier accepts this exact additive
tuple only; statement15, possession and result22 semantics remain unchanged.

`NativeShadowEncryptedKeysConfiguration` is exact2 (`apiVersion`,
`authorization`), with the separate18-field delivery assignment and signature
domain `serverware.nativeShadowEncryptedKeyDelivery.signature/v1`. It uses the
actual independently assigned current supervisor authority, never a local key
or caller-selected trust source. All Ed25519 domains use the existing signed
envelope/canonical ASCII integer preimage.

The stable public inventory is exact4: `apiVersion`, `fullKeySetRootSha256`,
`localKeySetRootSha256`, `localKeys`. Each local public key is exact5 in actual
AuthorityRole order. The private plaintext is exact3 (`apiVersion`,
`inventorySha256`, `seeds`), each seed exact3 (`role`, `keyId`, `seedBase64url`).
AES256-GCM authenticates canonical plaintext <=16368 bytes with random nonce12
and AAD `serverware/native-shadow-encrypted-local-keys/v1\0` plus the original
canonical inventory. Ciphertext <=16384 bytes. Base64url is unpadded/canonical.

The inventory AAD intentionally excludes signatures/delivery digests which
themselves pin its ciphertext, avoiding a circular artifact construction.
Live request8 separately binds the exact guest13, key/delivery authorization
digests, original nonce, native closure/executable/seccomp, full18/local roots,
actual X25519 recipient, actual RSA recipient digest, entire signed transport8
(including fixed helper image/interpreter/script pins), and original deadline.

NSM `user_data` is `serverware/native-shadow-kms-recipient/v1\0` plus SHA256 of
the exact canonical request. NSM `public_key` is the actual helper RSA DER.
Its nonce is SHA256(`serverware/native-shadow-kms-nonce/v1\0` plus the original
independent challenge32), separate from the possession nonce/domain. There is
no generic quote, phase reset, recontact or post-uncertainty retry API.

Role output uses fresh helper X25519, HKDF-SHA256 with that derived nonce as
salt, and info/AAD `serverware/native-shadow-role-recipient-ciphertext/v1\0`
plus requestSHA32. AES256-GCM nonce12 and ciphertext return in exact6 envelope.
Rust seeds/canonical plaintext/shared material have zeroizing buffers. Python,
OpenSSL and all immutable interpreter copies are NOT claimed erased; the
dedicated helper exits and never becomes a signing/decrypt service.

## Real process and packaging contract

Required new image: `/opt/serverware/native-shadow-key-delivery-runtime.squashfs`.
The existing sealed-memfd/read-only-loop/SquashFS mechanism admits it under a
distinct fixed purpose, <=512MiB, not legacy fs-verity/IMA. It must contain
`/usr/local/bin/python3.11`, the fixed
`/opt/serverware/serverware/native_shadow_key_helper.py`, this contract module,
the shared native shadow grammar and closed CMS module, pinned cryptography
dependencies, stdlib, loader and complete recursive DSO closure. No packaging
producer or image existence is asserted by these source files.

The root-created one-shot helper runs at the SAME signed final service UID/GID,
with groups/capabilities removed, NNP, private immutable root, empty environment,
no shell/argv selector, and post-exec nondumpability before secret input. This
is a purpose-specific measured TCB, not a peer-identity fallback. The role can
signal its actual child after drop without a DAC/ptrace capability. FD3 is the
unbound inherited private stream; FD4 is the original sealed root:root0600
zero-link bootstrap. The helper verifies the actual parent SO_PEERCRED/PIDFD,
retains that relationship and arms an absolute BOOTTIME SIGKILL timer after
exec. No writable seed/file descriptors are inherited or returned.

The actual root launcher still must bound interpreter startup before that
post-exec timer is armed, NSM's synchronous ioctl and all parent shutdown/reap
paths. No timer-renewal, guaranteed Drop cleanup, exec-confinement or whole
process zeroization claim is made. Independently admitted native seccomp must
permit these exact startup NSM/vsock/owned-channel/reap operations; this slice
does not relax any existing filter or serving capability.

## Parent and remaining gates

`native_shadow_key_kms_parent.py` accepts one CID/request and invokes only the
existing fixed AWS KMS Decrypt adapter with Recipient, original key ID/blob/
context, no plaintext fallback. Its separate root:root0400 protected config6
pins entire transport and exact binding digest. Its local COSE parse establishes
correlation only. Real KMS PKI/PCR/key policy and actual TLS/runtime verification
remain independent deployment prerequisites. The enclave's full KEK digest and
AES-GCM authentication refuse parent-selected replacement material. Parent
timeout does not translate its clock into guest authority.

This batch supplies a real ciphertext producer/consumer seam, not provisioning
authorization for arbitrary seeds. The independent key inventory, actual sealed
secret inputs, KMS ciphertext/policy, signatures, release/boot/nonce originals,
and pinned images still must come from genuine external provisioning. The
distinct native launcher/serving construction, fixed-peer inspection, external
verifier result transport, receipt/proof endpoint producers and same-origin
lifetime/settlement joins remain required. Builds, negative crypto/protocol
tests, real Nitro/KMS interoperability and pilot runtime evidence are deferred.
