# Native shadow-role key ownership and original NSM evidence

This is a source-only, first local-subset ownership profile. It supplies actual
retained role keys, fixed key-possession signatures, and a real NSM ioctl producer.
It does **not** implement encrypted key provisioning, the independent verifier
service, receipt/proof servers, or a complete measured shadow service launcher.
Nothing here changes a `TrustedHostNoTee` report into a measured report.

## Authority and keys

The closed `serverware.nativeShadowRoleKeys/v1` configuration has exactly two
fields: `apiVersion` and `authorization`. Its authorization has `payload` and
`signature`; the payload is the exact 18-field
`serverware.nativeShadowRoleKeyAssignment/v1` object in
[`native-shadow-role-keys.v1.schema.json`](../schemas/native-shadow-role-keys.v1.schema.json).
It fixes profile `preassigned-final-role-originals-v1`, purpose
`shadow-role-key-possession`, the verified policy assignment, native closure,
actual signed guest delivery/configuration/boot/UID/GID/window, full key-set root,
explicit local roles, original nonzero 32-byte challenge, current trust checkpoint,
time interval, and independent supervisor-capability signer.

This is a **new signature domain**, not an old supervisor capability or a
response-v2 role assignment. The actual current `CustodySupervisorCapability`
key, SPKI, public material, revocation checkpoint and assignment scope must match.
The signature input is the existing policy-shadow `signature_preimage`:

```
serverware.signedEnvelope/v1 || NUL || purpose-domain || NUL ||
serverware.canonicalJson/ascii-integer-v1 || NUL || canonical-payload
```

The authorization purpose-domain is
`serverware.nativeShadowRoleKeyAssignment.signature/v1`. Canonical payload bytes
use the existing ASCII/integer canonicalizer: sorted ASCII object keys, no floats,
signed-64-bit integer bound, existing string escaping, and no trailing newline.
Signatures are canonical unpadded base64url of the raw 64 Ed25519 bytes, without a
prefix. This does not change any existing signature recipe.

The full root covers the existing 18 production authorities. The local subset is
one to 16 keys, strictly ordered by the actual `AuthorityRole` declaration:

- Ten receipt roles: ingress admission, unavailable ingress, dispatch barrier,
  terminal append, ledger append, spool compaction, active-effect barrier,
  active-effect commit, publication reconciliation, activation publication.
- Six support roles: result envelope, store response, signer response, retrieval
  response, trusted-time response, provider response.
- The two external roles, attestation verifier and supervisor capability, remain
  in the full independently assigned public root but have **no local seed slot**.

Each local role uses the fixed C9 credential name `shadow-key-` followed by its
complete kebab-case role name, e.g. `shadow-key-custody-ingress-admission`.
These are not the five trusted-host handshake keys. Every selected original must
already be present in the independently signed C9 inventory, length 32, with an
actual signing-public-key/key-ID association. Content is read only after the real
permanent final-role drop. The derived Ed25519 public key, canonical DER SPKI hash,
public-material hash and key ID must all match the independent full assignment.
Seeds are placed in zeroizing temporary buffers; the owned `SigningKey` is never
exported, cloned through this API, or passed to a raw signing RPC.

Both full and local roots use the existing `production_custody_key_set_root`:
source-ordered bindings `(role,keyId,keySpkiSha256,keyMaterialSha256)`, the existing
`serverware.policyShadowCustodyAssertedKey/v1` framed leaf hash, then the existing
sequence-indexed policy-shadow Merkle recipe. A local root is a subset commitment,
not an assertion that this process possesses all 18 private keys.

## Actual owner and startup order

The source-private, non-serializable API is:

1. `PreparedNativeCustodyKeys::open(configuration, &VerifiedAssignment, trust,
   time, &PreparedGuestServiceDelivery)` while the **same actual C9 root
   preparation owner** is live. It retains the same private delivery `Arc`,
   original checkpoint and genuine root-opened NSM device originals; it reads no
   seed. The actual native closure must be prepared from that same delivery.
2. The future launcher performs the real root switch and irreversible final-role
   drop, then `PreparedNativeCustodyClosure::bind_current_process`. Its actual
   executable/image/BPF/config owners are prerequisites, not JSON claims.
3. Construct the actual `ProductionCustodyConfiguration` with that native closure
   and the existing real operation driver/backends/limits. Then
   `PreparedNativeCustodyKeys::bind(&closure, &configuration, trust, time)` proves
   identity of the retained C9 origin, reads the assigned local seeds, and consumes
   the prepared NSM into a **new final-identity** device owner in the same process.
   No root `Process` snapshot is relabelled as final credentials.
4. `NativeCustodyKeys::quote(trust,time)` makes one fixed-purpose attempt. It
   retains the resulting public original evidence. There is no retry/reset or
   arbitrary statement, user-data, key, ioctl, signing or descriptor API.
5. Only `accept_verifier_result(actual_signed_result,trust,time)` may activate its
   retained production configuration. It first compares the result's quote hash
   with the **actual retained document** and the complete assigned key-set root,
   then invokes the unchanged independent TEE-result verifier. Every access to
   `admitted_configuration` revalidates current trust, actual closure/delivery,
   original process/boot/lifetime, and active attestation. A wire object cannot
   reconstruct this owner.

The NSM mechanism opens `/dev` and its real `nsm` device before the root switch.
Afterwards it validates those retained descriptors, their identities/flags and
the device entry relative to the **held original directory**, never a replacement
`/dev` inside the new image. Ordinary gate NSM still additionally checks its named
`/dev` path; its legacy behavior is preserved. The dedicated shadow mechanism is
not authority by itself: only the above actual C9/closure owner supplies it.

All phases narrow the original signed C9 startup/lifetime window; none creates a
fresh timeout. Quoting and verifier-result acceptance must finish inside the
original startup window. Owner checks during use retain the original lifetime.
The actual installed BPF must permit the required fixed NSM/read/check operations;
the profile neither changes BPF nor claims an untested policy permits them.

## Fixed quote and possession framing

The evidence is exact seven fields; its statement is exact 15 fields and repeats
the new purpose, assignment, full/local roots, actual local public keys, closure,
configuration, guest binding and independently assigned challenge. Each local key
signs only the canonical tuple `[role,keyId,statementSha256]` under
`serverware.nativeShadowRoleKeyPossession.signature/v1`, using the same signature
preimage wrapper above. The evidence retains the original ordered signatures.

NSM receives exactly:

```
user_data = b"serverware/native-shadow-role-key-evidence/v1\0"
            || raw32(statementSHA256) || raw32(full18KeySetRoot)
            || raw32(localKeySetRoot) || raw32(possessionArraySHA256)
public_key = raw32(localKeySetRoot)
nonce = original independently assigned raw32 challenge
```

`public_key` is explicitly a commitment, **not an Ed25519/RSA/KMS recipient key**.
The real ioctl's original document and exact inputs are preserved in canonical
unpadded base64url. Before and after checks do not turn NSM's synchronous ioctl
into a cancellable operation. A source-owned launcher/watchdog with the original
absolute lifetime is still mandatory; delayed ioctl completion is refused, not
reported as timely cancellation.

## Required continuations, not completed by this source slice

1. **Encrypted provisioning:** implement purpose-specific KMS Recipient delivery
   into this same actual role process, bound to its assigned role/closure/boot,
   independent key material and original deadline. The present C9 protected seed
   inputs are a finite ownership seam, not an encrypted delivery producer. Never
   bake seeds into EIF/configuration, send raw keys through a parent RPC, or alias
   response-v2 key provisioning or the gate's generic KEK handling.
2. **Independent verifier adapter:** the existing genuine cryptographic primitive
   is `scripts.verify_nitro_tee._verify_nitro_document_common`. With `claims=None`,
   exact `expected_user_data_bytes`, original challenge, independently admitted
   PCR/EIF/module/PKI/time expectations and `native_profile=True`, it returns the
   verified payload, issued-at seconds, verified PCR map, leaf X.509 certificate
   and trusted root certificate. A dedicated shadow adapter must verify this new
   authorization, original framing, every actual local possession signature,
   full18/local roots and native closure purpose; then invoke that primitive and
   check `public_key`. It must produce the existing independently signed
   `CustodyTeeAttestationVerifierResultWire` under the externally held
   `CustodyAttestationVerifier` key with genuine collateral/measurement bindings.
   The current result constructor/consumer does **not** implement that adapter.
   Holder role-4 evidence, legacy closure digests and old result purposes must not
   be relabelled. In particular, a quoted local root alone proves neither PCR
   acceptance nor full-key possession nor the exact process executable.
3. **Real endpoint producers:** the ten `ProductionParentSignerEndpointConfigV4`
   receipt endpoints and four production proof endpoint families (trusted time,
   persistence, retrieval, generation-install envelope) still need genuine
   servers. An initial result-envelope server must consume the actual
   generation-install context and transition originals; a typed signing-preimage
   helper alone is not effect/receipt authority. No generic `sign(raw_bytes)` or
   successful receipt response exists in this slice.
4. **Launcher and deployment:** connect actual preparation/root switch/final-role
   identity, fixed-peer inspection, signed result transport, real endpoint owners,
   same-origin lifetime/settlement and watchdog. Produce and independently admit
   the fixed native closure image and its actual kernel/BPF/runtime dependencies.
   No outer startup selector or serving caller is added here. Builds, real Nitro
   attestation/negative checks and deployment acceptance remain unperformed.

The schema describes public data only. The actual code additionally enforces
canonical encodings, source ordering, signatures, original files/process owners,
trust/revocation, same-origin associations and time bounds; schema validity is not
key custody, verified attestation, service readiness or pilot authorization.
