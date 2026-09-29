# Independent native shadow Nitro verifier producer

This source implements a one-shot external verifier and the closed Rust result
decoder. It verifies actual original COSE evidence before producing the existing
custody attestation-result signature. It neither self-generates a verifier key
nor replaces native shadow launcher, fixed-peer inspection, encrypted role-key
delivery or receipt/proof servers. No execution or real Nitro test is claimed.

## Actual inputs and authority

The fixed entrypoint is `scripts/verify_native_shadow_custody.py`. It accepts **no
arguments or environment-based policy/key selection**. The independently managed
launcher must use a pinned Python 3.11/module/cryptography closure with `-I`
isolated imports (enforced before application imports), already at the independently configured verifier UID/GID (distinct from
the guest custody role and reserved gate/helper identities), empty supplementary
groups and no effective/permitted/inheritable/ambient capabilities. This source
sets/verifies nondumpability, no-new-privileges and zero core limits before any
seed read. It does not claim Python cannot exec or that its memory is zeroized.

Inherited originals are fixed, disjoint, and retained until the one-shot attempt
finishes:

| FD | Actual original |
| --- | --- |
| 3 | Read-only root:root `0400`, singly linked regular file, at most 512 KiB, matching the protected named `/etc/serverware/native-shadow-nitro-verifier.json` through retained root-owned non-writable ancestor directories. A sealed caller copy or another path is not accepted. |
| 4 | Final verifier UID:GID `0600`, zero-link memfd, exactly 32 bytes, all four immutable seals; independently provisioned **CustodyAttestationVerifier** Ed25519 seed. |
| 5 | Separate final-verifier-UID:GID-owned `0600`, zero-link fully sealed memfd, at most 128 KiB; exact canonical original `nativeShadowRoleKeyEvidence/v1` (seven fields). |

The configuration is exact 12 fields in
[`native-shadow-nitro-verifier.v1.schema.json`](../schemas/native-shadow-nitro-verifier.v1.schema.json).
It independently pins the complete public 18-role set; original new-purpose
SupervisorCapability-signed key authorization; exact expected 15-field native key
statement/guest binding; current trust checkpoint; complete PCR/EIF/module/PKI/age
expectations; explicit application-level revocation snapshot; expected existing
TEE-mode commitments; and result maximum age. The request supplies **none** of
these authorities. Every actual public key must reproduce its assigned SPKI and
role-independent public-material hash; the three identity sets are distinct.

`operation` is the original external verifier host's boot/time-namespace/absolute
BOOTTIME interval, at most 30 seconds. It is independently provisioned, never
generated from the input request or reset per phase. The verifier retains its own
actual PIDFD/start/UID/GID and all originals. Its wall clock must not move backward.
The guest's different original signed startup/lifetime domain is quoted and
matched exactly; the genuine guest owner independently checks that domain when
accepting the result. No conversion of an external host's BOOTTIME into the
guest's allowance is performed.

The fixed protected public configuration must itself be installed by the actual
independent policy/trust owner from current approved assignment, checkpoint,
application revocation, measured closure and guest challenge originals. It is
not inferred from a submitted quote. That deployment/provisioning authority and
the external verifier's trusted clock/runtime are prerequisites, not generated
by this adapter. The seed's actual derived public key must match the configured
external verifier role before the only fixed-purpose signature is made.

## Genuine verification and computed commitments

The adapter validates the unchanged C8 key authorization's separate signature
domain, original nonce, current checkpoint, full18 root and ordered local subset.
It verifies **each actual local possession signature** over the source-fixed
`[role,keyId,statementSha256]` tuple, including exact public material. It derives
the original `user_data`, local-root `public_key` commitment and nonce framing
described in [native-shadow-role-keys.md](native-shadow-role-keys.md).

It then calls the actual cryptographic primitive
`scripts.verify_nitro_tee._verify_nitro_document_common` with the original COSE,
`claims=None`, exact user data/challenge, complete independently configured PCR
map/EIF/module/root-PKI/age inputs and `native_profile=True`. The returned verified
payload, issued-at time, verified PCR map, leaf and trusted root are the source of
the result. The original COSE public-key field must equal the local-root
commitment. No role-4 holder wrapper, caller verdict or pre-parsed certificate
summary substitutes for this invocation.

Let `C` be the existing ASCII/integer canonical JSON codec and `F(domain,parts)`
be the existing `hash_domain_frames`: SHA256 of `domain || NUL`, followed by each
part's unsigned big-endian 64-bit byte length and exact bytes. The new explicit
native shadow profile computes:

- `measurementSha256 = F("serverware.nativeShadowNitroMeasurement/v1", [C([verified module_id, verified PCR map, independently expected EIF, expected worker executable SHA, native closure SHA, structurally verified seccomp SHA])])`.
- `endorsementEvidenceSha256 = F("serverware.nativeShadowNitroEndorsementEvidence/v1", [C([base64url(original leaf DER), ordered base64url(original verified cabundle DER)])])`.
- `endorsementRootSha256 = SHA256(actual trusted-root DER)`.
- `collateralPolicySha256 = F("serverware.nativeShadowNitroCollateralPolicy/v1", [C(exact configured nitro object)])`.
- `revocationSourceSha256 = SHA256(C(exact current application-revocation object))`.
- `collateralRevocationRootSha256 = F("serverware.nativeShadowNitroApplicationRevocationRoot/v1", [C([actual snapshot generation, sorted denied-certificate SHA list])])`.

The existing assignment's expected measurement/root/collateral/revocation pins
must independently select these **new** profile bytes. The adapter compares them
with its computations; it does not copy a declared hash into a successful result
without verifying its source. A native closure hash is never reinterpreted as a
legacy fs-verity/IMA manifest. A quote plus these bindings still does not provide
kernel process inspection; the genuine closure owner, admitted measured TCB,
fixed-peer inspection and launcher/lifetime joins remain separate requirements.

AWS's native certificate profile in the existing verifier requires an empty CRL
inventory and explicitly provides **no vendor revocation proof**. Accordingly,
this profile is named `application-denial-inventory-no-vendor-crl-v1`. Its actual
current independently provisioned denial inventory is checked against every
verified leaf/bundle/root certificate. It does not invent an AWS CRL. Both the
application snapshot and trust checkpoint must be at most 300 seconds old.

## Exact result and genuine guest consumer

The output is canonical ASCII without a trailing newline, at most 32 KiB:
`{apiVersion:"serverware.nativeShadowNitroVerifierResult/v1", result:<exact22>}`.
The 22 result fields match `CustodyTeeAttestationVerifierResultWire`. Its signature
retains **exactly** the existing canonical tuple
`["serverware.policyShadowCustodyTeeAttestationResult/v1", tuple9, tuple12]` and
`serverware.policyShadowCustodyAttestationVerifier/v1` signature domain/preimage.
The new outer label is only closed transport framing, not a new success authority.

The result expires no later than the original authorization, app-revocation,
trust-checkpoint freshness, quote age, every verified certificate's expiry,
original external BOOTTIME residual and configured maximum result age. Seed
access/signing is one-shot; all real originals, identity, time and authorization
are checked again after signing. Late/changed results are not emitted. Python
temporary seed-buffer overwrite is best effort; cryptography/private object and
immutable Python allocation zeroization is **not** claimed. The process must exit.

`NativeCustodyKeys::accept_verifier_original(raw,trust,time)` is the actual Rust
consumer. It enforces exact closed fields/label/canonical bytes, reconstructs the
existing data-only result with `from_verifier_with_execution_closure`, then calls
the already retained native key owner's verifier path. The retained actual quote
hash, complete assigned root, independent current verifier signature and native
closure/configuration/current trust must match. Any failed decoding/admission
poisons that real owner. No JSON-to-owner or JSON-to-verified-attestation shortcut
is introduced.

The source still needs a real independently provisioned external launcher and
public-result transport to that guest consumer, with original lifetime watchdog
containment and installed interpreter/PKI dependencies. Before/after deadline
checks are not proof of bounded termination. Encrypted KMS Recipient role-key
delivery, actual receipt/proof endpoint servers, native guest fixed-peer/lifetime
settlement, build packaging and real positive/negative runtime verification stay
open. Schema validity or a signed result alone is not deployment/pilot approval.
