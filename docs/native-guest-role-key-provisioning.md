# Boot-time encrypted guest role keys

This source path provisions the seven guest services before their startup and
before the gate's final privilege drop. It is separate from the serving
`EnclaveRuntimeIdentity` and post-drop secret broker: neither can authorize or
supply keys that must already exist when the guest roles start.

The existing `StartedGuestCohort::launch` is unchanged. The additive
`launch_with_role_keys(configuration, provisioner, prepared, inspector)` takes
the real retained `Prepared` and inspector owners, admits all seven original
signed deliveries, and provisions keys before public-artifact preparation or
the first role child. [Explicit startup v12](native-role-key-startup.md) supplies
the actual cold caller join; this constructor does not auto-select from missing
files or environment.

## Authority and exact originals

`GuestRoleKeyProvisionerConfiguration::validate` accepts the closed eight-field
`serverware.nativeGuestRoleKeyProvisioner/v1` configuration: `apiVersion`,
`helperImage`, `kmsParentPort`, `kmsKeyId`, `ciphertextBlobSha256`,
`encryptionContext`, `kekSha256`, and `encryptedInventory`. Its paired schema is
[`configuration`](../schemas/native-guest-role-key-provisioner.v1.schema.json#/$defs/configuration).
The helper image and encrypted-inventory path are source-fixed; all full hashes
must be nonzero. The KMS encryption context requires the distinct
`serverwarePurpose: guest-role-keys/v1` value. The new helper image is not the
serving broker's image, entrypoint, phase, or key assignment.

Each `PreparedRoleDelivery` authenticates the existing configuration/delivery
originals, current kernel boot, signed role scope, and original startup window.
Its new public-only projection supplies exact logical-role, UID/GID, path,
seed SHA-256 and public-key SHA-256 commitments. Root does not read a seed to
produce that projection. All seven deliveries must share the configuration,
generation, trust checkpoint and boot. The operation deadline is the minimum
of those original deadlines and the actual `Prepared` deadline, never a fresh
helper interval.

The canonical inventory binds those originals and every seed slot, ordered by
the fixed service-role order and logical role. It contains seven to 64 keys,
with distinct paths and seven distinct service UIDs. Helper UID/GID 64989 must
not collide with any signed service UID/GID; inspector 64990 and gate 65534 are
also excluded from key ownership. The signed role assignments, public keys,
current-boot deliveries and independent KMS permission remain prerequisites;
neither this inventory nor a schema validation grants them.

## One pre-startup owner

The root owner opens the independently pinned encrypted inventory and checks
its exact canonical bytes. It then reserves the fixed helper descriptors
64 through 127, refusing an already-occupied required descriptor before file
creation. Each output is a new `O_EXCL | O_NOFOLLOW` file at an admitted seed
path. Protected ancestors and the immediate role-owned 0700 directory must
already exist. The leaf is role-owned 0400, regular, single-link and empty;
its creation and parent directory are flushed before the helper can receive
the writable descriptor. Root keeps only an `O_PATH` identity descriptor after
handoff, not a readable seed descriptor.

The helper is launched from a separately hashed, sealed-memfd, read-only
SquashFS root and held interpreter FD. Its sole entrypoint is
`/opt/serverware/serverware/native_role_key_provisioner.py`. The child gets
only its unnamed Unix channel and exact write-only output FDs, no inherited
environment or general output-path API. It drops to UID/GID 64989, clears
supplementary groups/capabilities, sets no-new-privileges and non-dumpability,
and retains parent-death and bounded resource limits. The actual process,
pidfd, channel, image and original deadline remain owned through completion.

Inside that child, a new RSA-2048 recipient key and nonce are generated. The
root uses the actual pre-drop `NsmDeviceV1` to attest only that public recipient
and the purpose-separated commitment to the complete request. Request fields
include the common configuration, complete delivery-inventory digest, exact
provisioner configuration and image digests, boot and original deadline. This
does not construct an `EnclaveRuntimeIdentity` or label a decoded quote as
verified evidence.

`native_role_key_kms_parent.py` accepts one connection and performs at most one
fixed KMS Decrypt call. Its local COSE checks establish correlation only. KMS
must independently admit the genuine Recipient attestation and separately
provisioned key/context. The parent returns only `CiphertextForRecipient` and
exact request/ciphertext commitments, never KMS `Plaintext`. Its separate
30-second transport cap cannot extend the enclave's BOOTTIME deadline.

The helper uses the existing strict RSA-OAEP-SHA256/CMS primitive solely to
recover a 32-byte KEK; no broker mutation or signing authority is reused. It
checks the independently pinned full KEK hash, then AES-256-GCM authenticates
the encrypted seed inventory under the purpose domain plus exact public
inventory bytes. It verifies every seed hash and derived raw Ed25519 public
key hash before the first write. Only then does it write exactly 32 bytes to
each admitted descriptor, flush and close it. No seed or KEK appears in a
channel response.

The root requires both the exact completion frame and the actual successful
child exit within the original window, then checks output inode/owner/mode/
size and flushes every containing directory. A claimed completion frame is
not sufficient. The completed owner is retained with the cohort; serving
checks retain its original association and file identities. Actual guest
role readers still reopen and verify their own exact key originals after
their UID drop. Root's file-length observation is not a replacement for those
key-authentication checks.

## Failure and recovery boundary

Any existing seed name, malformed inventory, assignment mismatch, quote/KMS
uncertainty, partial write, missing/late child exit, or failed directory flush
refuses cohort startup. Partial output names and bytes are retained. Neither
the owner nor its destructors unlink, repair, adopt, rename over, or retry
them. A subsequent attempt encounters the existing slot and refuses, even if
the bytes happen to be complete. There is no completed-file recovery or
restart authority in this profile.

Failure requests termination and attempts to reap the actual child only
within the original deadline; an overdue child is not reported as timely
reaped. The existing NSM ioctl itself has driver blocking behavior, so this
source does not claim a hard wall-clock syscall watchdog. No timeout proves
that KMS was not contacted, and no timeout permits another recipient request.
The one-shot parent adapter also has no automatic reconnect or retry loop.

## Material preparation and source status

`prepare_native_role_keys.py` is an offline material producer for an
independently trusted provisioning station, **not the Nitro parent**. It reads
root-protected assigned seeds/KEK, verifies the complete public commitments,
and creates only the encrypted inventory with `O_EXCL` and file/directory
durability. It cannot sign a delivery, provision KMS, extend a boot interval,
or turn arbitrary key material into an admitted assignment. Plaintext keys
must not be copied to the Nitro parent; the parent receives ciphertext only.
Python immutable-object erasure is not claimed.

The separate `package_native_role_key_runtime.py` builds a closed, hash-locked
runtime with only the helper, contract, pure CMS dependency and their fixed
Python/crypto closure. The production Dockerfile has an explicit artifact
stage and copies the read-only helper image/manifest into the EIF filesystem;
no key material or encrypted inventory is baked into that image. The broker's
existing build purpose remains its default and retains its own image path.

Current-boot assignment/delivery issuance, KMS key and recipient policy,
encrypted inventory delivery, role-private directories, final cold-profile
selection and runtime acceptance must be supplied and verified independently.
Cross-boot reassignment/recovery is not implemented by this one-shot profile.
This batch is source-only: no build, NSM/KMS call, provisioning, cloud action,
key release, guest launch or runtime acceptance was performed.
