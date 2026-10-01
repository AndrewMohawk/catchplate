# Local authority installation

These are executable setup components for the synthetic, non-TEE pilot, not an
installed authority or a working application claim. Host root remains trusted.
Private keys arrive as protected sealed descriptors, never command-line values.
Original approvals and deadlines remain in force; failure preserves partial
effects and does not authorize an automatic retry.

The [focused results](production-status.md) resolve 46 controls across the
initial and three-case correction snapshots. No full suite, image rebuild,
successful signed install or live policy transition is claimed.

## Connected components

| Command | Actual effect | Still required beforehand |
| --- | --- | --- |
| [`local_snapshot.py`](../scripts/authority/local_snapshot.py) | Measures an exact frozen CAS tree and signs the existing snapshot receipt | Already frozen root-owned tree named by its digest, protected approval/trust, authorized snapshot-verifier key |
| [`local_artifacts.py`](../scripts/authority/local_artifacts.py) | Remeasures source, authenticates upstream evidence, signs package/generation and artifact-verification originals | Unsigned package, genuine snapshot/closure/provenance/witness originals, independently selected trust and purpose-specific keys |
| [`local_install.py`](../scripts/authority/local_install.py) | Copies and verifies files, applies fs-verity/immutability, publishes an absent generation and its signed receipt | Genuine signed package and verification receipt, protected current trust/high-water, authorized provisioner key, capable destination |
| [`commission_development_policy.py`](../scripts/commission_development_policy.py) | Calls genuine policy preparation, retains its actual result, then calls finalization after independently supplied audit and WebAuthn evidence | Admitted authority runtime, exact signed demo policy, real enrolled operator and independently produced/registered evidence |

Use each command's `--help` for its closed FD/hash interface. There is no arbitrary
command, key creation, SQL authority insertion, activation shortcut or synthetic
success result. The snapshot issuer does **not** freeze a mutable checkout or
claim complete import/native closure. The artifact signer does **not** originate
missing upstream evidence. The installer does **not** advance the external
witness/high-water or activate the generation.

The local installation plan/receipt have explicit local schema names. Native
plans remain native-only. The local installer freezes descendants, performs the
no-replace generation rename, then freezes the published root and fsyncs it.
Freezing the staging root before renaming would prevent that operation.

## Actual filesystem constraint

Two tiny new task-owned files were checked on this host with the Linux UAPI:

| Filesystem | Inode-generation ioctl | Enable/measure fs-verity |
| --- | --- | --- |
| NVMe scratch, ext4 `/dev/md0` | Succeeded | Both refused with `EOPNOTSUPP` (95) |
| Home/root, ext4 LVM volume | Succeeded | Both refused with `EOPNOTSUPP` (95) |

Kernel `6.8.0-138-generic` enables `CONFIG_FS_VERITY`; the attempted filesystems
still did not support these operations. The installer must refuse that result.
The [kernel documentation](https://docs.kernel.org/filesystems/fsverity.html)
describes the filesystem support requirement and the read-only-FD enable API.
No shared filesystem feature, mount option or immutable flag was changed.

Deployment needs a **task-dedicated, fs-verity-capable filesystem** and its scoped
root installer privileges, including immutable-flag capability. Do not enable
features on a shared homelab filesystem or grant a general privileged container
just to pass commissioning. There is no successful immutable install yet.

## Evidence producers still missing

The new snapshot issuer removes one source gap, but source review did not find
executable producers for all of these existing contracts:

- Complete Python/native closure analysis and its required actual rootfs
  verity/pivot enforcement evidence.
- Genuine artifact provenance and persistent artifact-witness checkpoint
  issuance. Runtime replay witness service is a different protocol.
- Policy-signature verification and audit-inclusion evidence issuance and
  registration. The PostgreSQL outbox and Merkle audit-anchor sink do not
  produce the required policy-authority inclusion receipt.

These are implementation/provisioning gaps, not permission to sign invented
claims. The current closure contract still requires real rootfs enforcement even
when the package selects `trusted-host-local`.

Commissioning now keeps one foreground owner from preparation to finalization.
Its four input/output descriptors must already be in the runtime trust inventory.
The independent supervisor fills and fully seals the initially empty late
finalization memfd only after obtaining real inclusion and fresh bound WebAuthn
approval. Both operations use the existing runtime client and original limits;
the caller cannot substitute a saved preparation-result JSON.

Development startup itself permits no active policy. Existing registration and
challenge routes can therefore support first-policy enrollment after authority
startup, but still require real admitted enrollment and evidence owners. No live
enrollment or policy commissioning is established by these source changes.

After actual installation, follow [local startup](trusted-host-local-startup.md)
and [pilot commissioning](pilot-commissioning.md), then prove the application's
credential replacement, denial and redaction before handing over a pilot URL.
