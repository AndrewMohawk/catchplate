# Local authority installation

These are executable setup components for the synthetic, non-TEE pilot, not an
installed authority or a working application claim. Host root remains trusted.
Private keys arrive as protected sealed descriptors, never command-line values.
Original approvals and deadlines remain in force; failure preserves partial
effects and does not authorize an automatic retry.

The [focused results](production-status.md) resolve 46 setup controls across the
initial and three-case correction snapshots, then31 witness/provenance/genesis
controls on frozen `96f70c6c`. No full suite, image rebuild,
successful signed install or live policy transition is claimed.
The additional roster/composition/audit/assembly batch resolves 36 controls
across `fee6a0ee` and a single test-only correction; see the exact result record.

## Connected components

| Command | Actual effect | Still required beforehand |
| --- | --- | --- |
| [`local_snapshot.py`](../scripts/authority/local_snapshot.py) | Measures an exact frozen CAS tree and signs the existing snapshot receipt | Already frozen root-owned tree named by its digest, protected approval/trust, authorized snapshot-verifier key |
| [`local_provenance.py`](../scripts/authority/local_provenance.py) | Verifies actual clean Git/archive/report/OCI associations and signs a detached local observation | Exact compatible clean build report, retained source/OCI objects, frozen tree and authorized provenance key; this is not build-execution or SLSA proof |
| [`local_composition.py`](../scripts/authority/local_composition.py) | Observes separately selected clean source and retained runtime OCI inputs | Exact source/archive/commit, OCI objects and canonical composition declaration; no source-to-image build claim |
| [`local_closure.py`](../scripts/authority/local_closure.py) | Measures the selected Python/native roster and actual bounded ELF metadata | Genuine snapshot and frozen tree; local-only assurance, not production complete closure |
| [`local_artifact_witness.py`](../scripts/authority/local_artifact_witness.py) | Verifies persistent signed history and appends the actual generation/checkpoint under an exclusive lock | Pinned root0700 store, external high-water, authorized witness key and exact expected prior head; no external trust advance |
| [`assemble_local_package.py`](../scripts/authority/assemble_local_package.py) | Derives the real pre-witness generation core, then assembles the unsigned package with the actual checkpoint | Genuine signed configs/trust and measured originals; fixed core/package modes, no authority issuance |
| [`local_artifacts.py`](../scripts/authority/local_artifacts.py) | Remeasures source, authenticates upstream evidence, signs package/generation and artifact-verification originals | Unsigned package, genuine snapshot/closure/provenance/witness originals, independently selected trust and purpose-specific keys |
| [`local_install.py`](../scripts/authority/local_install.py) | Copies and verifies files, applies fs-verity/immutability, publishes an absent generation and its signed receipt | Genuine signed package and verification receipt, protected current trust/high-water, authorized provisioner key, capable destination |
| [`commission_development_policy.py`](../scripts/commission_development_policy.py) | Calls genuine policy preparation, retains its actual result, then calls finalization after independently supplied audit and WebAuthn evidence | Admitted authority runtime, exact signed demo policy, real enrolled operator and independently produced/registered evidence |
| [`local_audit_inclusion.py`](../scripts/authority/local_audit_inclusion.py) | Reads actual committed metadata/audit snapshots and signs first-genesis inclusion under its scoped key | Genuine audited preparation, current signer and separately provisioned fixed reader grants/authentication; first inclusion only |

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

The subsequent [isolated KVM guest](trusted-host-local-storage.md) successfully
provides a task-dedicated fs-verity/immutable-capable filesystem without host-root
access. Its read-only second boot also verifies persistence. No Serverware
authority has been installed there yet. Deployment needs that separate guest
integration and its scoped installer identities. Do not enable
features on a shared homelab filesystem or grant a general privileged container
just to pass commissioning. There is no successful signed-package install yet.

## Evidence integration still pending

Snapshot, measured provenance/composition, local roster and persistent
artifact-witness producers are now implemented. They require genuine compatible
inputs and do not turn existing dirty engineering reports or raw rootfs exports
into clean OCI provenance. The separate [composition profile](trusted-host-local-composition.md)
describes clean source plus a retained runtime without a source-to-image claim.
The runtime replay witness is a separate protocol. Remaining integration:

- Original production complete-closure analysis and rootfs/pivot enforcement
  have no actual producer. The implemented local-only measured-roster profile
  claims neither exhaustive future dynamic loading nor rootfs isolation, and
  cannot satisfy production complete-closure admission.
- Genuine first-inclusion issuance is source-connected to separately read
  committed audit and metadata state. Its new restricted reader has an explicit
  absent-role-only provisioner; it is not applied to the live database yet.
  The existing Merkle audit-anchor receipt is not the policy-authority inclusion
  receipt, and co-location is not independent administration.
- Signed service/replay-witness configurations, trust authorization/revocation
  documents, role keys and actual DB/TLS credential originals still need genuine
  provisioning. The [assembly order](trusted-host-local-package-assembly.md)
  identifies these exact inputs; they are not inferred from image bytes.

Genesis v2 verifies the actual current policy signature and records verification
inside the real transaction. It avoids the legacy circular evidence/request
hash dependency and uses signed configuration pins for the audit store/signer.
Legacy operations remain unchanged. Real WebAuthn and independent inclusion
originals remain mandatory; no direct SQL authority insertion is added.

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
