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
| [`local_keys.py`](../scripts/authority/local_keys.py) | Creates the fixed 20 distinct local Ed25519 key pairs and public inventory without replacement | Exact empty root0700 destination and protected bounded approval; local key creation is not a trust grant |
| [`local_database_credentials.py`](../scripts/authority/local_database_credentials.py) | Issues actual CA/server/client TLS staging originals and unapplied PostgreSQL fragments | Exact existing role selection, owners, DNS/network, empty private output and original validity; no DB connection or installed-credential claim |
| [`local_trust.py`](../scripts/authority/local_trust.py) | Signs initial artifact key authorization/revocation documents under the explicitly pinned local root | Actual13-purpose public roster, exact initial trust, actual empty witness directory and protected root signing key |
| [`local_configuration.py`](../scripts/authority/local_configuration.py) | Signs exact Service6 or ReplayWitness4 configuration payloads | Actual role manifests, TLS issuance originals, generation intent and distinct configuration root; witness binds the already signed service payload |
| [`local_snapshot.py`](../scripts/authority/local_snapshot.py) | Measures an exact frozen CAS tree and signs the existing snapshot receipt | Already frozen root-owned tree named by its digest, protected approval/trust, authorized snapshot-verifier key |
| [`local_provenance.py`](../scripts/authority/local_provenance.py) | Verifies actual clean Git/archive/report/OCI associations and signs a detached local observation | Exact compatible clean build report, retained source/OCI objects, frozen tree and authorized provenance key; this is not build-execution or SLSA proof |
| [`local_composition.py`](../scripts/authority/local_composition.py) | Observes separately selected clean source and retained runtime OCI inputs | Exact source/archive/commit, OCI objects and canonical composition declaration; no source-to-image build claim |
| [`local_closure.py`](../scripts/authority/local_closure.py) | Measures the selected Python/native roster and actual bounded ELF metadata | Genuine snapshot and frozen tree; local-only assurance, not production complete closure |
| [`local_artifact_witness.py`](../scripts/authority/local_artifact_witness.py) | Verifies persistent signed history and appends the actual generation/checkpoint under an exclusive lock | Pinned root0700 store, external high-water, authorized witness key and exact expected prior head; no external trust advance |
| [`assemble_local_package.py`](../scripts/authority/assemble_local_package.py) | Derives the real pre-witness generation core, then assembles the unsigned package with the actual checkpoint | Genuine signed configs/trust and measured originals; fixed core/package modes, no authority issuance |
| [`local_artifacts.py`](../scripts/authority/local_artifacts.py) | Remeasures source, authenticates upstream evidence, signs package/generation and artifact-verification originals | Unsigned package, genuine snapshot/closure/provenance/witness originals, independently selected trust and purpose-specific keys |
| [`local_install.py`](../scripts/authority/local_install.py) | Full-copy mode copies and seals files; explicit prepared-static mode adopts verified sealed static files and copies fresh files, then publishes an absent generation and its signed receipt | Genuine signed package and verification receipt, protected current trust/high-water, authorized provisioner key, capable destination; prepared mode additionally requires the exact selected static subtree |
| [`commission_development_policy.py`](../scripts/commission_development_policy.py) | Calls genuine policy preparation, retains its actual result, then calls finalization after independently supplied audit and WebAuthn evidence | Admitted authority runtime, exact signed demo policy, real enrolled operator and independently produced/registered evidence |
| [`local_audit_inclusion.py`](../scripts/authority/local_audit_inclusion.py) | Reads actual committed metadata/audit snapshots and signs first-genesis inclusion under its scoped key | Genuine audited preparation, current signer and separately provisioned fixed reader grants/authentication; first inclusion only |

Use each command's `--help` for its closed FD/hash interface. Key creation is
limited to its fixed roster; there is no arbitrary command, SQL authority
insertion, activation shortcut or synthetic success result. The snapshot issuer
does **not** freeze a mutable checkout or
claim complete import/native closure. The artifact signer does **not** originate
missing upstream evidence. The installer does **not** advance the external
witness/high-water or activate the generation.

The local installation plan/receipt have explicit local schema names. Native
plans remain native-only. The local installer freezes descendants, performs the
no-replace generation rename, then freezes the published root and fsyncs it.
Freezing the staging root before renaming would prevent that operation.

## Prepared-static local installation

The source now implements an explicit second installation mode. Configuration
`serverware.authorityTrustedHostLocalInstallation/v2` selects local plan
`serverware.authorityTrustedHostLocalProvisioningPlan/v3` and local receipt
`serverware.authorityTrustedHostLocalProvisioningReceipt/v2`. The original
configuration v1, local plan v2 and local receipt v1 retain their full-copy
behavior and wire formats. Native/production provisioning is not admitted by
the new local mode; command-line descriptors and the installation result shape
are unchanged.

Configuration v2 adds one closed `preparedStatic` object: `relativePath` must
be the literal `prepared-static`; `device`, `inode` and `generation` select the
actual subtree; `freshPaths` is a sorted, unique, nonempty proper subset of the
current signed package's file paths. There is no separate manifest authority or
saved installation receipt. The signed package remains the complete source of
expected content and metadata. Every other package entry must already exist in
the prepared subtree, and its exact files and implied directories must contain
no extras or missing members.

The COMMON pilot prepares independent sealed static leaves once in its unsigned
base image, then uses a fresh session COW. It selects these three late files for
fresh copying: `configurations/authority-service.json`,
`configurations/witness.json`, and `sbom/selected-files.spdx.json`. This split
includes the exact selected pilot public keys and role manifests in the static
roster; it is not permission to reuse a different pilot's inputs or any prior
session authority. The SDK does not assume that every package has this same
three-file split.

Under the existing generation lock, the installer checks the selected root and
all static files before consuming the template. Directories must be private
root-owned mutable mode0700 directories on the destination's device and mount.
Leaves must be single-link regular files with the exact signed size, ownership
and mode, actual inode generation, immutable flag and kernel-enforced ext4
SHA-256 fs-verity. Actual bytes must match the signed content hash. A previously
observed sealed-content digest in the bounded process memo can satisfy that
hash observation; a cold standalone invocation reads the bytes. Claimed hashes
never populate the memo. Invalid prepared inputs are refused, not silently
converted to full-copy mode.

After validation, the installer publishes the fresh plan and Prepared state,
moves the selected subtree into private staging with `RENAME_NOREPLACE`, and
creates the selected fresh files through the existing exclusive copy,
readback, sealing and synchronization path. It then freezes descendants,
publishes the generation without replacement and freezes its root. Plan v3 and
receipt v2 record each entry's `adopt-prepared-static` or `copy-fresh` action;
the receipt records actual installed inode/verity identities and uses separate
v2 signing and digest domains. The selected prepared root's device, inode and
generation must survive publication. Trust commit independently reconstructs
the plan from the current verified package and selector, then checks the actual
installed tree and fresh signed receipt.

All existing package/verification signatures, current trust, signer authority,
boot/clock limits, high-water and publication checks remain fresh. A template
does not activate anything, advance trust, extend an approval or allow retry of
a partial installation. Tests and the root-owned KVM component probe for this
mode are in progress. It is not deployed to R97, no new end-to-end startup
improvement has been measured, and no production/native signed-install
acceptance is claimed. See [startup cost](native-pilot-startup-performance.md)
for the separate completed cache-test evidence and observed R97 timings.

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
access. Its read-only second boot also verifies persistence. That storage probe
did not install a Serverware authority. Installation needs separate guest
integration and scoped installer identities. Do not enable
features on a shared homelab filesystem or grant a general privileged container
just to pass commissioning. Filesystem support alone is not signed-package
installation acceptance.

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
- Fixed service/replay-witness configuration, initial-trust, key and TLS producers
  are now implemented. A real isolated guest run generated 20 signing keys,
  13 database client identities and signed initial trust; its read-only reboot
  confirmed persistence. These are private staging originals, not installed
  credentials or observed database sessions. The
  [assembly order](trusted-host-local-package-assembly.md) still requires actual
  role/configuration inputs and complete package installation.

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

The [late-admission handoff](trusted-host-local-admission.md) describes the real
manifest/certificate and RuntimeTrust issuers, explicit local root delegation,
same-kernel requirements and the still-missing five-role cohort producer.
