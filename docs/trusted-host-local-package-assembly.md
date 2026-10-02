# Trusted-host-local package assembly

This is the real local package path, not a native/TEE release or an installed
pilot claim. The generator is already
`scripts/authority/generate_artifact_bundle.py`; the local fixed entrypoint is
`scripts/authority/assemble_local_package.py`. It adds only the missing
pre-checkpoint boundary and exact canonical pipe output. No fixture key,
placeholder checkpoint, predicted process identity or installation receipt is
an admissible prerequisite.

## Prepare the actual selected tree and authority inputs

Stage the actual interpreter, bootstrap source, application/import/native files,
public keys, role files, signed configurations, source/archive/Git and retained
OCI objects. The generator's `files` rows select exact `path,kind,mode,uid,gid`;
hashes and sizes come from the actual tree. A retained ordinary-Dockerfile image
does not automatically provide the selected runtime paths or prove derivation
from the selected clean source. The local composition issuer records only that
the source and runtime inputs were separately selected.

The connected role roster is `runtime,verifier,planner,planner-writer,issuer,
executor,witness`. Use the actual fixed UID/GID, mode, listener and credential
maps in `authority_launcher.py`, not arbitrary role names. The role rows retain
their exact files and independently selected credentials; local argv selects
the closed local argument profile, with actual invocation argv authenticated
later at the genuine parked process. There is no PID prediction in the package.

Generate the existing public operation/query documents from
`authority_contract.operation_contract_document()` and
`authority_primary_contract.source_query_manifest()` /
`source_authorization_manifest()`. Their source-fixed validators remain in use.
Supply exactly one signed authority-service configuration and one signed replay
witness configuration, genuine role credentials/TLS/session identities, and the
existing signed key-authorization/revocation documents. These configurations bind
`configuration_generation_binding` of the explicit generation intent, not the
final generation digest; the witness configuration can then bind the service
configuration's actual payload digest. This ordering has no generation-hash cycle.

## Provision the local signing and configuration originals

These fixed producers now exist under `scripts/authority/`. Run them before
freezing the complete selected tree, using separately approved protected inputs;
creating keys does not authorize their use or initialize trust implicitly.

1. `local_keys.py --approval-fd N --approval-sha256 sha256:HEX --directory-fd N`
   creates the fixed 20 distinct Ed25519 keys in the approved empty directory:
   13 artifact purposes, a separate configuration root and six role-response
   keys. Retain the actual `public-roster.json` and `inventory.json`; later
   signers require separately sealed copies of the selected private seeds.
2. `local_database_credentials.py --approval-fd N --approval-sha256 sha256:HEX
   --output-directory-fd N` stages real CA/server/client certificates, private
   keys, verify-full DSNs, scoped PostgreSQL fragments and public issuance
   originals. It requires explicit `metadata-bootstrap` process mode and `dev`
   release channel. It does not create roles, install credentials or connect to
   PostgreSQL. Configuration signing verifies the five service roles' literal
   issuance originals through `authority_local_database_credentials.issuance`;
   their digests are not backend-session observations.
3. `local_trust.py --approval-fd N --approval-sha256 sha256:HEX --trust-fd N
   --trust-sha256 sha256:HEX --public-keys-fd N --public-keys-sha256 sha256:HEX
   --witness-directory-fd N --signing-key-fd N` issues the existing first-generation
   key-authorization/revocation documents. Supply the actual public roster,
   independently pinned initial trust and genuinely empty witness directory;
   only the dedicated trust-document root signs these documents. This does not
   advance external trust/high-water state or append a witness checkpoint.
4. Run `local_configuration.py --approval-fd N --approval-sha256 sha256:HEX
   --signing-key-fd N` first for Service6, then for Witness4. Each approval fixes
   one exact payload, local generation intent, seven literal role originals,
   actual issuance originals, runtime public keys and original clocks. Use the
   distinct configuration root, not the artifact trust root or a response key.
   Witness4 requires the actual signed Service6 original and binds its payload
   digest. Outputs are the existing signed envelopes, canonical without newline.

Use `python -I -B` as root for these entrypoints. All directory publications are
no-overwrite; partial material remains on failure and must not be reset or
silently retried. Actual role names, intended credential owners and public pins
remain explicit selections. Static expectations are not measured process or
database identities, and local root custody is not independent administration.

## Real command order

Each fixed command's `--help` lists its exact FD/hash roster. Public originals
are protected root0400 files or sealed FDs. Private signing inputs are explicitly
supplied, purpose-authorized sealed32-byte FDs, never command-line key bytes.
Capture complete pipe output **and exit0** before admitting an original.

1. Finish the complete selected tree, then freeze it on the actual supported
   filesystem. Detached receipts cannot be added into the tree they measure.
2. `local_snapshot.py`: measure and sign the actual frozen snapshot.
3. `local_closure.py`: authenticate that snapshot and measure/sign the explicit
   local roster. This is not future dynamic-loader/rootfs completeness.
4. `local_composition.py`: authenticate/measure the clean source and retained OCI
   objects; sign the local input-composition reference, not a build claim.
5. `assemble_local_package.py --mode core --spec-fd N --spec-sha256 sha256:HEX
   --trust-fd N --trust-sha256 sha256:HEX`: use the existing generator input with
   the six original generation intent fields and **no** `witnessCheckpoint`.
   It measures the tree and derives the existing generation core.
6. `local_artifact_witness.py`: explicitly approve that exact core and perform the
   real durable initializer/append against the independently supplied current
   trust/high-water and witness directory. Preserve its actual signed checkpoint.
7. Add only that actual checkpoint to the generator input's generation selection;
   run `assemble_local_package.py --mode package` with the same FD/hash grammar.
   It remeasures and uses the same core derivation; final validation requires the
   witness to bind that exact core. Output is the existing unsigned package,
   canonical with no newline, directly compatible with the signer.
8. `local_artifacts.py`: authenticate upstream evidence, sign the exact package
   with the supplied authorized keys and publish `package.json` then
   `verification.json` without replacement.
9. `local_install.py`: actually copy/hash/fsync/verity/freeze/publish in the
   supported guest and produce the honest terminal installation receipt.
10. `local_startup.py`: park actual roles, obtain independently supplied late
    signed originals for those observed processes, and enter the existing guard.

All script names above are under `scripts/authority/`. Generation/configuration,
evidence, key and invocation windows must overlap at their actual use; no step
renews an original expiry. The assembly CLI also limits elapsed BOOTTIME by the
remaining original generation/snapshot/closure interval. Filesystem stalls still
need external supervision. Assembly has no private key or state-changing effect.
Witness append and installation do have durable effects: never retry/reset a
partial operation, invent its receipt, or silently advance external trust state.

## Remaining concrete provisioning work

The signing/configuration producers above connect to the existing snapshot,
measured-roster, composition, persistent artifact witness, package-signing and
immutable-installation producers. Their presence does not establish that any
selected inputs have been issued, installed or admitted. The operator must
approve the real directory identities, initial trust, generation intent and
original windows, install the selected DB/TLS material with its intended owners,
and satisfy the existing live database and role-admission checks. Empty migration
selections are permissible only when no migration receipt is required; never
synthesize a successful DB migration. Real guest package installation, actual
role startup and application allow/deny behavior remain separate observed
milestones, not consequences of successful material generation.
