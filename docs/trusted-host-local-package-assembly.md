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

The source has real snapshot, measured-roster, composition, persistent artifact
witness, package-signing and immutable-installation producers. It does not yet
provide a connected producer for the exact signed service/replay-witness
configurations and artifact key-authorization/revocation documents. Actual local
role-scoped key provisioning, DB/TLS identities and credential-issuance originals
must be supplied through the existing contracts before this sequence can run.
These may be separate roles under one trusted local administrator; no off-host
or independent-organizational custody claim follows. Empty migration selections
are permissible only when no migration receipt is required; never synthesize a
successful DB migration. Real guest package installation, actual role startup
and application allow/deny behavior remain to be observed.
