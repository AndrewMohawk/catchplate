# Local source/runtime composition

The first local pilot can combine an exact clean Git source archive with an
already retained Python runtime image. Those are **separately selected inputs**;
the older runtime image is not claimed to have been built from the new source.
This avoids requiring an unrelated production image rebuild merely to describe
the actual local assembly. It is not a production release shortcut.

[`local_composition.py`](../scripts/authority/local_composition.py) signs the
explicit local predicate
`catchplate.authorityTrustedHostLocalSourceRuntimeComposition/v1`. Native and
external/TEE package profiles refuse it. The existing clean-build-report
observer remains available with its original, different contract.

## Actual observation

The real issuer retains the existing protected-FD owner, frozen-tree measurement,
original two-clock bounds and current purpose-authorized provenance key. It:

1. Measures the exact immutable tree and verifies all selected original hashes.
2. Checks the actual clean Git commit object, reconstructed tree, deterministic
   source archive headers, file bytes, modes and blob hashes.
3. Joins the selected OCI manifest, Linux/amd64 config and layer-object hashes.
4. Requires an exact canonical composition-input declaration, then signs the
   existing detached provenance reference using the explicit local predicate.

The declaration is `catchplate.authorityTrustedHostLocalCompositionInputs/v1`.
The `input_manifest()` formatter produces its unsigned selection from source and
runtime object identities before the tree is frozen. It has no final artifact
tree digest or self-hash, and is not evidence on its own. The issuer independently
reconstructs its fields; extra fields, stale identities and asserted build or
production assurances refuse. The detached signature is not placed in the
tree whose digest it authenticates.

## Limits and remaining work

This establishes observed input association, **not** source-to-image derivation,
historical build execution, image execution, uncompressed-layer/rootfs equality,
reproducibility, independent administration, hardware custody or production
approval. It cannot replace the actual measured-roster, immutable-installation
or runtime-admission checks. A raw Docker rootfs export is not an OCI manifest,
config and layers; genuine retained OCI objects are still needed for issuance.

Use `--help` for the fixed FD/hash interface. Private keys never appear in
arguments, logs or chat. The command does not generate keys, trust, files,
checkpoints or installations. Require complete output and successful exit;
preserve partial outcomes instead of retrying automatically.

Source and compact association controls are implemented. No full signed
composition issuance, package installation or working pilot is claimed here.
