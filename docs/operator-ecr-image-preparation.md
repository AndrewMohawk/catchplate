# Exact-image preparation for the ECR publishing workflow

This is the local artifact-preparation component of the planned ECR workflow.
It does **not** enable AWS publishing in the operator app. Encrypted AWS
[credential storage](operator-aws-credentials.md) is implemented, but compound
publication authority, approved continuation, proxy dispatch integration and
actual SDK-through-proxy acceptance remain unfinished.
Ordinary app startup never depends on this preparation or a native pilot.

## Why preparation precedes approval

The original example approves one exact container image before any protected
upload. ECR's first upload call does not include the complete image manifest;
that manifest arrives later at `PutImage`. A declaration of layer hashes alone
also cannot prove that early part bytes belong to the approved image.
See the AWS contracts for
[InitiateLayerUpload](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_InitiateLayerUpload.html)
and [PutImage](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html).

The selected design prepares the complete artifact locally before requesting
approval. Catchplate must then bind a genuine approval to the image, application,
account, region, repository, tag, policy, credential generation and original
expiry. One approval opens one bounded publication, not several independent
request grants. The normal SDK sends the corresponding bytes only after that
explicit continuation. This component neither creates that approval nor returns
fabricated successful ECR responses while gathering content.

## Implemented preparation contract

The Python and Rust image verifiers independently read the **actual** config
and layer bytes, check their full SHA-256 digests and exact lengths, and retain
the original manifest bytes. Reformatting JSON changes the manifest identity.
Identical repeated layer references keep their order; their underlying content
is read and counted once. Missing, extra or conflicting supplied blobs fail.

Supported inputs are a single OCI image manifest or Docker schema-2 image
manifest. The closed media profiles exclude indexes, foreign layers, URLs and
artifact manifests. Optional bounded OCI annotations are retained through the
original manifest digest. Config and layer contents are otherwise opaque: this
is content-integrity validation, **not** proof that an image is runnable or that
its root filesystem, `diff_ids`, software or provenance are valid. Nothing is
decompressed, extracted or executed.

Limits are 4 MiB each for the manifest/config, 512 MiB per layer, 1 GiB of unique
blob content and 128 layer references. Reads request at most 1 MiB; each blob
has a finite read-call budget including an exact end-of-file check. Caller-owned
readers still require their own blocking/cancellation and deadline management.

The content commitment uses
[`ecr-verified-image.v1.schema.json`](../schemas/ecr-verified-image.v1.schema.json).
Validating an arbitrary serialized commitment is not evidence that its author
read the blobs. The original byte-reading operation is essential.

## Local command

The source must contain regular single-link files named
`blobs/sha256/<lowercase digest>` for the selected manifest and referenced blobs.
Unrelated content in a shared source blob directory is not copied. Select an
exact manifest digest; the command does not choose an index entry or resolve a
tag. The destination must not exist and its parent must already be private and
owned by the invoking user.

```sh
python3 -B -m scripts.prepare_ecr_image_artifact \
  --source /absolute/path/to/image-layout \
  --manifest-digest 'sha256:<exact-manifest-digest>' \
  --destination /absolute/private-parent/new-image-stage
```

Use real values for the placeholder paths and digest. No AWS credentials,
provider account or network access are needed. A successful invocation writes
the original `manifest.json`, exact referenced `blobs/<digest>`, canonical
`artifact.json` and, last, the unsigned `stage.json` marker. It prints only that
marker, not image content. The stage marker has the separate closed
[`ecr-artifact-stage.v1.schema.json`](../schemas/ecr-artifact-stage.v1.schema.json).

The stager uses exclusive creation, bounded copying, file synchronization and
readback checks. Existing destinations are never reset or reused. Failure
preserves partial output for inspection; a failure after publication can leave
an uncertain completion, not permission to retry or overwrite it.

These ordinary private files are **not immutable or hostile-root-safe custody**.
An unsigned marker is not an admission receipt, signature, hardware approval,
credential grant or evidence of an AWS effect. A future trusted publication
owner must recheck retained content and current authority before use, preserve
its original deadlines, bind upload IDs/offsets to the approved image, and stop
on uncertain writes without automatic replay.

The broader [AWS integration plan](operator-aws-client-compatibility.md) and its
real-provider acceptance gates remain applicable. No Docker-push compatibility,
native custody or real AWS publication follows from this preparation component.
The [publication planner](operator-ecr-publication-plan.md) connects verified
content to bounded SDK request/response proposals; it does not turn this mutable
stage into trusted custody or confer permission to send them.

## Verification checkpoint (2026-10-11)

All 27 Python checks passed: 13 verifier checks, 11 real-filesystem staging
checks and 3 command-line subprocess checks. Run them without a build, provider
connection or pilot:

```sh
make verify-ecr-image-preparation
```

All 8 standalone Rust test groups also passed using pinned Rust 1.88.0 and
cached dependencies in a network-disabled container. Both implementations
matched the shared literal manifest and canonical commitment fixture. The Rust
module was compiled independently; this was not a decision-gate build or proxy
integration test. The temporary test container was removed after successful
exit.

Private execution receipts are retained outside Git under
`catchplate-operator-workspace-evidence/ecr-image-preparation.Jx1DS25o`.
These checks made no AWS requests, issued no approval and changed no live app
configuration. The incomplete publication and real-provider acceptance gates
above remain open.
