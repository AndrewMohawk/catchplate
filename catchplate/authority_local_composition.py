"""Observe exact clean-source and retained-OCI inputs without a build claim.

This explicit local profile does not assert that the runtime OCI was built from
the selected source, or that its layers are the subsequently executed rootfs.
The actual measured-roster and installation checks remain separate obligations.
No production build report or historical execution verdict is manufactured.
"""
from __future__ import annotations

from catchplate import authority_local_provenance as observed

APPROVAL_SCHEMA = "catchplate.authorityTrustedHostLocalCompositionApproval/v1"
MANIFEST_SCHEMA = "catchplate.authorityTrustedHostLocalCompositionInputs/v1"
PURPOSE = "observe-clean-source-and-retained-runtime-oci-inputs"
PREDICATE = "catchplate.authorityTrustedHostLocalSourceRuntimeComposition/v1"
BUILDER = "catchplate-trusted-host-local-composition-observer"
RELATIONSHIP = "separately-selected-inputs-not-source-to-image-derivation"
ASSURANCES = {
    "buildExecution": False,
    "sourceToImageDerivation": False,
    "reproducibility": False,
    "productionReleaseApproval": False,
    "rootfsExecution": False,
    "futureDynamicLoading": False,
    "hardwareBacked": False,
}


def approval(raw):
    selected = observed.document(raw, canonical=True)
    observed._require(selected.get("schema") == APPROVAL_SCHEMA
                      and selected.get("purpose") == PURPOSE)
    # Reuse the closed FD/tree/original-clock selection contract, without
    # altering the original bytes retained and rechecked by the real owner.
    observed.approval(observed.spec.canonical_json_bytes(dict(
        selected, schema=observed.APPROVAL_SCHEMA, purpose=observed.PURPOSE)))
    return selected


def input_manifest(source, *, source_manifest_raw, runtime_manifest_raw,
                   runtime_config_raw, runtime_layer_sha256s):
    """Format unsigned input selection before freezing; not an attestation.

    No field depends on this document or the final measured artifact tree.
    The real issuer independently derives and checks every field below.
    """
    return {
        "schema": MANIFEST_SCHEMA,
        "sourceCommit": source["commit"],
        "sourceTreeDigest": source["sourceTreeDigest"],
        "sourceArchiveSha256": source["archive"]["sha256"],
        "sourceManifestSha256": observed.sha(source_manifest_raw),
        "runtimeManifestSha256": observed.sha(runtime_manifest_raw),
        "runtimeConfigSha256": observed.sha(runtime_config_raw),
        "runtimeLayerSha256s": list(runtime_layer_sha256s),
        "relationship": RELATIONSHIP,
        "assurances": dict(ASSURANCES),
    }


def composition_manifest(selected, measured, originals):
    """Derive a public declaration from independently measured selected bytes."""
    rows, source, _commit_digest, _archive_row = observed.measured_originals(
        selected, measured, originals)
    observed.oci_objects(selected["objects"], rows, originals)
    return input_manifest(source, source_manifest_raw=originals["sourceManifest"],
        runtime_manifest_raw=originals["ociManifest"], runtime_config_raw=originals["ociConfig"],
        runtime_layer_sha256s=[rows[path]["sha256"] for path in selected["objects"]["layers"]])


def association(selected, measured, originals):
    rows, source, commit_digest, _archive_row = observed.measured_originals(
        selected, measured, originals)
    observed.oci_objects(selected["objects"], rows, originals)
    expected = input_manifest(source, source_manifest_raw=originals["sourceManifest"],
        runtime_manifest_raw=originals["ociManifest"], runtime_config_raw=originals["ociConfig"],
        runtime_layer_sha256s=[rows[path]["sha256"] for path in selected["objects"]["layers"]])
    # Literal canonical equality also rejects True/False versus integer aliases,
    # extra fields and any asserted production/build assurance.
    observed._require(originals["report"] == observed.spec.canonical_json_bytes(expected))
    payload = dict(
        path=selected["objects"]["report"], sha256=observed.sha(originals["report"]),
        predicateType=PREDICATE, mediaType="application/json", builderId=BUILDER,
        sourceRevision=observed.SOURCE_REVISION, sourceCommitDigest=commit_digest,
        sourceTreeDigest=measured["treeDigest"],
        ociRootDigest=observed.sha(originals["ociManifest"]),
    )
    payload["statementDigest"] = observed.spec.domain_digest(
        observed.spec.PROVENANCE_PAYLOAD_DIGEST_DOMAIN,
        observed.spec.canonical_json_bytes(payload))
    return payload, source


class LocalCompositionIssuer(observed.LocalProvenanceIssuer):
    """Same real FD/tree/archive/key owner; only explicit input profile differs."""

    validate_approval = staticmethod(approval)
    associate = staticmethod(association)
