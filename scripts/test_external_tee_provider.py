#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("SERVERWARE_DATA_DIR", str(Path(".tmp/test-external-tee-provider/data").resolve()))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware.attestation import attestation_document, verify_attestation_quote
from serverware.key_release import release_material


def main() -> None:
    attestation = attestation_document("external-tee-provider-test")
    quote = attestation.get("quote") or {}
    claims = verify_attestation_quote(attestation)
    assert quote.get("provider") == "external-command-fixture", quote
    assert attestation.get("tee_platform") == "fixture-tee", attestation
    assert claims.get("debug") is False, claims
    for field in (
        "runtime_manifest_digest",
        "policy_bundle_digest",
        "policy_sequence",
        "policy_high_water_digest",
        "ca_intermediate_spki_sha256",
        "data_plane_binary_digest",
        "rollback_epoch",
        "provenance_digest",
        "image_signatures_digest",
        "source_tree_digest",
        "response_signing_key_id",
        "release_channel",
    ):
        assert claims.get(field) == attestation.get(field), (field, claims, attestation)

    release = release_material(
        "broker-kek",
        expected_policy_hash=attestation["policy_bundle_digest"],
        expected_policy_sequence=attestation["policy_sequence"],
        expected_policy_high_water_digest=attestation["policy_high_water_digest"],
        expected_ca_spki=attestation["ca_intermediate_spki_sha256"],
        expected_rollback_epoch=attestation["rollback_epoch"],
        expected_release_channel=attestation["release_channel"],
        expected_data_plane_binary_digest=attestation.get("data_plane_binary_digest"),
    )
    assert release["ok"] is True, release
    assert release["key_release_provider"] == "external-command", release
    assert release["external_release"]["provider"] == "fixture-kms-hsm", release
    print(
        json.dumps(
            {
                "ok": True,
                "external_tee_provider": quote["provider"],
                "key_release_provider": release["key_release_provider"],
                "tee_platform": attestation["tee_platform"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
