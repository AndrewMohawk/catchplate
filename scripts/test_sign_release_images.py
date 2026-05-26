#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sign_release_images as signer  # noqa: E402


def main() -> None:
    control_ref = "registry.example/serverware/control@sha256:" + "a" * 64
    gate_ref = "registry.example/serverware/decision-gate@sha256:" + "b" * 64
    inventory = signer.production_image_inventory([control_ref, gate_ref])
    if set(inventory) != {"control", "decision-gate"}:
        raise AssertionError(f"production image services were not derived from refs: {inventory}")
    if inventory["control"]["image_id"] != "sha256:" + "a" * 64:
        raise AssertionError(f"control image digest mismatch: {inventory}")
    if inventory["decision-gate"]["repo_digests"] != [gate_ref]:
        raise AssertionError(f"decision-gate repo digest was not preserved: {inventory}")
    try:
        signer.production_image_inventory(["registry.example/serverware/control:latest"])
    except ValueError as exc:
        if "digest-pinned" not in str(exc):
            raise AssertionError(f"mutable ref failed for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("mutable production image ref was accepted")

    provenance = {
        "source_tree": {"digest": "sha256:" + "c" * 64},
        "compose_config_sha256": "sha256:" + "d" * 64,
        "sbom": {"cyclonedx": {"sha256": "sha256:" + "e" * 64, "components": 10}},
    }
    statement = signer.statement_for_image(
        service="control",
        image=inventory["control"],
        provenance=provenance,
        provenance_digest="sha256:" + "f" * 64,
    )
    subject = statement["subject"][0]
    if subject["digest"]["sha256"] != "a" * 64:
        raise AssertionError(f"statement subject did not bind production image digest: {statement}")
    if statement["predicate"]["repo_digests"] != [control_ref]:
        raise AssertionError(f"statement omitted production repo digest: {statement}")
    print(json.dumps({"ok": True, "sign_release_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
