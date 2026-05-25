from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
from typing import Any

from serverware import db
from serverware.attestation import (
    attestation_document,
    canonical_json,
    sha256_prefixed,
    verify_attestation_quote,
)
from serverware.config import (
    KEY_RELEASE_ALLOW_DEBUG,
    KEY_RELEASE_COMMAND,
    KEY_RELEASE_MIN_ROLLBACK_EPOCH,
    KEY_RELEASE_REQUIRED,
    KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
    KEY_RELEASE_STATE_PATH,
    RELEASE_CHANNEL,
    ensure_data_dirs,
)


class KeyReleaseError(RuntimeError):
    pass


_lock = threading.Lock()


def _state() -> dict[str, Any]:
    if not KEY_RELEASE_STATE_PATH.exists():
        return {"version": 1, "materials": {}}
    try:
        return json.loads(KEY_RELEASE_STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KeyReleaseError(f"key release state is corrupt: {exc}") from exc


def _write_state(state: dict[str, Any]) -> None:
    ensure_data_dirs()
    KEY_RELEASE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = KEY_RELEASE_STATE_PATH.with_name(f".{KEY_RELEASE_STATE_PATH.name}.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, KEY_RELEASE_STATE_PATH)


def _quote_digest(quote: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_json(quote).encode("utf-8"))


def _claims_from_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    try:
        claims = verify_attestation_quote(attestation)
    except ValueError as exc:
        raise KeyReleaseError(str(exc)) from exc
    checks = {
        "runtime_manifest_digest": attestation.get("runtime_manifest_digest"),
        "policy_bundle_digest": attestation.get("policy_bundle_digest"),
        "ca_intermediate_spki_sha256": attestation.get("ca_intermediate_spki_sha256"),
        "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
        "rollback_epoch": attestation.get("rollback_epoch"),
        "provenance_digest": attestation.get("provenance_digest"),
        "source_tree_digest": attestation.get("source_tree_digest"),
        "response_signing_key_id": attestation.get("response_signing_key_id"),
        "release_channel": attestation.get("release_channel"),
    }
    for field, expected in checks.items():
        if claims.get(field) != expected:
            raise KeyReleaseError(f"quote claim {field} does not match attestation")
    return claims


def _external_key_release_policy(
    material: str,
    claims: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any] | None:
    if not KEY_RELEASE_COMMAND:
        return None
    result = subprocess.run(
        shlex.split(KEY_RELEASE_COMMAND),
        input=(canonical_json({"material": material, "claims": claims, "expected": expected}) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise KeyReleaseError(f"external key-release command failed with exit {result.returncode}: {detail}")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise KeyReleaseError("external key-release command returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise KeyReleaseError("external key-release command denied material release")
    return payload


def _validate_claims(
    material: str,
    claims: dict[str, Any],
    *,
    expected_policy_hash: str | None = None,
    expected_ca_spki: str | None = None,
    expected_rollback_epoch: int | None = None,
    expected_release_channel: str | None = None,
    expected_provenance_digest: str | None = None,
    expected_data_plane_binary_digest: str | None = None,
) -> None:
    if material not in set(claims.get("materials") or []):
        raise KeyReleaseError(f"material {material} is not authorized by the quote")
    if claims.get("debug") is True and not KEY_RELEASE_ALLOW_DEBUG:
        raise KeyReleaseError("debug quote is not allowed by key-release policy")
    if claims.get("release_channel") != (expected_release_channel or RELEASE_CHANNEL):
        raise KeyReleaseError("release channel mismatch")
    rollback = claims.get("rollback_epoch")
    min_epoch = expected_rollback_epoch if expected_rollback_epoch is not None else KEY_RELEASE_MIN_ROLLBACK_EPOCH
    if not isinstance(rollback, int) or rollback < min_epoch:
        raise KeyReleaseError("rollback epoch is stale")
    if expected_policy_hash and claims.get("policy_bundle_digest") != expected_policy_hash:
        raise KeyReleaseError("policy digest mismatch")
    if expected_ca_spki and claims.get("ca_intermediate_spki_sha256") != expected_ca_spki:
        raise KeyReleaseError("CA SPKI mismatch")
    if expected_data_plane_binary_digest and claims.get("data_plane_binary_digest") != expected_data_plane_binary_digest:
        raise KeyReleaseError("data-plane binary digest mismatch")
    if expected_provenance_digest and claims.get("provenance_digest") != expected_provenance_digest:
        raise KeyReleaseError("provenance digest mismatch")
    if not claims.get("policy_bundle_digest"):
        raise KeyReleaseError("policy digest is required for key release")
    if not claims.get("ca_intermediate_spki_sha256"):
        raise KeyReleaseError("CA SPKI is required for key release")
    if KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST and material == "decision-gate-ca" and not claims.get("data_plane_binary_digest"):
        raise KeyReleaseError("data-plane binary digest is required for decision-gate-ca key release")


def release_material(
    material: str,
    *,
    expected_policy_hash: str | None = None,
    expected_ca_spki: str | None = None,
    expected_rollback_epoch: int | None = None,
    expected_release_channel: str | None = None,
    expected_provenance_digest: str | None = None,
    expected_data_plane_binary_digest: str | None = None,
) -> dict[str, Any]:
    if not KEY_RELEASE_REQUIRED:
        return {"ok": True, "enabled": False, "material": material, "reason": "key release gate is disabled"}
    attestation = attestation_document(nonce=f"key-release:{material}:{db.iso_now()}")
    quote = attestation["quote"]
    claims = _claims_from_attestation(attestation)
    _validate_claims(
        material,
        claims,
        expected_policy_hash=expected_policy_hash,
        expected_ca_spki=expected_ca_spki,
        expected_rollback_epoch=expected_rollback_epoch,
        expected_release_channel=expected_release_channel,
        expected_provenance_digest=expected_provenance_digest,
        expected_data_plane_binary_digest=expected_data_plane_binary_digest,
    )
    external_release = _external_key_release_policy(
        material,
        claims,
        {
            "policy_bundle_digest": expected_policy_hash,
            "ca_intermediate_spki_sha256": expected_ca_spki,
            "rollback_epoch": expected_rollback_epoch,
            "release_channel": expected_release_channel,
            "provenance_digest": expected_provenance_digest,
            "data_plane_binary_digest": expected_data_plane_binary_digest,
        },
    )
    record = {
        "material": material,
        "released_at": db.iso_now(),
        "tee_platform": attestation["tee_platform"],
        "quote_provider": quote.get("provider"),
        "quote_digest": _quote_digest(quote),
        "quote_signing_key_id": quote.get("quote_signing_key_id"),
        "runtime_manifest_digest": claims.get("runtime_manifest_digest"),
        "policy_bundle_digest": claims.get("policy_bundle_digest"),
        "ca_intermediate_spki_sha256": claims.get("ca_intermediate_spki_sha256"),
        "data_plane_binary_digest": claims.get("data_plane_binary_digest"),
        "rollback_epoch": claims.get("rollback_epoch"),
        "release_channel": claims.get("release_channel"),
        "provenance_digest": claims.get("provenance_digest"),
        "debug": claims.get("debug"),
        "key_release_provider": "external-command" if external_release else "local-dev",
        "external_release": external_release,
    }
    with _lock:
        state = _state()
        state.setdefault("materials", {})[material] = record
        state["updated_at"] = record["released_at"]
        _write_state(state)
    db.record_audit_event("key_release.released", record, actor_type="system", actor_id="key-release-gate")
    return {"ok": True, "enabled": True, "released": True, **record}


def ensure_material_released(material: str) -> dict[str, Any]:
    if not KEY_RELEASE_REQUIRED:
        return {"ok": True, "enabled": False, "material": material}
    attestation = attestation_document(nonce=f"key-release-check:{material}:{db.iso_now()}")
    claims = _claims_from_attestation(attestation)
    with _lock:
        state = _state()
        existing = (state.get("materials") or {}).get(material)
    if (
        existing
        and existing.get("policy_bundle_digest") == claims.get("policy_bundle_digest")
        and existing.get("ca_intermediate_spki_sha256") == claims.get("ca_intermediate_spki_sha256")
        and existing.get("data_plane_binary_digest") == claims.get("data_plane_binary_digest")
        and existing.get("rollback_epoch") == claims.get("rollback_epoch")
        and existing.get("release_channel") == claims.get("release_channel")
        and existing.get("provenance_digest") == claims.get("provenance_digest")
    ):
        return {"ok": True, "enabled": True, "released": True, **existing}
    return release_material(material)


def status() -> dict[str, Any]:
    state = _state()
    return {
        "enabled": KEY_RELEASE_REQUIRED,
        "allow_debug": KEY_RELEASE_ALLOW_DEBUG,
        "min_rollback_epoch": KEY_RELEASE_MIN_ROLLBACK_EPOCH,
        "release_channel": RELEASE_CHANNEL,
        "require_data_plane_digest": KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
        **state,
    }
