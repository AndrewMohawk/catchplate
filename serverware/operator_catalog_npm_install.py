"""Explicit npm install closure, separate from metadata and publication grants."""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit

from serverware import operator_catalog_npm as metadata
from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

BUNDLE = "npm_install_v1"
ORIGIN = metadata.ORIGIN
RESPONSE_MODE = "npm_install_v1"
MODES = ("metadata", "tarball", "audit")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GATE = {"schema": "serverware.operatorNpmInstallGate/v1", "adapter": "npm.install.v1", "modes": list(MODES)}
_FIELDS = {"name", "application_id", "credential_id", "operation_bundle", "packages",
    "upstream_url", "methods", "request_fields", "response_fields", "query_keys",
    "allowed_headers", "response_mode", "credential_input", "placeholder"}
_RETAINED = {"id", "route_id", "created_at", "status", "ordinal", "version", "revoked_at"}


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def _derived_fields(packages: list[str]) -> dict:
    from serverware import npm_install
    npm_install.validate_packages(packages)
    headers = sorted({header for mode in MODES for header in npm_install.request_profile(mode)["allowedHeaders"]})
    return {"upstream_url": ORIGIN + "/", "methods": ["GET", "POST"], "request_fields": [],
        "response_fields": [], "query_keys": [], "allowed_headers": headers,
        "response_mode": RESPONSE_MODE, "credential_input": "replace_exact", "placeholder": metadata.PLACEHOLDER}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields(record["packages"]))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    if not selected(rule) or not _FIELDS <= set(rule) or set(rule) - (_FIELDS | _RETAINED):
        raise CatalogIntegrityError("operator npm install contract refused")
    try:
        expected = _derived_fields(rule["packages"])
    except (KeyError, TypeError, ValueError):
        raise CatalogIntegrityError("operator npm install package closure refused") from None
    if any(rule[key] != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator npm install derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    metadata.validate_credential(credential)


def validate_route_coexistence(rules: list[dict]) -> None:
    """Only the new install grant excludes all sibling registry grants."""
    active = [rule for rule in rules if rule.get("status") == "active"]
    for install in active:
        if not selected(install):
            continue
        validate_shape(install)
        for other in active:
            if other is install or other["application_id"] != install["application_id"]:
                continue
            try:
                target = urlsplit(other["upstream_url"])
                overlap = target.scheme == "https" and target.hostname == "registry.npmjs.org" and target.port in {None, 443}
            except (KeyError, TypeError, ValueError):
                raise CatalogIntegrityError("operator npm install overlap refused") from None
            if overlap:
                raise CatalogIntegrityError("npm install conflicts with an active registry permission")


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}])
    except CatalogIntegrityError:
        raise CatalogConflict("npm install registry permission conflicts") from None


def route_ids(rule: dict) -> tuple[str, str, str]:
    """Exact aliases of one validated retained permission, not caller routes."""
    validate_shape(rule)
    try:
        if str(uuid.UUID(rule["id"])) != rule["id"] or rule["route_id"] != "operator." + rule["id"]:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise CatalogIntegrityError("operator npm install route identity refused") from None
    return rule["route_id"], rule["route_id"] + ".tarball", rule["route_id"] + ".audit"


def render_routes(rule: dict, credential: dict, principal_id: str) -> list[dict]:
    from serverware import npm_install
    validate_rule(rule, credential)
    routes = []
    for mode, identifier in zip(MODES, route_ids(rule)):
        routes.append({"id": identifier, "principals": [principal_id],
            "match": {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
                "methods": ["POST" if mode == "audit" else "GET"], "paths": npm_install.route_paths(mode)},
            "credentialRef": credential["id"], "adapter": {"type": npm_install.ADAPTER, "config": {
                "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                    "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"},
                "packages": list(rule["packages"]), "mode": mode,
                "request": npm_install.request_profile(mode), "response": npm_install.response_profile(mode)}},
            "constraints": [npm_install.response_envelope(identifier + ".envelope", mode)]})
    return routes


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, "packages": list(rule["packages"])}


def gate_descriptor_matches(value) -> bool:
    return (type(value) is dict and value == _GATE and type(value.get("modes")) is list
        and all(type(item) is str for item in value["modes"]))


def _available(policy_hash: str) -> bool:
    try:
        if type(policy_hash) is not str or _SHA.fullmatch(policy_hash) is None:
            return False
        from serverware import operator_demo, operator_demo_store as store, operator_publication as publication
        from serverware import operator_google_managed_config as managed
        publication.assert_not_held()
        if ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
            return False
        if managed.enabled():
            from serverware import operator_google_managed_readiness as readiness
            observed = readiness.observe_npm_install()
            return observed["ready"] is True and observed["policy_hash"] == observed["loaded_policy_hash"] == policy_hash
        observed = store.loaded_gate_status()
        if (type(observed) is not dict or observed.get("ok") is not True
                or observed.get("policy_hash") != policy_hash
                or not gate_descriptor_matches(observed.get("operator_npm_install"))):
            return False
        with store._require().metadata_connection() as conn:
            rows = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchall()
            return len(rows) == 1 and rows[0][0] == policy_hash
    except Exception:
        return False


def require_available(policy_hash: str) -> None:
    if not _available(policy_hash):
        raise CatalogConflict("npm install gate unavailable") from None


def _capability() -> dict:
    """Display only; caller owns fresh gate/policy/destination observation."""
    return {"schema": "serverware.operatorNpmInstall/v1", "connection_type": metadata.CONNECTION,
        "create_rule_path": "/api/operator-demo/access-rules/npm-install", "registry_origin": ORIGIN,
        "destination_allowed": True, "operation_bundles": [BUNDLE], "sdk_auth_token": metadata.SDK_TOKEN,
        "placeholder": metadata.PLACEHOLDER, "response_mode": RESPONSE_MODE, "source_pair_required": True,
        "max_active_rules_per_application": 1, "max_packages": 64,
        "modes": list(MODES), "dependencies_require_explicit_grant": True}
