"""Explicit chain-status RPC grants; never a generic POST or wallet grant.

The marker identifies operator-imported static custody, not a verified Alchemy
account. Provider secrets remain in the existing encrypted credential store.
"""
from __future__ import annotations

import re

from serverware import alchemy_rpc_read
from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

CONNECTION = "alchemy_key_v1"
BUNDLE = "alchemy_chain_status_read_v1"
RESPONSE_MODE = "alchemy_rpc_read_json_v1"
SDK_TOKEN = alchemy_rpc_read.PLACEHOLDER
PLACEHOLDER = alchemy_rpc_read.REPLACEMENT["expectedValue"]
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GATE_DESCRIPTOR = {"schema": "serverware.operatorAlchemyRpcReadGate/v1",
    "adapter": "alchemy.rpc_read.v1", "operation": "alchemy.rpc.read"}

_RULE_FIELDS = frozenset({
    "name", "application_id", "credential_id", "operation_bundle", "chain",
    "upstream_url", "methods", "request_fields", "response_fields", "query_keys",
    "allowed_headers", "response_mode", "credential_input", "placeholder",
    "id", "route_id", "created_at", "status", "ordinal", "version", "revoked_at",
})


def validate_token(value: str) -> str:
    """Bounded opaque bearer syntax only; no provider request or prefix guess."""
    return alchemy_rpc_read.validate_token(value)


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    if (record.get("connection_type") != CONNECTION or record.get("auth_type") != "bearer"
            or record.get("header_name") != "Authorization"
            or metadata is not None and metadata.get("connection_type") != CONNECTION):
        raise CatalogIntegrityError("catalog Alchemy key binding refused")
    return True


def _derived_fields(chain: str) -> dict:
    chain = alchemy_rpc_read.validate_chain(chain)
    request = alchemy_rpc_read.request_profile()
    return {"upstream_url": alchemy_rpc_read.origin(chain) + alchemy_rpc_read.route_paths(chain)[0],
        "methods": ["POST"], "request_fields": [], "response_fields": [], "query_keys": [],
        "allowed_headers": list(request["allowedHeaders"]), "response_mode": RESPONSE_MODE,
        "credential_input": "replace_exact", "placeholder": PLACEHOLDER}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields(record["chain"]))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    if not selected(rule) or set(rule) - _RULE_FIELDS:
        raise CatalogIntegrityError("operator Alchemy chain-status contract refused")
    try:
        expected = _derived_fields(rule["chain"])
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("operator Alchemy chain-status contract refused") from error
    if any(rule.get(key) != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator Alchemy derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    validate_credential(credential)


def validate_route_coexistence(rules: list[dict]) -> None:
    """Identical route matches must not silently select another credential."""
    selected_chains = set()
    for rule in rules:
        if rule.get("status") != "active" or not selected(rule):
            continue
        validate_shape(rule)
        key = (rule["application_id"], rule["chain"])
        if key in selected_chains:
            raise CatalogIntegrityError("duplicate active Alchemy chain-status permission refused")
        selected_chains.add(key)


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}])
    except CatalogIntegrityError:
        raise CatalogConflict("Alchemy chain-status permission already exists") from None


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    validate_rule(rule, credential)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": alchemy_rpc_read.host(rule["chain"]), "port": 443,
            "methods": ["POST"], "paths": list(alchemy_rpc_read.route_paths(rule["chain"]))},
        "credentialRef": credential["id"], "adapter": {"type": alchemy_rpc_read.ADAPTER, "config": {
            "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"},
            "chain": rule["chain"], "request": alchemy_rpc_read.request_profile(),
            "response": alchemy_rpc_read.response_profile()}},
        "constraints": [alchemy_rpc_read.response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, "chain": rule["chain"]}


def gate_descriptor_matches(value) -> bool:
    """Exact compatibility declaration, not a provider or SDK result."""
    return (type(value) is dict and value == _GATE_DESCRIPTOR
        and all(type(item) is str for item in value.values()))


def _available(policy_hash: str) -> bool:
    """Observe outside locks; the later mutation still requires local CAS."""
    try:
        if type(policy_hash) is not str or _SHA.fullmatch(policy_hash) is None:
            return False
        from serverware import operator_demo_store as store, operator_publication as publication
        from serverware import operator_google_managed_config as managed
        publication.assert_not_held()
        if managed.enabled():
            from serverware import operator_google_managed_readiness as readiness
            observed = readiness.observe_alchemy()
            return (observed["ready"] is True
                and observed["policy_hash"] == observed["loaded_policy_hash"] == policy_hash)
        observed = store.loaded_gate_status()
        if (type(observed) is not dict or observed.get("ok") is not True
                or observed.get("policy_hash") != policy_hash
                or not gate_descriptor_matches(observed.get("operator_alchemy_rpc_read"))):
            return False
        # The owned connection opens only after the health transport closed.
        with store._require().metadata_connection() as conn:
            rows = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchall()
            return len(rows) == 1 and rows[0][0] == policy_hash
    except Exception:
        return False


def require_available(policy_hash: str) -> None:
    if not _available(policy_hash):
        raise CatalogConflict("Alchemy RPC read gate unavailable") from None


def capability(policy_hash: str) -> dict | None:
    if not _available(policy_hash):
        return None
    return _capability()


def _capability() -> dict:
    """Display DTO only; caller owns its fresh, policy-bound observation."""
    from serverware import operator_demo
    allowed = operator_demo.settings()["allowed_upstreams"]
    return {"schema": "serverware.operatorAlchemyRpcRead/v1", "connection_type": CONNECTION,
        "create_credential_path": "/api/operator-demo/credentials/alchemy-key",
        "create_rule_path": "/api/operator-demo/access-rules/alchemy-chain-status",
        "chains": [{"chain": chain, "api_origin": alchemy_rpc_read.origin(chain),
            "destination_allowed": alchemy_rpc_read.origin(chain) in allowed} for chain in alchemy_rpc_read.CHAINS],
        "operation_bundles": [BUNDLE], "rpc_methods": list(alchemy_rpc_read.METHODS),
        "sdk_auth_token": SDK_TOKEN, "placeholder": PLACEHOLDER,
        "response_mode": RESPONSE_MODE, "source_pair_required": True}
