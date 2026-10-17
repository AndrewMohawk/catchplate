"""Host-trusted permission configuration; never native or TEE authority."""
from __future__ import annotations

MODE = "host_review_v1"
CONSTRAINT = {"type": "hostTrustedApproval",
    "schema": "catchplate.hostTrustedApprovalPolicy/v1",
    "pendingTtlSeconds": 300, "approvalTtlSeconds": 60}
BUNDLES = ["gmail_read_v1", "github_issues_read_v1", "github_issues_write_v1",
    "npm_metadata_read_v1", "npm_install_v1", "npm_publish_v1",
    "x_username_read_v1", "x_text_post_v1", "alchemy_chain_status_read_v1"]


def validate(rule: dict) -> None:
    from catchplate.operator_catalog_schema import CatalogIntegrityError
    if "approval_mode" not in rule:
        return
    if (rule["approval_mode"] != MODE
            or "daily_post_attempt_limit" in rule):
        raise CatalogIntegrityError("host-trusted approval setting is incompatible with this permission")


def apply(rule: dict, route: dict) -> None:
    validate(rule)
    if rule.get("approval_mode") == MODE:
        route.setdefault("constraints", []).append(dict(CONSTRAINT))


def require_available() -> None:
    from catchplate import operator_host_approvals
    if not operator_host_approvals.available():
        raise ValueError("host-trusted approvals are not available on the running proxy")


def capability() -> dict:
    from catchplate import operator_host_approvals
    return {"schema": "catchplate.operatorHostApprovals/v1", "mode": "host_trusted_v1",
        "available": operator_host_approvals.available(), "operation_bundles": list(BUNDLES),
        "generic_rules": True, "setting_path": "/api/operator-demo/access-rules/approval"}
