"""Closed policy-file approval inputs, not activation or filesystem authority."""
from __future__ import annotations

import re
from collections.abc import Mapping

from catchplate import authority_publication_approval as shared

PREFIX = "policy-file-approval."
OPERATIONS = frozenset(PREFIX + value for value in ("request", "decide", "consume", "settle"))
ASSERTION_OPERATIONS = OPERATIONS - {PREFIX + "settle"}
OPTIONS_SCHEMA = "catchplate.policyFileApprovalOptions/v1"
RESOURCE = "active-policy-file"
ROLE = "policy_publisher"
PROVENANCE_SCHEMA = "catchplate.policyFileApprovalProvenance/v1"
HANDLER_PREFIX = "catchplate_policy_authority_policy_file_approval_"
AUDIT_PREFIX = "control_plane.policy_file_approval."
FIELDS = shared.FIELDS
canonical, require, digest, policy = shared.canonical, shared.require, shared.digest, shared.policy


def action(value):
    return {"materialize": "policy.file.materialize", "resolve": "policy.file.resolve",
        "genesis-materialize": "policy.file.genesis.materialize"}[value["kind"]]


def request_binding(value):
    require(type(value) is dict and value.get("kind") in {"materialize", "genesis-materialize", "resolve"})
    common = {"kind", "publicationId", "reason"}
    genesis = value["kind"] == "genesis-materialize"
    fields = (common | {"policyOriginalSha256", "policyId", "sequence", "rollbackEpoch", "policyHash",
        "policyBundleSha256", "expectedFileSha256"} | ({"genesisPreparationDigest", "genesisFinalizationDigest"}
            if genesis else {"artifactEnvelopeSha256"})
        if value["kind"] != "resolve" else common | {"intentSha256", "outcome"})
    require(set(value) == fields and type(value["publicationId"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", value["publicationId"]) is not None
        and (value["reason"] is None or type(value["reason"]) is str and len(value["reason"]) <= 500))
    if value["kind"] != "resolve":
        for key in ("policyOriginalSha256", "policyHash", "policyBundleSha256") + (
                ("genesisPreparationDigest", "genesisFinalizationDigest") if genesis else ("artifactEnvelopeSha256",)):
            digest(value[key])
        require(value["expectedFileSha256"] is None or digest(value["expectedFileSha256"]))
        require(not genesis or value["expectedFileSha256"] is None)
        require(type(value["policyId"]) is str and 1 <= len(value["policyId"].encode("utf-8")) <= 256)
        require(all(type(value[key]) is int and 1 <= value[key] <= 2**63 - 1 for key in ("sequence", "rollbackEpoch")))
    else:
        digest(value["intentSha256"])
        require(value["outcome"] in {"finalize-installed", "abandon-uninstalled"})
    require(len(canonical(value)) <= 8192)
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS if operation in ASSERTION_OPERATIONS else (
        FIELDS - {"credential_policy"}) | {"consumption_request_digest", "completion_sha256"}
    require(fields <= set(value) and set(value) <= fields | ({"businessIntent", "authn_evidence"} if typed else set()))
    require(not typed or "businessIntent" in value)
    bound = request_binding(value["request"])
    require(value["action"] == action(bound) and value["resource_id"] == RESOURCE)
    actor = value["actor_id"]
    require(type(actor) is str and actor.startswith("oidc:") and actor == actor.strip()
        and len(actor.encode("utf-8")) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in actor))
    import hashlib
    require(digest(value["payload_digest"]) == "sha256:" + hashlib.sha256(canonical(bound)).hexdigest())
    approval = value["approval_id"]
    require(approval is None if operation == PREFIX + "request" else
        type(approval) is str and re.fullmatch(r"[0-9a-f-]{36}", approval) is not None)
    if operation in ASSERTION_OPERATIONS:
        policy(value["credential_policy"])
    else:
        digest(value["consumption_request_digest"])
        digest(value["completion_sha256"])
    require(len(canonical(dict(value))) <= 32 * 1024)
    return {key: value[key] for key in fields}


def request_digest(operation, value):
    from catchplate.authority_request_commitment import publication_request_digest
    return publication_request_digest(operation, value)
