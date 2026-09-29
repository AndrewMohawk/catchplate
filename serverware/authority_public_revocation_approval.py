"""Closed approval-only public revocation operations and semantic commitments.

Identity and asserted variants are distinct operations. The independently
enrolled policy selects one pair; no absent assertion can downgrade the other.
Only the dedicated verifier original-owner admits these operations. This
module is pure parsing/commitment, not a caller or an approval verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

from serverware import authority_public_webauthn_revocation as public


PREFIX = "public-revocation-approval."
OPERATIONS = frozenset(PREFIX + phase + "-" + mode
    for phase in ("request", "decide") for mode in ("identity", "asserted"))
ASSERTION_OPERATIONS = frozenset(value for value in OPERATIONS if value.endswith("-asserted"))
PROVENANCE_SCHEMA = "serverware.publicWebAuthnRevocationApprovalProvenance/v1"
OPTIONS_SCHEMA = "serverware.publicWebAuthnRevocationApprovalOptions/v1"
FIELDS = frozenset({"action", "resource_id", "payload_digest", "actor_id", "actor_roles",
    "request", "approval_id", "mutation_policy", "ttl_seconds", "note"})
MUTATION_FIELDS = frozenset({"credential_record_id", "credential_id_sha256", "credential_user_id",
    "label", "attestation_root_sha256", "reason"})


def operation(phase, policy):
    public.policy_shape(policy)
    public._require(phase in ("request", "decide") and policy["twoPersonRequired"] is True)
    return PREFIX + phase + ("-asserted" if policy["mfaRequired"] else "-identity")


def handler(selected):
    public._require(selected in OPERATIONS)
    return "serverware_policy_authority_public_revocation_approval_" + selected[len(PREFIX):].replace("-", "_")


def arguments(selected, value, *, typed=False):
    public._require(selected in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent"} if typed else set())
    public._require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    public._require(value["action"] == public.OPERATION)
    public._text(value["actor_id"])
    roles = value["actor_roles"]
    public._require(type(roles) is list and roles == sorted(set(roles)) and 1 <= len(roles) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in roles))
    phase = selected[len(PREFIX):].split("-")[0]
    public._require(selected == operation(phase, value["mutation_policy"]))
    public._require(bool(set(roles) & ({"admin"} if phase == "decide" else {"admin", "approver"})))
    bound = value["request"]
    public._object(bound, MUTATION_FIELDS)
    for name in ("credential_record_id", "credential_user_id"):
        public._text(bound[name])
    public.core.require_digest(bound["credential_id_sha256"], "target credential")
    if bound["attestation_root_sha256"] is not None:
        public.core.require_digest(bound["attestation_root_sha256"], "target attestation root")
    public._require(type(bound["reason"]) is str and 1 <= len(bound["reason"]) <= 500
        and type(bound["label"]) is str and len(bound["label"].encode("utf-8")) <= 4096
        and value["resource_id"] == bound["credential_record_id"])
    public._require(value["payload_digest"] == "sha256:" + hashlib.sha256(public.core.canonical_bytes(bound)).hexdigest())
    if phase == "request":
        public._require(value["approval_id"] is None and value["note"] is None)
    else:
        public._text(value["approval_id"], 256)
        public._require(value["note"] is None or type(value["note"]) is str and len(value["note"]) <= 500)
    public._require(type(value["ttl_seconds"]) is int and 1 <= value["ttl_seconds"] <= 3600)
    public._require(len(public.core.canonical_bytes(dict(value))) <= 32 * 1024)
    return {name: value[name] for name in FIELDS}


def request_digest(selected, value):
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment
    values = arguments(selected, value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(selected, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", public.core.canonical_bytes({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": selected,
        "handler": contract.operation_spec(selected)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
