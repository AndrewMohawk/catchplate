"""Pure authority-policy producer and explicit canonical JIT-policy projection.

The two schemas and digest domains are intentionally different. The authority
producer below is shared by capability issuance and the JIT receipt consumers;
it retains the original alias precedence and tagged argument representation.
Stored JIT policies must first pass their store's canonical binding and pinned
RP/origin validation. from_jit_policy also checks the closed representation; it
does not normalize malformed policies or turn a digest into authorization.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any

from serverware.rbac import normalize_rbac_roles


AUTHORITY_SCHEMA = "serverware.authorityApproverPolicyBinding/v1"
JIT_SCHEMA = "serverware.jitApproverPolicy/v1"
_POLICY_FIELDS = frozenset({"schema", "requiredRoles", "roleMatch", "allowedApproverIds",
    "allowAnyApproverId", "requireWebAuthn", "threshold", "credentialPolicy"})
_CREDENTIAL_FIELDS = frozenset({"allowedCredentialRecordIds", "allowedAuthenticatorClasses",
    "allowedAaguids", "requireAttestationTrusted", "requiredTrustBundleDigest",
    "minimumTrustBundleSequence", "rpId", "origins", "requireUserPresence",
    "requireUserVerification", "counterPolicy", "maxAssertionAgeSeconds"})


class ApproverPolicyError(ValueError):
    def __init__(self):
        super().__init__("approver policy projection is invalid")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        separators=(",", ":"), sort_keys=True).encode("ascii")


def _argument_value(value):
    # Extracted from the authority producer, including its exact wire handling.
    if isinstance(value, list):
        return [_argument_value(item) for item in value]
    if not isinstance(value, Mapping):
        return value
    value_type = value.get("$authorityType")
    if (value_type in {"set", "tuple"} and set(value) == {"$authorityType", "items"}
            and isinstance(value["items"], list)):
        return sorted((_argument_value(item) for item in value["items"]), key=_canonical)
    return {str(key): _argument_value(item) for key, item in value.items()}


def material(arguments: Mapping[str, Any]) -> dict[str, Any] | None:
    """The existing authority capability producer, not a stored-policy parser."""
    aliases = {
        "requiredApproverRoles": ("required_approver_roles", "required_roles"),
        "allowedApproverIds": ("allowed_approver_ids",),
        "requireWebAuthn": ("require_webauthn", "require_approver_webauthn"),
        "threshold": ("threshold", "approval_threshold"),
        "credentialPolicy": ("credential_policy", "approver_credential_policy"),
    }
    result: dict[str, Any] = {"schema": AUTHORITY_SCHEMA}
    missing = False
    for output_name, input_names in aliases.items():
        found = False
        for input_name in input_names:
            if input_name in arguments:
                result[output_name] = _argument_value(arguments[input_name])
                found = True
                break
        if not found:
            missing = True
    if missing:
        return None
    allowed_ids = result["allowedApproverIds"]
    if allowed_ids is None:
        result["allowedApproverIds"] = []
        result["allowAnyApproverId"] = True
    else:
        if not isinstance(allowed_ids, list):
            return None
        result["allowedApproverIds"] = sorted(allowed_ids)
        result["allowAnyApproverId"] = False
    roles = result["requiredApproverRoles"]
    if not isinstance(roles, list):
        return None
    result["requiredApproverRoles"] = sorted(roles)
    if (not isinstance(result["requireWebAuthn"], bool)
            or not isinstance(result["threshold"], int) or isinstance(result["threshold"], bool)
            or result["threshold"] < 1 or not isinstance(result["credentialPolicy"], Mapping)):
        return None
    result["credentialPolicy"] = dict(result["credentialPolicy"])
    return result


def digest(arguments: Mapping[str, Any]) -> str | None:
    """Original authority domain-NUL plus length-prefixed canonical frame digest."""
    value = material(arguments)
    if value is None:
        return None
    frame = _canonical(value)
    hasher = hashlib.sha256()
    hasher.update(AUTHORITY_SCHEMA.encode("ascii"))
    hasher.update(b"\0")
    hasher.update(len(frame).to_bytes(8, "big"))
    hasher.update(frame)
    return "sha256:" + hasher.hexdigest()


def _require(condition):
    if not condition:
        raise ApproverPolicyError()


def _text(value, maximum):
    _require(type(value) is str and bool(value) and value == value.strip()
        and len(value.encode("utf-8")) <= maximum)


def _text_set(value, maximum):
    _require(type(value) is list)
    for item in value:
        _text(item, maximum)
    _require(value == sorted(set(value)))


def _jit_policy(policy):
    _require(type(policy) is dict and set(policy) == _POLICY_FIELDS)
    _require(policy["schema"] == JIT_SCHEMA and policy["roleMatch"] == "any"
        and policy["requireWebAuthn"] is True and type(policy["allowAnyApproverId"]) is bool
        and type(policy["threshold"]) is int and 1 <= policy["threshold"] <= 16)
    _text_set(policy["requiredRoles"], 128)
    _require(normalize_rbac_roles(policy["requiredRoles"], require_nonempty=False)
        == policy["requiredRoles"])
    _text_set(policy["allowedApproverIds"], 512)
    if policy["allowAnyApproverId"]:
        _require(not policy["allowedApproverIds"])
    else:
        _require(bool(policy["allowedApproverIds"])
            and policy["threshold"] <= len(policy["allowedApproverIds"]))
    credential = policy["credentialPolicy"]
    _require(type(credential) is dict and set(credential) == _CREDENTIAL_FIELDS)
    for name, maximum in (("allowedCredentialRecordIds", 512),
            ("allowedAuthenticatorClasses", 64), ("allowedAaguids", 128)):
        _text_set(credential[name], maximum)
    _require(type(credential["requireAttestationTrusted"]) is bool
        and credential["requireUserPresence"] is True
        and credential["requireUserVerification"] is True
        and credential["counterPolicy"] in ("strict", "strict-or-zero")
        and type(credential["maxAssertionAgeSeconds"]) is int
        and 1 <= credential["maxAssertionAgeSeconds"] <= 30)
    trust = credential["requiredTrustBundleDigest"]
    _require(trust is None or (type(trust) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", trust) is not None))
    sequence = credential["minimumTrustBundleSequence"]
    _require(sequence is None or (type(sequence) is int and sequence >= 1))
    _text(credential["rpId"], 253)
    _require(type(credential["origins"]) is list and len(credential["origins"]) == 1)
    _text(credential["origins"][0], 2048)
    _require(len(_canonical(policy)) <= 64 * 1024)


def from_jit_policy(policy: dict[str, Any]) -> str:
    """Project a canonical stored JIT policy through the real authority producer.

    The caller separately validates the stored JSON/digest and configured RP and
    origin. No stored fields, schema names, or JIT digest are rewritten here.
    """
    try:
        _jit_policy(policy)
        result = digest({
            "required_roles": policy["requiredRoles"],
            "allowed_approver_ids": None if policy["allowAnyApproverId"]
                else policy["allowedApproverIds"],
            "require_webauthn": policy["requireWebAuthn"],
            "threshold": policy["threshold"],
            "credential_policy": policy["credentialPolicy"],
        })
        _require(type(result) is str)
        return result
    except Exception:
        raise ApproverPolicyError() from None
