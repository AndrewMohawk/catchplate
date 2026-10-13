"""Join native JIT envelope retention to the locked original planner bytes.

This is a retention integrity check, not native custody or signature admission.
The measured planner/verifier own those checks. No raw runtime input, private
review document, SQL write, clock renewal or replay authority is accepted here.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import re
from typing import Any

from serverware import authority_contract as contract
from serverware import authority_native_jit_review_assignment as grammar
from serverware import authority_native_jit_submission as submission


ERROR = "Native JIT retained execution binding is not exact"


def require_locked_plan(row: Mapping[str, Any], *, typed_request: dict[str, Any],
                        retained: dict[str, str], deadline_epoch_ns: int) -> None:
    """Require the exact supplied four originals already retained by this plan.

    The caller owns the locked v3 planner row and its operation, capability,
    request, projection and original deadline bindings. Returning None is not
    permission to retain or execute; all existing writer checks still apply.
    """
    try:
        if type(retained) is not dict:
            raise ValueError(ERROR)
        encoded = row["exact_plan_base64url"]
        if (type(encoded) is not str or not encoded
                or len(encoded) > (contract.MAX_RESULT_BYTES * 4 + 2) // 3
                or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None):
            raise ValueError(ERROR)
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        if (base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded
                or not 2 <= len(raw) <= contract.MAX_RESULT_BYTES
                or type(row["exact_plan_byte_count"]) is not int
                or row["exact_plan_byte_count"] != len(raw)
                or row["exact_plan_bytes_digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()):
            raise ValueError(ERROR)
        payload = grammar.document(raw.decode("ascii"), contract.MAX_RESULT_BYTES)
        plan = payload["measuredPlan"]
        if (payload.get("schema") != "serverware.policyAuthorityPlannerResponse/v3"
                or grammar.canonical(payload["typedRequest"]) != grammar.canonical(typed_request)
                or payload[submission.RETAINED_FIELD] != retained
                or type(plan) is not dict or plan.get("operation") != "release.reserve"
                or type(plan.get("deadlineEpochNs")) is not int
                or plan["deadlineEpochNs"] != deadline_epoch_ns):
            raise ValueError(ERROR)
        submission.require_retained_request(typed_request, retained=retained,
            operation=plan["operation"], deadline_epoch_ns=deadline_epoch_ns)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError(ERROR) from None
