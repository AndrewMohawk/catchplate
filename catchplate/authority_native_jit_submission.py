"""Closed transient submission and commitment-only native JIT retention.

The five original strings travel only between the actual verifier and planner.
Each independently verifies native custody using its own admitted configuration
and the invocation's unchanged deadline. Only the four public/sealed originals
may enter a measured plan. Parsing or returning those originals is not proof of
admission, a writer capability, permission to open review documents, or replay.

The original parent request is never extended or rewritten: its native-signed
identity remains the ordinary seven-field release request. A fresh submission
must pass fresh custody even if an earlier operation might have committed.
"""
from __future__ import annotations

from functools import wraps
import time

from catchplate import authority_contract as contract
from catchplate import authority_native_jit_review_assignment as grammar
from catchplate import authority_native_jit_review_custody as custody
from catchplate import authority_release_private_input as public_guard
from catchplate import authority_release_private_request as private
from catchplate import native_jit_review_material as material


SCHEMA = "catchplate.nativeJitPendingSubmission/v1"
PLANNER_FIELD = "nativeJitSubmission"
RETAINED_FIELD = "nativeJitPending"
RETAINED_FIELDS = frozenset({"parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal"})
SUBMISSION_FIELDS = RETAINED_FIELDS | {"schema", "runtimeOriginal"}
ERROR = "Native JIT pending submission is unavailable"


class SubmissionError(ValueError):
    def __init__(self):
        super().__init__(ERROR)


def selected(request):
    """Select source-declared commitment grammar, not custody or permission."""
    return (type(request) is dict and request.get("operation") == private.OPERATION
        and type(request.get("arguments")) is dict
        and request["arguments"].get("schema") == private.PUBLIC_SCHEMA)


def _require(condition):
    if not condition:
        raise SubmissionError()


def _checked(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            # Originals can contain private URLs and review documents. Never
            # expose values or nested parser exceptions to logs or callers.
            raise SubmissionError() from None
    return checked


def _original(value, maximum):
    grammar.document(value, maximum)
    return value


def _retained(value):
    _require(type(value) is dict and set(value) == RETAINED_FIELDS)
    owned = {
        "parentOriginal": _original(value["parentOriginal"], custody.MAX_ORIGINAL_BYTES),
        "childOriginal": _original(value["childOriginal"], custody.MAX_ORIGINAL_BYTES),
        "pairOriginal": _original(value["pairOriginal"], custody.MAX_PAIR_BYTES),
        "evidenceOriginal": _original(value["evidenceOriginal"], custody.MAX_EVIDENCE_BYTES),
    }
    # JSON string escaping is part of the actual transport/storage bound.
    _require(len(grammar.canonical(owned)) <= contract.MAX_REQUEST_BYTES)
    return owned


@_checked
def parse_submission(value):
    """Own a bounded literal channel; perform no cryptographic admission."""
    _require(type(value) is dict and set(value) == SUBMISSION_FIELDS
        and value["schema"] == SCHEMA)
    owned = {"schema": SCHEMA,
        "runtimeOriginal": _original(value["runtimeOriginal"], custody.MAX_ORIGINAL_BYTES),
        **_retained({name: value[name] for name in RETAINED_FIELDS})}
    _require(len(grammar.canonical(owned)) <= contract.MAX_REQUEST_BYTES)
    return owned


@_checked
def retained_from_submission(value):
    """Drop the private runtime channel, never serialize a parsed runtime."""
    owned = parse_submission(value)
    return {name: owned[name] for name in RETAINED_FIELDS}


@_checked
def public_request_from_submission(value):
    owned = parse_submission(value)
    runtime = grammar.document(owned["runtimeOriginal"], custody.MAX_ORIGINAL_BYTES)
    derived = private.derive_native_requests(runtime)
    _require(grammar.canonical(derived.parent_request).decode("ascii") == owned["parentOriginal"]
        and grammar.canonical(derived.child_request).decode("ascii") == owned["childOriginal"])
    retained_documents(retained_from_submission(owned), typed_request=derived.parent_request)
    return derived.parent_request


@_checked
def name_guard_arguments(arguments, *, typed=False):
    """Project one source-fixed policy boolean for the generic name guard.

    ``requireAttestationTrusted`` is a requested approver-policy constraint,
    not a caller attestation verdict. Validate the complete native commitment
    grammar first, then omit only that scalar at its exact declared locations
    from this temporary guard projection. The signed input is never changed.
    Arbitrary public JSON and every other policy field remain under the guard.
    """
    owned = private.public_arguments(arguments, typed=typed)
    _require(owned["native_profile"] is True and owned["policy_aware_profile"] is False)
    parents = [owned]
    if typed:
        parents.append(owned["businessIntent"]["arguments"])
    for parent in parents:
        for candidate in (parent, parent["jit_approval_request"]):
            policy = candidate["approver_credential_policy"]
            if "requireAttestationTrusted" in policy:
                _require(type(policy["requireAttestationTrusted"]) is bool)
                candidate["approver_credential_policy"] = {name: item for name, item in policy.items()
                    if name != "requireAttestationTrusted"}
    return owned


@_checked
def retained_documents(value, *, typed_request):
    """Parse public/sealed originals and join exact bytes; NOT admission.

    This is usable by deterministic kernels and retention guards after their
    actual authority owners have admitted the operation. There is no returned
    verified flag or authority-bearing object, and no private document input.
    """
    owned = _retained(value)
    parent = grammar.document(owned["parentOriginal"], custody.MAX_ORIGINAL_BYTES)
    child = grammar.document(owned["childOriginal"], custody.MAX_ORIGINAL_BYTES)
    pair = grammar.document(owned["pairOriginal"], custody.MAX_PAIR_BYTES)
    proof = custody.authority_evidence(owned["evidenceOriginal"])
    _require(type(typed_request) is dict
        and grammar.canonical(typed_request).decode("ascii") == owned["parentOriginal"])
    public = private.public_arguments(parent["arguments"], typed=True)
    _require(public["native_profile"] is True and public["policy_aware_profile"] is False
        and public["now_epoch_ms"] is None)
    parent_public = {name: item for name, item in public.items() if name != "businessIntent"}
    expected_parent = private._derive_request(private.OPERATION, parent_public)
    expected_child = private._derive_request("jit.request", public["jit_approval_request"])
    _require(grammar.canonical(expected_parent).decode("ascii") == owned["parentOriginal"]
        and grammar.canonical(expected_child).decode("ascii") == owned["childOriginal"])
    _require(type(pair) is dict and set(pair) == material.PAIR_FIELDS
        and pair["schema"] == material.RELEASE_PAIR_SCHEMA)
    scope = material.validate_release_scope(pair["scope"])
    statement = proof["statement"]
    _require(grammar.canonical(scope["publicRequest"]).decode("ascii") == owned["childOriginal"]
        and scope["sourceContractDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and scope["parentRequestSha256"] == grammar.sha256(owned["parentOriginal"].encode("ascii"))
        and statement["sourceContractDigest"] == scope["sourceContractDigest"]
        and statement["parentRequestSha256"] == scope["parentRequestSha256"]
        and statement["parentRequestDigest"] == parent["requestDigest"]
        and statement["parentOperationId"] == parent["operationId"]
        and statement["requestDigest"] == child["requestDigest"]
        and statement["operationId"] == child["operationId"]
        and statement["publicRequestSha256"] == grammar.sha256(owned["childOriginal"].encode("ascii"))
        and statement["pairSha256"] == grammar.sha256(owned["pairOriginal"].encode("ascii"))
        and statement["secretKekId"] == pair["keyId"]
        and statement["expiresAtEpochNs"] == scope["sealExpiresAtEpochNs"])
    for name in ("controlPlaneConfigurationDigest", "ownerScopeDigest", "issuedAtEpochNs",
            "documentExpiresAtEpochNs"):
        _require(statement[name] == scope[name])
    grammar.kek(pair["keyId"])
    items = pair["items"]
    _require(type(items) is list and len(items) == 2)
    for item, kind, purpose in zip(items,
            ("approval-secret-json/v1", "approval-review-json/v1"),
            ("jit-canonical-request", "jit-redacted-display"), strict=True):
        _require(type(item) is dict and set(item) == material.ITEM_FIELDS
            and item["valueKind"] == kind
            and item["opaqueId"] == material._identity(child["requestDigest"], purpose))
        grammar.digest(item["plaintextSha256"])
        size = grammar.integer(item["plaintextBytes"], maximum=material.MAX_PLAINTEXT_BYTES)
        material._decoded(item["wrappedKeyNonce"], 12, 12)
        material._decoded(item["wrappedKey"], 48, 48)
        material._decoded(item["ciphertextNonce"], 12, 12)
        material._decoded(item["ciphertext"], material.MAX_PLAINTEXT_BYTES + 16, size + 16)
    _require(items[1]["plaintextSha256"] == child["arguments"]["redacted_display_digest"])
    return parent, child, pair, proof


@_checked
def validate_retained(value, *, typed_request, deadline_epoch_ns=None):
    _parent, _child, _pair, proof = retained_documents(value, typed_request=typed_request)
    if deadline_epoch_ns is not None:
        _require(grammar.integer(deadline_epoch_ns) <= proof["statement"]["expiresAtEpochNs"])


@_checked
def require_retained_request(typed_request, *, retained=None, operation=None, deadline_epoch_ns=None):
    """Keep the legacy refusal; allow only the joined commitment-only profile."""
    if retained is None:
        public_guard.require_public_request(typed_request, operation=operation)
        return
    _require(operation in (None, private.OPERATION)
        and type(typed_request) is dict and typed_request.get("operation") == private.OPERATION)
    validate_retained(retained, typed_request=typed_request, deadline_epoch_ns=deadline_epoch_ns)


@_checked
def verify_submission(value, *, typed_request, configuration_payload, root_key,
        now_epoch_ns, deadline_monotonic_ns, deadline_epoch_ns=None):
    """Independently verify literal native evidence; return no admission token."""
    owned = parse_submission(value)
    validate_retained(retained_from_submission(owned), typed_request=typed_request,
        deadline_epoch_ns=deadline_epoch_ns)
    custody.verify_original(runtime_original=owned["runtimeOriginal"],
        parent_original=owned["parentOriginal"], child_original=owned["childOriginal"],
        pair_original=owned["pairOriginal"], evidence_original=owned["evidenceOriginal"],
        configuration_payload=configuration_payload, root_key=root_key,
        now_epoch_ns=now_epoch_ns, deadline_monotonic_ns=deadline_monotonic_ns)
    if deadline_epoch_ns is not None:
        _require(time.time_ns() < deadline_epoch_ns)
    _require(time.monotonic_ns() < deadline_monotonic_ns)
