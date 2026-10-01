"""Fixed late launch authorizations from actual authenticated C9/key originals.

Policy selects original intervals and existing encrypted transport commitments,
not future guests, keys, signatures or observations. Pure preparation does not
perform KMS operations or attest an enclave. Native receivers retain those checks.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_encrypted_authority as encrypted
from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_verifier_authority as verifier
from serverware import native_shadow_key_contract as transport

p = keys.p
API = "serverware.nativePilotLaunchAuthorizationPolicy/v1"
ROLES = keys.ROLES
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
WINDOW_FIELDS = ("issuedAtUnixNanos", "expiresAtUnixNanos")
JOBS = tuple((operation, role) for role in ROLES for operation in
    (("closure", "request-commitment", "encrypted-delivery", "verifier-transport") if role == "commitRequest"
     else ("closure", "encrypted-delivery", "verifier-transport")))
MAX_POLICY = 256 * 1024


def job_name(operation, role):
    p.require((operation, role) in JOBS)
    return "native-" + operation + "-" + role


def _window(value):
    p.require(p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))


def validate_policy(fragment):
    p.fields(fragment, ("apiVersion", "endpoints"))
    p.require(fragment["apiVersion"] == API and len(p.canonical(fragment)) <= MAX_POLICY)
    for role, row in p.fields(fragment["endpoints"], ROLES).items():
        fields = ("closure", "encryptedDelivery", "verifierTransport")
        p.fields(row, fields + (("requestCommitment",) if role == "commitRequest" else ()))
        p.fields(row["closure"], WINDOW_FIELDS)
        _window(row["closure"])
        settings = p.fields(row["encryptedDelivery"], WINDOW_FIELDS + ("transportOriginal",))
        _window(settings)
        _, selected = c9._original(settings["transportOriginal"], 16384)
        transport.transport(selected)
        p.require(selected["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v"
            + ("2" if role == "commitRequest" else "1"))
        settings = p.fields(row["verifierTransport"], WINDOW_FIELDS + ("parentPort",))
        _window(settings)
        p.integer(settings["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
        if role == "commitRequest":
            settings = p.fields(row["requestCommitment"], WINDOW_FIELDS + ("requestCommitmentOriginal",))
            _window(settings)
            _, descriptor = c9._original(settings["requestCommitmentOriginal"], 4096)
            transport.commitment(descriptor)
    return copy.deepcopy(fragment)


def _pair(role, pair_context, clocks):
    p.fields(pair_context, PAIR_FIELDS)
    raw = {name: c9._original(pair_context[name], keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT)[0]
        for name in PAIR_FIELDS}
    admitted = keys.admitted_pair(role, raw["roleKeyInputOriginal"], raw["roleKeyOriginal"],
        raw["admissionInputOriginal"], raw["admissionOriginal"], **clocks)
    prepared = keys.prepare_input("admission", role, raw["admissionInputOriginal"], **clocks)
    original = p.document(raw["roleKeyInputOriginal"], keys.MAX_INPUT)
    return admitted, prepared, original


def _closure_input(role, row, pair, prepared, original):
    delivery_raw, _ = c9._original(original["deliveryInputOriginal"], c9.MAX_INPUT)
    delivered = p.fields(p.document(delivery_raw, c9.MAX_INPUT), c9.INPUT_FIELDS)
    recipe = original["recipeOriginals"]
    _, envelope = c9._original(recipe["assignmentOriginal"], 4 * 1024 * 1024)
    set_raw, _ = c9._original(recipe["closureSetOriginal"], closure.MAX_BYTES)
    leaf = assignment.closure_binding(envelope, set_raw, role)
    checkpoint = prepared["trustCheckpoint"]
    supervisor = prepared["authorityKeys"][-1]
    payload = {"apiVersion": "serverware.nativeCustodyClosureAssignment/v3",
        "purpose": "shadow-custody-closure-set-member", "profile": closure.SET_PROFILE,
        "assignmentId": envelope["payload"]["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": envelope["payload"]["assignmentRevision"],
        "manifestSha256": prepared["manifest"]["manifestSha256"], "guest": pair["expectedScope"]["guest"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], **row,
        "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"],
        "guestRole": role, **{name: leaf[name] for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256")}}
    return {"apiVersion": "serverware.nativePilotClosureAuthorityInput/v2", "guestRole": role,
        "configurationOriginal": delivered["ownerConfigurationOriginal"], "windowOriginal": delivered["windowOriginal"],
        "observationOriginal": delivered["observationOriginal"],
        "deliveryConfigurationOriginal": delivered["configurationOriginal"], "deliveryOriginal": original["deliveryOriginal"],
        "runtimeOriginal": delivered["runtimeOriginal"], "trustOriginal": recipe["trustOriginal"],
        "trustSha256": recipe["trustSha256"], "assignmentOriginal": recipe["assignmentOriginal"],
        "closureSetOriginal": recipe["closureSetOriginal"], "manifestOriginal": p.canonical(prepared["manifest"]).decode("ascii"),
        "payloadOriginal": p.canonical(payload).decode("ascii")}


def prepare_input(operation, role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    p.require((operation, role) in JOBS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    if operation == "closure":
        value = closure.prepare_input(input_raw, **clocks)
        p.require(value["payload"]["guestRole"] == role)
        return value
    if operation == "verifier-transport":
        return verifier.prepare_input(role, input_raw, **clocks)
    return encrypted.prepare_input("delivery" if operation == "encrypted-delivery" else operation,
        role, input_raw, **clocks)


def build(operation, role, *, fragment, pair_context, prior_authorization_originals,
          boot, now_boottime_ns, now_unix_ns) -> bytes:
    p.require((operation, role) in JOBS)
    fragment = validate_policy(fragment)
    p.fields(prior_authorization_originals,
        ("request-commitment",) if (operation, role) == ("encrypted-delivery", "commitRequest") else ())
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    pair, prepared, original = _pair(role, pair_context, clocks)
    row = fragment["endpoints"][role]
    maximum = keys.MAX_INPUT
    if operation == "closure":
        value = _closure_input(role, row["closure"], pair, prepared, original)
        maximum = closure.MAX_INPUT
    elif operation == "verifier-transport":
        value = {"apiVersion": verifier.API, "role": role, **pair_context, **row["verifierTransport"]}
    else:
        key = "encryptedDelivery" if operation == "encrypted-delivery" else "requestCommitment"
        value = {"apiVersion": encrypted.API, "operation": "delivery" if operation == "encrypted-delivery" else operation,
            "role": role, **pair_context, **row[key]}
        if operation == "encrypted-delivery" and role == "commitRequest":
            raw = prior_authorization_originals["request-commitment"]
            p.require(type(raw) is bytes and 0 < len(raw) <= keys.MAX_OUTPUT)
            signed = p.fields(p.document(raw, keys.MAX_OUTPUT), ("payload", "signature"))
            settings = row["requestCommitment"]
            _, descriptor = c9._original(settings["requestCommitmentOriginal"], 4096)
            p.require(signed["payload"]["requestCommitment"] == descriptor
                and all(signed["payload"][field] == settings[field] for field in WINDOW_FIELDS))
            # The encrypted producer below verifies its signature and full
            # guest/pair association. Also retain this policy's exact choice.
            value["requestCommitmentOriginal"] = raw.decode("ascii")
    raw = p.canonical(value)
    p.require(len(raw) <= maximum)
    prepare_input(operation, role, raw, **clocks)
    return raw


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    p.require((operation, role) in JOBS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    if operation == "closure":
        # Role is part of the independently approved input, not a result hint.
        value = p.document(input_raw, closure.MAX_INPUT)
        p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v2" and value["guestRole"] == role)
        return closure.checked_result(input_raw, result, **clocks)
    if operation == "verifier-transport":
        return verifier.checked_result(role, input_raw, result, **clocks)
    return encrypted.checked_result("delivery" if operation == "encrypted-delivery" else operation,
        role, input_raw, result, **clocks)


def prepare_adopted_input(operation, role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Only the explicitly approved hot12 issuer versions, never old fallback."""
    from serverware import native_pilot_launch_publication as launch
    p.require(role in launch.ADOPTED_ROLES and operation in ("closure", "encrypted-delivery", "verifier-transport"))
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    selected = p.document(input_raw, 32 * 1024 * 1024)
    expected = {"closure": "serverware.nativePilotClosureAuthorityInput/v3",
        "encrypted-delivery": "serverware.nativePilotEncryptedAuthorityInput/v2",
        "verifier-transport": "serverware.nativePilotVerifierAuthorityInput/v2"}[operation]
    p.require(selected["apiVersion"] == expected and selected["guestRole" if operation == "closure" else "role"] == role)
    if operation == "closure": return closure.prepare_input(input_raw, **clocks)
    if operation == "verifier-transport": return verifier.prepare_input(role, input_raw, **clocks)
    return encrypted.prepare_input("delivery", role, input_raw, **clocks)


def checked_adopted_result(operation, role, input_raw, result, **clocks):
    prepare_adopted_input(operation, role, input_raw, **clocks)
    if operation == "closure": return closure.checked_result(input_raw, result, **clocks)
    if operation == "verifier-transport": return verifier.checked_result(role, input_raw, result, **clocks)
    return encrypted.checked_result("delivery", role, input_raw, result, **clocks)
