"""Bridge-only public key assignments over actual late C9 originals.

These pure checks authenticate supplied originals, not kernel provenance or
independent approval. The complete input/trust pin must be independently
approved. Endpoint-only producers remain unchanged. The bridge closure leaf
commits bootstrap runtime; its late C9 separately commits operational runtime.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_assignment as assignments
from serverware import native_pilot_bridge_runtime as runtime
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_measured_configuration as measured_profile
from serverware import native_pilot_native_delivery_profile as native_delivery
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_bridge_admission_profile as admission
from serverware import native_shadow_guest_delivery as delivery

p = delivery.p
API = "serverware.nativePilotBridgeKeyAuthorityInput/v1"
ADOPTED_API = "serverware.nativePilotBridgeKeyAuthorityInput/v2"
OPERATIONS = ("role-keys", "admission")
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 65536
POLICY_FIELDS = ("localRoles", "challengeBase64url", "issuedAtUnixNanos", "expiresAtUnixNanos")
INPUT_FIELDS = ("apiVersion", "operation", "controlOriginal", "deliveryInputOriginal", "deliveryOriginal",
    "recipeOriginals", "measured", "policy")
DOMAINS = {"role-keys": "serverware.nativeShadowRoleKeyAssignment.signature/v2",
    "admission": admission.ADMISSION_DOMAIN}


def validate_policy(value):
    p.fields(value, POLICY_FIELDS)
    roles = value["localRoles"]
    p.require(type(roles) is list and 1 <= len(roles) <= 16
        and all(type(role) is str and role in p.ROLES[:16] for role in roles)
        and roles == sorted(set(roles), key=p.ROLES.index))
    p.require(p.decoded(value["challengeBase64url"], size=32) != bytes(32)
        and p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))
    return copy.deepcopy(value)


def _context(value, *, boot, now_boottime_ns, now_unix_ns, adopted=False):
    p.require(type(adopted) is bool)
    delivery_input, _ = c9._original(value["deliveryInputOriginal"], c9.MAX_BRIDGE_INPUT)
    source = c9.input_document(delivery_input)
    p.require(source["role"] == "bridge" and source["apiVersion"] ==
        ("serverware.nativePilotDeliverySigningInput/v3" if adopted else "serverware.nativePilotDeliverySigningInput/v1"))
    delivery_raw, signed = c9._original(value["deliveryOriginal"], delivery.MAX_DELIVERY)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    payload_raw, payload = c9._original(source["payloadOriginal"], delivery.MAX_DELIVERY)
    p.require(p.canonical(signed["payload"]) == payload_raw)
    _, activation = c9._original(source["activationOriginal"], 32768, array=True)
    c9._same(payload["activation"], activation)
    originals = p.fields(value["recipeOriginals"], native_delivery.RECIPE_FIELDS)
    measured = p.fields(value["measured"], native_delivery.MEASURED_FIELDS)
    p.require(measured["apiVersion"] == "serverware.nativePilotMeasuredConfiguration/v2")
    bridge = {"controlOriginal": value["controlOriginal"],
        "configurationOriginal": source["ownerConfigurationOriginal"],
        "windowOriginal": source["windowOriginal"], "observationOriginal": source["observationOriginal"],
        "deliveryConfigurationOriginal": source["configurationOriginal"],
        "deliveryOriginal": value["deliveryOriginal"], "runtimeOriginal": source["runtimeOriginal"], **originals}
    if adopted:
        bridge["deliveryInputOriginal"] = value["deliveryInputOriginal"]
        config, window, observed, guest = closure._adopted_bridge_guest(bridge, boot=boot, now=now_boottime_ns)
    else:
        config, window, observed, guest = closure._guest(bridge, boot=boot, now=now_boottime_ns)
    runtime_raw, _ = runtime.original(source["runtimeOriginal"])
    c9._same(payload["runtimeConfig"], {"path": publication.DESTINATIONS["bridge-runtime"], "sha256": p.sha(runtime_raw)})

    # Existing authenticated assignment/trust derivation, including all 18
    # independent authority records. No key declared by the candidate self-pins.
    envelope, bindings, key_root = measured_profile._assignment(
        {"apiVersion": measured_profile.ADOPTED_API if adopted else measured_profile.SET_API, **originals}, now_unix_ns)
    p.require(assignments.version(envelope) == 2)
    _, trust = c9._original(originals["trustOriginal"], 1024 * 1024)
    public = {row["role"]: row["key"]["publicKeyBase64url"] for row in trust["roleKeys"]}
    keys = [bindings[role] | {"publicKeyBase64url": public[role]} for role in p.ROLES]
    for field in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        p.require(len({key[field] for key in keys}) == 18)
    p.require(p.key_root(keys) == key_root)
    set_raw, _ = c9._original(originals["closureSetOriginal"], closure_set.MAX_BYTES)
    set_api = closure_set.PUBLICATION_API if adopted else closure_set.API
    selected = closure_set.validate(set_raw, api_version=set_api)
    manifest = selected["members"][-1]["manifest"]
    assignments.closure_binding(envelope, set_raw, "bridge", set_api_version=set_api)
    bridge["manifestOriginal"] = p.canonical(manifest).decode("ascii")
    closure._manifest(bridge, config, observed, envelope["payload"])
    p.fields(measured["production"], scope.PRODUCTION_FIELDS)
    derived = measured_profile.derive_configuration(envelope=envelope, keys=bindings, key_root=key_root,
        manifest=manifest, observed=observed, production={name: measured["production"][name]
            for name in measured_profile.PRODUCTION_FIELDS}, window=window,
        recipe_sha=measured["recipeSha256"], successor=True)
    c9._same(derived, measured)
    cold_raw, _ = c9._original(source["configurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    p.require(keys[-1]["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
        and keys[-1]["keyId"] != cold["authority"]["keyId"])
    return envelope, keys, trust, manifest, config, window, guest, signed["payload"]


def _verify(raw, operation, expected, key):
    signed = p.fields(p.document(raw, MAX_OUTPUT), ("payload", "signature"))
    p.fields(signed["payload"], p.AUTH_FIELDS if operation == "role-keys" else admission.ADMISSION_FIELDS)
    c9._same(signed["payload"], expected)
    p.public_key(key).verify(p.decoded(signed["signature"], size=64), p.preimage(DOMAINS[operation], expected))
    return signed


def prepare_input(operation, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    p.require(type(operation) is str and operation in OPERATIONS)
    value = p.fields(p.document(input_raw, MAX_INPUT),
        INPUT_FIELDS + (("roleKeyOriginal",) if operation == "admission" else ()))
    adopted = value["apiVersion"] == ADOPTED_API
    p.require(value["apiVersion"] in (API, ADOPTED_API) and value["operation"] == operation)
    row = validate_policy(value["policy"])
    p.integer(now_unix_ns)
    envelope, keys, trust, manifest, config, window, guest, delivered = _context(value,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=adopted)
    assignment, checkpoint = envelope["payload"], trust["checkpoint"]
    issued, expires = row["issuedAtUnixNanos"], row["expiresAtUnixNanos"]
    p.freshness(issued, expires, now_unix_ns)
    p.require(assignment["issuedAtUnixNanos"] <= issued < expires <= assignment["expiresAtUnixNanos"]
        and trust["issuedAtUnixNanos"] <= issued < expires <= trust["expiresAtUnixNanos"]
        and checkpoint["asOfUnixNanos"] <= issued < expires <= checkpoint["asOfUnixNanos"] + 300_000_000_000
        and expires - issued <= p.integer(assignment["observationWindow"]["maximumEvidenceAgeNanos"]))
    for key in [trust["assignmentKey"], trust["timeKey"], *(item["key"] for item in trust["roleKeys"])]:
        p.require(key["notBeforeUnixNanos"] <= issued < expires <= key["notAfterUnixNanos"])
    p.integer(checkpoint["revocationGeneration"], maximum=p.MAX_U64)
    common = {"assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": assignment["assignmentRevision"],
        "guest": guest, "executionClosureManifestSha256": manifest["manifestSha256"],
        "fullKeySetRootSha256": p.key_root(keys), "challengeBase64url": row["challengeBase64url"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires,
        "signingKeyId": keys[-1]["keyId"], "signingKeySpkiSha256": keys[-1]["keySpkiSha256"]}
    role_payload = {"apiVersion": "serverware.nativeShadowRoleKeyAssignment/v2",
        "profile": "preassigned-encrypted-local-v1", "purpose": "shadow-role-key-possession",
        "assignmentId": assignment["assignmentId"], **common, "localRoles": row["localRoles"]}
    p.fields(role_payload, p.AUTH_FIELDS)
    payload = role_payload
    if operation == "admission":
        role_raw, _ = c9._original(value["roleKeyOriginal"], MAX_OUTPUT)
        _verify(role_raw, "role-keys", role_payload, keys[-1])
        local = [key for key in keys if key["role"] in row["localRoles"]]
        payload = {"apiVersion": "serverware.nativeShadowBridgeAdmissionAssignment/v1",
            "purpose": "native-shadow-context-and-production-admission", **common,
            "keyAuthorizationSha256": p.sha(role_raw), "localKeySetRootSha256": p.key_root(local),
            "productionConfigurationBindingSha256": value["measured"]["configurationBindingSha256"]}
        p.fields(payload, admission.ADMISSION_FIELDS)
    result = {"payload": payload, "signature": ""}
    p.require(len(p.canonical(result)) + 86 <= MAX_OUTPUT)
    epoch_limit = min(expires, trust["issuedAtUnixNanos"] + p.DAY_NS + 1,
        assignment["issuedAtUnixNanos"] + p.DAY_NS + 1) if adopted else expires
    p.require(now_unix_ns < epoch_limit)
    return copy.deepcopy({"payload": payload, "supervisor": keys[-1], "window": window,
        "deadline": p.ns(window["startupDeadlineBoottimeNs"]), "epochLimit": epoch_limit,
        "domain": DOMAINS[operation], "result": result, "authorityKeys": keys, "trustCheckpoint": checkpoint,
        "manifest": manifest, "configuration": config, "delivery": delivered, "adopted": adopted})


def build(operation, *, control_original, delivery_input_raw, delivery_raw, recipe_originals,
          measured, policy, boot, now_boottime_ns, now_unix_ns, role_key_raw=None, adopted=False):
    p.require(type(adopted) is bool and operation in OPERATIONS and ((type(role_key_raw) is bytes)
        if operation == "admission" else role_key_raw is None))
    value = {"apiVersion": ADOPTED_API if adopted else API, "operation": operation, "controlOriginal": control_original.decode("ascii"),
        "deliveryInputOriginal": delivery_input_raw.decode("ascii"), "deliveryOriginal": delivery_raw.decode("ascii"),
        "recipeOriginals": recipe_originals, "measured": measured, "policy": policy}
    if operation == "admission":
        value["roleKeyOriginal"] = role_key_raw.decode("ascii")
    raw = p.canonical(value)
    prepare_input(operation, raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return raw


def checked_result(operation, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    context = prepare_input(operation, input_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw, _ = c9._original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    _verify(raw, operation, context["payload"], context["supervisor"])
    return raw


def admitted_pair(role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
                  *, boot, now_boottime_ns, now_unix_ns, adopted=False):
    """Verified bridge scope only; no fabricated native context or attestation."""
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    first = p.document(role_key_input_raw, MAX_INPUT)
    second = p.document(admission_input_raw, MAX_INPUT)
    p.require(type(adopted) is bool and first["apiVersion"] == second["apiVersion"] == (ADOPTED_API if adopted else API))
    for name in INPUT_FIELDS:
        if name != "operation":
            c9._same(first[name], second[name])
    p.require(second["roleKeyOriginal"] == role_key_raw.decode("ascii"))
    checked_result("role-keys", role_key_input_raw,
        {"original": role_key_raw.decode("ascii"), "sha256": p.sha(role_key_raw)}, **clocks)
    context = prepare_input("admission", admission_input_raw, **clocks)
    admitted = _verify(admission_raw, "admission", context["payload"], context["supervisor"])
    authorization = p.document(role_key_raw, MAX_OUTPUT)
    key, payload = authorization["payload"], admitted["payload"]
    expected = {"apiVersion": "serverware.nativeShadowBridgeAdmissionScope/v1",
        "purpose": "native-shadow-context-and-production-admission", "assignmentId": key["assignmentId"],
        **{name: payload[name] for name in ("assignmentPayloadSha256", "assignmentRevision", "keyAuthorizationSha256",
            "guest", "executionClosureManifestSha256", "fullKeySetRootSha256", "localKeySetRootSha256",
            "challengeBase64url", "productionConfigurationBindingSha256")},
        "admissionAuthorizationSha256": p.sha(admission_raw),
        "localKeys": [record for record in context["authorityKeys"] if record["role"] in key["localRoles"]],
        "structurallyVerifiedSeccompPolicySha256": context["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "workerExecutableSha256": context["manifest"]["workerExecutableSha256"]}
    p.fields(expected, admission.SCOPE_FIELDS)
    return copy.deepcopy({"authorization": authorization, "admissionAuthorization": admitted, "expectedScope": expected,
        "authorityKeys": context["authorityKeys"], "trustCheckpoint": context["trustCheckpoint"]})


def admitted_adopted_pair(role_key_input_raw, role_key_raw, admission_input_raw, admission_raw, **clocks):
    """Explicit hot12 bridge scope; never selected from a result's shape."""
    return admitted_pair(role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
        adopted=True, **clocks)
