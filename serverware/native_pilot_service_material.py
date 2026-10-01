"""Publish four approved public originals, never initialize native journals.

Complete prior service inputs/grants remain authenticated. Pure helpers verify
their byte associations, not installation or resource ownership. The live
installer retains the actual protected grant/launch originals and their named
ancestors before any exclusive publication. Existing or partial paths are never
adopted, replaced or removed; one attempt consumes this process's capability.
No credential, private key, ciphertext or service journal is opened here.
"""
from __future__ import annotations

import copy
import os
import threading
import time

from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_adopted_service_authority as adopted_services
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_native_service_profile as services
from serverware import native_pilot_publication as publication
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_originals as originals
from serverware.native_shadow_proof_cohort_control import _Original

p = services.p
POLICY_API = "serverware.nativePilotServiceMaterialPolicy/v1"
API = "serverware.nativePilotServiceMaterialBundle/v1"
RESULT_API = "serverware.nativePilotServiceMaterialInstallation/v1"
ADOPTED_POLICY_API = "serverware.nativePilotServiceMaterialPolicy/v2"
ADOPTED_API = "serverware.nativePilotServiceMaterialBundle/v2"
ADOPTED_RESULT_API = "serverware.nativePilotServiceMaterialInstallation/v2"
ROLES = ("persistence", "generationInstall")
MAX_POLICY = 4096
MAX_INPUT = 64 * 1024 * 1024
SLOTS = {"native-persistence-configuration": p.MAX_CONFIG, "native-persistence-genesis": 16384,
    "native-persistence-journal": 1024, "native-generation-install-genesis": 512 * 1024}
ADOPTED_SLOTS = SLOTS | {"native-persistence-service-input": adopted_services.MAX_INPUT}
_ATTEMPTED = False


def validate_policy(fragment, *, adopted=False):
    p.fields(fragment, ("apiVersion", "initialization"))
    p.require(type(adopted) is bool and fragment["apiVersion"] == (ADOPTED_POLICY_API if adopted else POLICY_API)
        and fragment["initialization"] == ("adopted-persistence-and-generation" if adopted else "fresh-persistence-and-generation")
        and len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def shape(purpose, raw):
    """Closed existing public grammars; neither keys nor approvals are trusted."""
    if purpose == "native-persistence-service-input":
        return adopted_services.input_document("persistence", raw)
    p.require(purpose in SLOTS)
    value = p.document(raw, SLOTS[purpose])
    if purpose == "native-persistence-configuration":
        p.fields(value, admission.CONFIG_FIELDS)
        p.require(value["apiVersion"] == "serverware.nativeShadowNitroVerifierConfiguration/v2")
        services._verifier({name: value[name] for name in services.VERIFIER_FIELDS})
        operation = p.fields(value["operation"], ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "issuedAtBoottimeNs", "deadlineBoottimeNs"))
        p.require(p.decoded(operation["bootIdBase64url"], size=16) != bytes(16))
        for field in ("timeNamespaceDevice", "timeNamespaceInode"):
            p.integer(operation[field], maximum=p.MAX_U64)
        p.require(0 < p.ns(operation["deadlineBoottimeNs"]) - p.ns(operation["issuedAtBoottimeNs"]) <= 30_000_000_000)
        for name, fields in (("authorization", p.AUTH_FIELDS), ("admissionAuthorization", admission.ADMISSION_FIELDS)):
            signed = p.fields(value[name], ("payload", "signature"))
            p.fields(signed["payload"], fields); p.decoded(signed["signature"], size=64)
        p.require(value["authorization"]["payload"]["apiVersion"] == "serverware.nativeShadowRoleKeyAssignment/v2"
            and value["admissionAuthorization"]["payload"]["apiVersion"] == "serverware.nativeShadowKeyAdmissionAssignment/v1")
        scope = p.fields(value["expectedScope"], admission.SCOPE_FIELDS)
        p.require(scope["apiVersion"] == "serverware.nativeShadowKeyAdmissionScope/v1"
            and scope["purpose"] == "native-shadow-key-admission")
        p.guest(scope["guest"])
        p.require(type(value["authorityKeys"]) is list and len(value["authorityKeys"]) == len(p.ROLES))
        for role, key in zip(p.ROLES, value["authorityKeys"], strict=True):
            p.public_key(key); p.require(key["role"] == role)
        checkpoint = p.fields(value["trustCheckpoint"], ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256"))
        p.digest(checkpoint["checkpointId"]); p.digest(checkpoint["revocationRootSha256"])
        p.integer(checkpoint["asOfUnixNanos"]); p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    elif purpose == "native-persistence-journal":
        p.fields(value, ("genesisSha256", "headSequence", "headSha256"))
        p.digest(value["genesisSha256"])
        p.require(type(value["headSequence"]) is int and value["headSequence"] == 0
            and value["headSha256"] == value["genesisSha256"])
    else:
        generation = purpose == "native-generation-install-genesis"
        p.fields(value, ("apiVersion", "guest", "assignmentPayloadSha256", "servicesSha256") if generation
            else ("apiVersion", "proofScopeSha256", "guest"))
        p.require(value["apiVersion"] == ("serverware.nativeGenerationCoordinatorGenesis/v1" if generation
            else "serverware.nativeShadowPersistenceGenesis/v1"))
        p.guest(value["guest"])
        p.require(value["guest"]["serviceRole"] == "production-bridge")
        for field in (("assignmentPayloadSha256", "servicesSha256") if generation else ("proofScopeSha256",)):
            p.digest(value[field])
    return value


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _pin(purpose, raw):
    return {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)}


def _materials(values):
    """Copy exact selected public originals; create no genesis or record."""
    p.require(type(values["generationInstall"]["recordOriginals"]) is list
        and values["generationInstall"]["recordOriginals"] == [])
    selections = (("native-persistence-configuration", "persistence", "configurationOriginal"),
        ("native-persistence-genesis", "persistence", "genesisOriginal"),
        ("native-persistence-journal", "persistence", "journalOriginal"),
        ("native-generation-install-genesis", "generationInstall", "genesisOriginal"))
    prepared = {}
    for purpose, role, field in selections:
        raw, _ = c9._original(values[role][field], SLOTS[purpose])
        shape(purpose, raw)
        prepared[purpose] = raw
    pins = {purpose: _pin(purpose, raw) for purpose, raw in prepared.items()}
    material = {"persistence": {name: pins["native-persistence-" + name] for name in ("configuration", "genesis", "journal")},
        "generationJournal": {"genesis": pins["native-generation-install-genesis"], "records": []}}
    return prepared, pins, material


def prepare_bundle(bundle_original, *, boot, now_boottime_ns, now_unix_ns, adopted=False):
    value = p.fields(p.document(bundle_original, MAX_INPUT), ("apiVersion", "serviceContexts", "endpointLaunches"))
    p.require(type(adopted) is bool and value["apiVersion"] == (ADOPTED_API if adopted else API))
    p.fields(value["serviceContexts"], ROLES); p.fields(value["endpointLaunches"], ROLES)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    contexts, inputs, native, retained, launches = {}, {}, {}, {}, {}
    for role in ROLES:
        row = p.fields(value["serviceContexts"][role], ("inputOriginal", "grantOriginal"))
        input_raw, inputs[role] = c9._original(row["inputOriginal"], services.MAX_INPUT)
        grant_raw, _ = c9._original(row["grantOriginal"], services.MAX_OUTPUT)
        checked = services.checked_adopted_result if adopted else services.checked_result
        prepare = services.prepare_adopted_input if adopted else services.prepare_input
        checked(role, input_raw, {"original": row["grantOriginal"], "sha256": p.sha(grant_raw)}, **clocks)
        contexts[role] = prepare(role, input_raw, **clocks)
        item = inputs[role]
        _, native[role] = c9._original(item["configurationOriginal" if role == "persistence" else "nativeConfigurationOriginal"], p.MAX_CONFIG)
        grant_purpose = launch._grant_purpose(role)
        retained[grant_purpose] = grant_raw
        pin = value["endpointLaunches"][role]
        launch.delivery._pin(pin)
        p.require(pin["path"] == launch.DESTINATIONS["native-launch-" + role])
        cold = item["coldConfigurationOriginal" if role == "persistence" else "coordinatorConfigurationOriginal"].encode("ascii")
        delivery = item["deliveryOriginal" if role == "persistence" else "coordinatorDeliveryOriginal"].encode("ascii")
        key_raw = p.canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2", "authorization": native[role]["authorization"]})
        launches[role] = {"pin": copy.deepcopy(pin), "grant": _pin(grant_purpose, grant_raw),
            "inner": {"deliveryConfiguration": _pin("native-cold-" + role, cold),
                "delivery": _pin("native-delivery-" + role, delivery),
                "keys": _pin("native-" + role + "-keys", key_raw),
                "admission": _pin("native-" + role + "-admission", p.canonical(native[role]["admissionAuthorization"]))}}
    for name in ("cohortConfigurationOriginal", "precreationOriginal", "observationOriginal", "assignmentPayloadOriginal"):
        p.require(inputs["persistence"][name] == inputs["generationInstall"][name])
    for name in ("authorityKeys", "trustCheckpoint"):
        _same(native["persistence"][name], native["generationInstall"][name])
    for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "fullKeySetRootSha256"):
        _same(native["persistence"]["expectedScope"][name], native["generationInstall"]["expectedScope"][name])
    window = contexts["persistence"]["window"]
    _same(window, contexts["generationInstall"]["window"])
    prepared, pins, material = _materials(inputs)
    if adopted:
        # The actual Persistence owner rechecks this complete issuer input.
        # Publish its authenticated literal bytes, not a reconstructed recipe.
        purpose = "native-persistence-service-input"
        raw = value["serviceContexts"]["persistence"]["inputOriginal"].encode("ascii")
        shape(purpose, raw)
        prepared[purpose], pins[purpose] = raw, _pin(purpose, raw)
        material["persistenceServiceInput"] = pins[purpose]
    deadline = min(item["deadline"] for item in contexts.values())
    expiry = min(min(item["epochLimit"], item["payload"]["expiresAtUnixNanos"]) for item in contexts.values())
    p.require(now_boottime_ns < deadline and now_unix_ns < expiry)
    return {"window": window, "deadline": deadline, "epochLimit": expiry, "prepared": prepared,
        "pins": pins, "material": material, "retained": retained, "launches": launches}


def build(*, fragment, service_contexts, endpoint_launches, boot, now_boottime_ns, now_unix_ns, adopted=False):
    validate_policy(fragment, adopted=adopted)
    p.fields(service_contexts, ROLES); p.fields(endpoint_launches, ROLES)
    contexts = {}
    for role, item in service_contexts.items():
        p.fields(item, ("inputOriginal", "grantOriginal"))
        contexts[role] = {}
        for name, maximum in (("inputOriginal", services.MAX_INPUT), ("grantOriginal", services.MAX_OUTPUT)):
            raw = item[name]
            p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
            contexts[role][name] = raw.decode("ascii")
    raw = p.canonical({"apiVersion": ADOPTED_API if adopted else API, "serviceContexts": contexts, "endpointLaunches": endpoint_launches})
    prepare_bundle(raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=adopted)
    return raw


def _result(raw, context, *, adopted=False):
    return {"apiVersion": ADOPTED_RESULT_API if adopted else RESULT_API, "bundleSha256": p.sha(raw),
        **{name: context["window"][name] for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")},
        "material": context["material"], "pins": context["pins"]}


def checked_result(bundle_original, result, *, boot, now_boottime_ns, now_unix_ns, adopted=False):
    context = prepare_bundle(bundle_original, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=adopted)
    expected = _result(bundle_original, context, adopted=adopted)
    p.fields(result, tuple(expected)); _same(result, expected)
    return copy.deepcopy(expected)


def install(bundle_original, *, expected_sha256):
    """One approved four-file attempt; complete and partial paths remain."""
    return _install(bundle_original, expected_sha256=expected_sha256, adopted=False)


def install_adopted(bundle_original, *, expected_sha256):
    """One selected five-file attempt, including retained persistence input."""
    return _install(bundle_original, expected_sha256=expected_sha256, adopted=True)


def _install(bundle_original, *, expected_sha256, adopted):
    global _ATTEMPTED
    p.require(not _ATTEMPTED and threading.current_thread() is threading.main_thread()
        and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
    _ATTEMPTED = True
    held, publisher = [], None
    try:
        p.require(type(bundle_original) is bytes and 0 < len(bundle_original) <= MAX_INPUT
            and p.sha(bundle_original) == p.digest(expected_sha256))
        boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
        context = prepare_bundle(bundle_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall, adopted=adopted)

        def retain(pin, maximum):
            original = _Original(pin["path"], maximum, pin["sha256"])
            held.append(original)
            return original.raw

        for purpose, raw in context["retained"].items():
            p.require(retain(_pin(purpose, raw), (launch.ADOPTED_PURPOSES if adopted else publication.LIMITS)[purpose]) == raw)
        for role, row in context["launches"].items():
            raw = retain(row["pin"], launch.PURPOSES["native-launch-" + role])
            value = (launch.shape_adopted if adopted else launch.shape)("native-launch-" + role, raw)
            for name, pin in row["inner"].items():
                _same(value["keyAdmission"][name], pin)
            _same(value[launch.LAUNCHES[role][1]], row["grant"])

        def check(previous, previous_wall):
            for original in held:
                original.check()
            if publisher is not None:
                publisher.check()
            p.require(originals._boot() == boot)
            now, current_wall = c9._live(context["window"], previous), time.time_ns()
            final = originals._clock()
            p.require(now <= final < context["deadline"]
                and previous_wall <= current_wall < context["epochLimit"])
            return final, current_wall

        before, wall = check(before, wall)
        publisher = publication.PublicPublisher.open()
        publisher.require_absent(tuple(ADOPTED_SLOTS if adopted else SLOTS))
        before, wall = check(before, wall)
        for purpose, raw in context["prepared"].items():
            before, wall = check(before, wall)
            _same(publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw)), context["pins"][purpose])
            before, wall = check(before, wall)
        result = checked_result(bundle_original, _result(bundle_original, context, adopted=adopted),
            boot=boot, now_boottime_ns=before, now_unix_ns=wall, adopted=adopted)
        before, wall = check(before, wall)
    finally:
        if publisher is not None:
            publisher.close()
        for original in reversed(held):
            original.close()
    # Successful close consumes the same original installation window too.
    p.require(originals._boot() == boot)
    final, final_wall = c9._live(context["window"], before), time.time_ns()
    p.require(final <= originals._clock() < context["deadline"] and wall <= final_wall < context["epochLimit"])
    return result
