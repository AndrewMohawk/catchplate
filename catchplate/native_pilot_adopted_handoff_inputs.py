"""Candidate adoption and endpoint pins over actual retained cold/hot originals.

Native adoption validation is still mandatory before signing. Public pins here
do not publish their files, attest their provenance or provision an object store.
"""
from __future__ import annotations

import copy

from cryptography.hazmat.primitives import serialization
from catchplate import native_pilot_adopted_ordinary as ordinary
from catchplate import native_pilot_adopted_phase_profile as profile
from catchplate import native_pilot_genesis_core_profile as core
from catchplate import native_pilot_genesis_jobs as cold

p, g = profile.p, profile.g
FAMILIES = ("adoption", "endpoint-inputs")
KEY_FIELDS = ("keyId", "keySpkiSha256", "publicKeyBase64url")
WINDOW_FIELDS = ("issuedAtUnixNanos", "expiresAtUnixNanos", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")


def selection_fields(selected):
    p.require(profile.BY_NAME.get(selected.name, (None, None))[1] == selected and selected.family in FAMILIES)
    if selected.family == "adoption":
        return ("adoptionIdSha256", "validatorExecutableSha256", *WINDOW_FIELDS)
    return ("peerPath", "proofScopePath", "assignmentPath", "retrievalManifest", "objectDirectory")


def _key(trust, role):
    rows = [row["key"] for row in trust["roleKeys"] if row["role"] == role]
    p.require(len(rows) == 1)
    return {name: rows[0][name] for name in KEY_FIELDS}


def _cold(prior, observed):
    order = cold.catalogue(handoff=True)
    p.require(type(prior) is dict and set(prior) == {job.name for job in order})
    retained = 0
    for job in order:
        row = p.fields(prior[job.name], ("input", "result"))
        for field, maximum in (("input", job.maximum), ("result", cold.MAX_OUTPUT)):
            raw = row[field]
            p.require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii())
            retained += len(raw)
            p.require(retained <= profile.MAX_RETAINED_BYTES)
    p.require(cold._record(prior, "coordinator-finish") == observed["bundleOriginal"].encode("ascii")
        and cold._record(prior, "acquire-cold-core") == observed["observationOriginal"].encode("ascii"))
    core_observed = core.observation(observed["observationOriginal"].encode("ascii"),
        observed["bundleOriginal"].encode("ascii"))
    runtime = cold._record(prior, "coordinator-assemble")
    native = cold._record(prior, "native-publication-grant")
    retrieval = cold._record(prior, "native-retrieval-grant")
    p.require(core_observed["nativeGrantSha256"] == p.sha(native)
        and core_observed["retrievalGrantSha256"] == p.sha(retrieval))
    binding_input = g.document(cold._record(prior, "cold-binding", "input"), cold.binding.MAX_INPUT)
    trust = g.document(binding_input["trustOriginal"].encode("ascii"), 1024 * 1024)
    p.require(binding_input["trustSha256"] == p.sha(binding_input["trustOriginal"].encode("ascii")))
    supervisor = _key(trust, "custody-supervisor-capability")
    for operation, raw in (("publication", native), ("retrieval", retrieval)):
        auth = g.document(raw, cold.service.MAX_OUTPUT[operation])["payload"]["authorization"]
        p.require(all(auth[field] == supervisor[source] for field, source in
            (("signingKeyId", "keyId"), ("signingKeySpkiSha256", "keySpkiSha256"))))
    return runtime, native, retrieval, supervisor


def _targets(prior, window, boot):
    installed = profile._input(prior, "install-ordinary-runtime")
    rows, targets = [], []
    for role in ordinary.ROLES:
        runtime_text, history_text = installed["runtimeOriginals"][role], installed["historyOriginals"][role]
        header = ordinary.original(runtime_text, g.MAX_BYTES)[1]["runtime"]
        row = {"serviceRole": role, "runtimeOriginal": runtime_text, "historyOriginal": history_text,
            "rootKeyId": header["authorityHistoryRootKeyId"], "rootKeySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}
        held = ordinary.history(history_text.encode("ascii"), role=role, header=header, boot=boot,
            issued=window["issuedAtBoottimeNanos"], expires=window["expiresAtBoottimeNanos"])
        root = held["history"]["rootAuthority"]
        def public(key):
            return p.encoded(ordinary.authority._key(key).public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw))
        targets.append({"serviceRole": role, "historyManifestSha256": held["history"]["manifestSha256"],
            "rootKeySpkiSha256": root["keySpkiSha256"], "rootPublicKeyBase64url": public(root),
            "authorityEpoch": ordinary.epoch_reference(held["epoch"]),
            "publicKeyBase64url": public(held["epoch"]["serviceSigningKey"])})
        rows.append(row)
    return rows, targets


def _adoption(selection, prior, cold_prior, observations, supervisor_observation, boot):
    observed = observations["endpoint-inputs"]["adoptedCore"]
    runtime, native, retrieval, supervisor = _cold(cold_prior, observed)
    recipe, measured = supervisor_observation["recipeOriginals"], supervisor_observation["measuredConfiguration"]
    trust = p.document(recipe["trustOriginal"].encode("ascii"), 1024 * 1024)
    assignment = p.document(recipe["assignmentOriginal"].encode("ascii"), 4 * 1024 * 1024)
    window = {field: selection[field] for field in WINDOW_FIELDS}
    for field, value in window.items():
        p.integer(value, maximum=p.MAX_U64 if "Boottime" in field else p.MAX_I64)
    rows, targets = _targets(prior, window, boot)
    checkpoint = trust["checkpoint"]
    payload = {"apiVersion": "catchplate.nativePublicationAdoptionAuthorization/v2",
        "purpose": "cold-publication-to-operational", "adoptionIdSha256": p.digest(selection["adoptionIdSha256"]),
        "coldConfigurationOriginal": runtime.decode("ascii"), "coldBundleOriginal": observed["bundleOriginal"],
        "coldNativeGrantOriginal": native.decode("ascii"), "coldRetrievalGrantOriginal": retrieval.decode("ascii"),
        "priorSupervisor": supervisor, "assignmentPayloadSha256": assignment["payloadSha256"],
        "assignmentRevision": assignment["payload"]["assignmentRevision"],
        "productionConfigurationBindingSha256": measured["configurationBindingSha256"],
        "proofScopeOriginal": measured["proofScopeOriginal"],
        "retrievalNamespaceSha256": assignment["payload"]["custodyAuthority"]["retrievalNamespaceSha256"],
        "native": _key(trust, "custody-publication-reconciliation"),
        "retrieval": _key(trust, "custody-retrieval-response"),
        "authority": _key(trust, "custody-supervisor-capability"), "targetHistories": targets,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], **window}
    validation = {"apiVersion": "catchplate.nativePublicationAdoptionValidationInput/v2",
        "payloadOriginal": g.canonical(payload).decode("ascii"), "targetHistories": rows,
        **{"current" + name[0].upper() + name[1:]: recipe[name]
            for name in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal")},
        "currentConfigurationBindingSha256": measured["configurationBindingSha256"],
        "currentProofScopeOriginal": measured["proofScopeOriginal"]}
    raw = g.canonical(validation)
    control = {"apiVersion": profile.adoption.CONTROL_API,
        "validatorExecutableSha256": p.digest(selection["validatorExecutableSha256"]), "inputSha256": p.sha(raw)}
    return {"apiVersion": profile.ADOPTION_INPUT_API, "controlOriginal": p.canonical(control).decode("ascii"),
        "validationInputOriginal": raw.decode("ascii")}


def _endpoints(selection, prior, observations, supervisor_observation):
    from catchplate import native_pilot_adopted_endpoint_plan as plan
    for field, purpose in (("peerPath", "endpoint-peer"), ("proofScopePath", "endpoint-proof-scope"),
            ("assignmentPath", "endpoint-assignment")):
        p.require(selection[field] == plan.publication.DESTINATIONS[purpose])
    installed = profile._input(prior, "install-ordinary-runtime")
    peer = None
    for role in g.ROLES:
        header = profile.legacy.service_authority._runtime(installed["runtimeOriginals"][role].encode("ascii"),
            role, adopted=True)
        raw = g.canonical(header["expectedPeer"])
        p.require(peer is None or peer == raw)
        peer = raw
    measured, recipe = supervisor_observation["measuredConfiguration"], supervisor_observation["recipeOriginals"]
    def pin(path, raw):
        result = {"path": path, "sha256": p.sha(raw)}
        profile.legacy.delivery_authority.delivery._pin(result)
        return result
    cold_inputs = profile._input(prior, "install-precreation")["nativeColdOriginals"]
    directory = selection["objectDirectory"]
    p.require(type(directory) is str and directory.startswith("/") and len(directory) <= 4096 and "\0" not in directory)
    manifest = plan.retrieval.fresh_ledger_manifest_original(measured["proofScopeOriginal"].encode("ascii"))
    expected_manifest = pin(plan.publication.DESTINATIONS["endpoint-retrieval-manifest"], manifest)
    profile._same(selection["retrievalManifest"], expected_manifest)
    value = {"coldOriginals": {role: pin(profile.legacy.launch_install.ADOPTED_DESTINATIONS["native-cold-" + role],
            cold_inputs[role].encode("ascii")) for role in profile.COMPOSITE},
        "peer": pin(selection["peerPath"], peer),
        "proofScope": pin(selection["proofScopePath"], measured["proofScopeOriginal"].encode("ascii")),
        "assignment": pin(selection["assignmentPath"], recipe["assignmentOriginal"].encode("ascii")),
        "production": copy.deepcopy(measured["production"]), "retrievalManifest": expected_manifest,
        "objectDirectory": directory, "adoptionAuthorization": copy.deepcopy(profile._result(prior, "publication-adoption")["pin"])}
    plan.prepare(value, prior=prior, observations=observations)
    return value


def compose(selected, selection, *, prior, observations, supervisor_observation, cold_prior, boot):
    p.fields(selection, selection_fields(selected))
    value = (_adoption(selection, prior, cold_prior, observations, supervisor_observation, boot)
        if selected.family == "adoption" else _endpoints(selection, prior, observations, supervisor_observation))
    return g.canonical(value)
