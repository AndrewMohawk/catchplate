"""Purpose-fixed public composition for eleven native operational grants.

The caller must supply independently admitted policy and literal originals from
its retained process owner. These pure functions authenticate public bindings;
they neither construct that owner nor sign, publish, acquire attestation, renew
windows or establish resource emptiness. Explicit fresh-persistence and
fresh-generation policies authorize unsigned initialization configurations only.
The actual receiving owners still check their retained directories, emptiness,
exclusive creation and unchanged descriptors before any initialization writes.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_generation_install_authority as installation
from serverware import native_pilot_key_profile as key_profile
from serverware import native_pilot_native_service_authority as authority
from serverware import native_pilot_publication_profiles as publication
from serverware import native_pilot_runtime_evidence as evidence
from serverware import native_pilot_service_authority as ordinary
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_nitro_verifier as verifier
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware.native_shadow_time_profile import public_key, key_live

API = "serverware.nativePilotNativeServicePolicy/v1"
OPERATIONS = ("commitRequest", "ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "retrieval", "persistence", "trustedTime", "generationInstall")
ENDPOINT_ROLES = {name: authority._ENDPOINT[name] for name in authority.OPERATIONS} | {"generationInstall": "generationInstall"}
FIELDS = ("apiVersion", "verifierSettings", "operationWindows", "spool", "commitment", "persistence",
    "trustedTime", "generationInstall")
VERIFIER_FIELDS = ("uid", "gid", "nitro", "collateralRevocation", "expectedAttestation", "maximumResultAgeNanos")
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
MAX_POLICY = MAX_INPUT = authority.MAX_INPUT
MAX_OUTPUT = authority.MAX_OUTPUT


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _verifier(value, *, now=None):
    p.fields(value, VERIFIER_FIELDS)
    for name in ("uid", "gid"):
        p.integer(value[name], maximum=(1 << 32) - 2)
    p.integer(value["maximumResultAgeNanos"], maximum=30_000_000_000)
    roots, _ = verifier._nitro_policy(value["nitro"])
    revocation = value["collateralRevocation"]
    # The static call checks structure at its own stated issue time; it is not
    # a currentness verdict. Every build rechecks the actual supplied clock.
    p.require(type(revocation) is dict)
    _, source, _ = verifier._revocation(revocation,
        revocation.get("issuedAtUnixNanos") if now is None else now)
    expected = p.fields(value["expectedAttestation"], ("platform", "expectedMeasurementSha256",
        "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"))
    p.require(expected["platform"] == "aws-nitro-enclave")
    for name in ("expectedMeasurementSha256", "endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"):
        p.digest(expected[name])
    p.require(expected["endorsementRootSha256"] in {verifier.nitro.certificate_sha256(root) for root in roots}
        and expected["collateralPolicySha256"] == p.framed(b"serverware.nativeShadowNitroCollateralPolicy/v1",
            (p.canonical(value["nitro"]),)) and expected["revocationSourceSha256"] == source)


def validate_policy(fragment):
    """Closed independent selections; no observed identity or permissions added."""
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == API and len(p.canonical(fragment)) <= MAX_POLICY)
    for value in p.fields(fragment["verifierSettings"], key_profile.ROLES).values():
        _verifier(value)
    for window in p.fields(fragment["operationWindows"], OPERATIONS).values():
        p.fields(window, ("issuedAtUnixNanos", "expiresAtUnixNanos"))
        p.require(p.integer(window["issuedAtUnixNanos"]) < p.integer(window["expiresAtUnixNanos"]))
    spool = p.fields(fragment["spool"], ("generationId", "originVerifier"))
    p.digest(spool["generationId"]); public_key(spool["originVerifier"])
    evidence.validate_policy(fragment["commitment"])
    persistence = p.fields(fragment["persistence"], ("initialization", "permissions"))
    p.require(persistence["initialization"] == "fresh-persistence" and type(persistence["permissions"]) is list
        and persistence["permissions"] in (["verify-persistence"], ["store-dispatch-original", "verify-persistence"]))
    clock = p.fields(fragment["trustedTime"], ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm"))
    p.integer(clock["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    p.require(p.ns(clock["maximumBracketNanos"]) <= 1_000_000_000)
    p.integer(clock["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
    p.integer(clock["maximumClockRateErrorPpm"], minimum=0, maximum=10000)
    initial = p.fields(fragment["generationInstall"], ("initialization", "keyHistory", "recordOriginals"))
    history = p.fields(initial["keyHistory"], ("currentKeyEpoch", "predecessors"))
    p.require(initial["initialization"] == "fresh-generation" and type(history["currentKeyEpoch"]) is int
        and history["currentKeyEpoch"] == 1 and type(history["predecessors"]) is list and history["predecessors"] == []
        and type(initial["recordOriginals"]) is list and initial["recordOriginals"] == [])
    return copy.deepcopy(fragment)


def _context(operation, fragment, pair_context, *, boot, now_boottime_ns, now_unix_ns):
    role = ENDPOINT_ROLES[operation]
    p.fields(pair_context, PAIR_FIELDS)
    pair_raw = {name: ordinary._original(pair_context[name], key_profile.MAX_INPUT
        if "Input" in name else key_profile.MAX_OUTPUT) for name in PAIR_FIELDS}
    pair = key_profile.admitted_pair(role, pair_raw["roleKeyInputOriginal"], pair_raw["roleKeyOriginal"],
        pair_raw["admissionInputOriginal"], pair_raw["admissionOriginal"], boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    first = p.document(pair_raw["roleKeyInputOriginal"], key_profile.MAX_INPUT)
    delivery_raw = ordinary._original(first["deliveryInputOriginal"], c9.MAX_INPUT)
    delivery = p.fields(p.document(delivery_raw, c9.MAX_INPUT), c9.INPUT_FIELDS)
    recipe, measured = first["recipeOriginals"], first["measured"]
    assignment_raw = ordinary._original(recipe["assignmentOriginal"], p.MAX_CONFIG)
    assignment = p.document(assignment_raw, p.MAX_CONFIG)["payload"]
    guest = pair["expectedScope"]["guest"]
    settings = fragment["verifierSettings"][role]
    _verifier(settings, now=now_unix_ns)
    p.require(settings["uid"] != guest["uid"] and settings["gid"] != guest["gid"])
    operation_window = {name: guest[name] for name in ("bootIdBase64url", "timeNamespaceDevice",
        "timeNamespaceInode", "issuedAtBoottimeNs")}
    operation_window["deadlineBoottimeNs"] = guest["startupDeadlineBoottimeNs"]
    p.require(0 < p.ns(operation_window["deadlineBoottimeNs"]) - p.ns(operation_window["issuedAtBoottimeNs"])
        <= 30_000_000_000)
    config = {"apiVersion": "serverware.nativeShadowNitroVerifierConfiguration/v2",
        **copy.deepcopy(settings), "operation": operation_window, **pair}
    config_raw = p.canonical(config)
    p.require(len(config_raw) <= p.MAX_CONFIG)
    admitted, keys = admission.authorization(config, now_unix_ns)
    proof_raw = ordinary._original(measured["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(proof_raw)
    retrieval.require_assignment_scope(proof, p.canonical(assignment))
    window = fragment["operationWindows"][operation]
    p.freshness(window["issuedAtUnixNanos"], window["expiresAtUnixNanos"], now_unix_ns)
    common = commitment._common(config, admitted, keys, window["issuedAtUnixNanos"], window["expiresAtUnixNanos"], now_unix_ns)
    return {"role": role, "config": config, "config_raw": config_raw, "guest": guest, "keys": keys,
        "admitted": admitted, "delivery": delivery, "delivery_original": first["deliveryOriginal"],
        "assignment": assignment, "assignment_raw": assignment_raw, "recipe": recipe, "measured": measured,
        "proof": proof, "proof_raw": proof_raw, "common": common}


def _ordinary(context, value, peer, *, boot, now_boottime_ns, now_unix_ns):
    p.fields(value, ("launchOriginal", "services"))
    launch_raw = ordinary._original(value["launchOriginal"], 65536)
    launch, startup, lifetime = ordinary._launch(launch_raw, boot, now_boottime_ns)
    rows, common, issued, expires = {}, None, p.ns(context["guest"]["issuedAtBoottimeNs"]), p.ns(context["guest"]["lifetimeDeadlineBoottimeNs"])
    for role, row in p.fields(value["services"], g.ROLES).items():
        item = ordinary._service(row, role, launch, boot, startup, lifetime, now_boottime_ns, granted=True)
        grant, header = item["generation"], item["header"]
        p.require(len(item["history_raw"]) <= 1024 * 1024)
        _same(header["expectedPeer"], peer)
        if common is None:
            common = grant["scope"]
        else:
            _same(common, grant["scope"])
        issued = max(issued, grant["issuedAtBoottimeNanos"])
        expires = min(expires, grant["expiresAtBoottimeNanos"])
        rows[role] = {"grantOriginal": item["grant_raw"].decode("ascii"), "historyOriginal": item["history_raw"].decode("ascii"),
            "runtimeOriginal": item["runtime_raw"].decode("ascii"), "rootKeyId": header["authorityHistoryRootKeyId"],
            "rootKeySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}
    assignment, admitted, checkpoint = context["assignment"], context["admitted"], context["config"]["trustCheckpoint"]
    p.require(common["previousConfigurationBindingSha256"] is None and common["assignmentId"] == admitted["assignmentId"]
        and common["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
        and common["assignmentRevision"] == assignment["assignmentRevision"]
        and common["successorConfigurationBindingSha256"] == context["measured"]["configurationBindingSha256"]
        and common["fiveServiceProtocolSetSha256"] == context["measured"]["production"]["dispatcherProtocolSetSha256"]
        and issued <= now_boottime_ns < expires)
    for target, source in (("trustedTimeCheckpointSha256", "checkpointId"),
            ("trustedTimeRevocationGeneration", "revocationGeneration"), ("trustedTimeRevocationRootSha256", "revocationRootSha256")):
        _same(common[target], checkpoint[source])
    envelope_key = context["keys"][p.ROLES.index("custody-result-envelope")]
    p.require(common["envelopeAuthorityKeyId"] == envelope_key["keyId"]
        and common["envelopeAuthorityKeySpkiSha256"] == envelope_key["keySpkiSha256"])
    p.freshness(common["installationIssuedAtUnixNanos"], common["installationExpiresAtUnixNanos"], now_unix_ns)
    p.require(common["installationIssuedAtUnixNanos"] <= context["common"]["issuedAtUnixNanos"]
        < context["common"]["expiresAtUnixNanos"] <= common["installationExpiresAtUnixNanos"])
    scope = {"productionConfigurationBindingSha256": common["successorConfigurationBindingSha256"],
        **{name: common[name] for name in ("kernelDriverIdentitySha256", "retainedDescriptorSetSha256",
            "driverGenerationReceiptSha256", "assignmentPayloadSha256", "assignmentRevision")},
        "issuedAtBoottimeNanos": issued, "expiresAtBoottimeNanos": expires}
    return rows, scope


def _base(operation, context, peer_raw):
    delivery = context["delivery"]
    return {"apiVersion": authority.HISTORY_INPUT_API if operation in authority.HISTORY_OPERATIONS
        else authority.HISTORY_RETRIEVAL_INPUT_API if operation == "retrieval" else "serverware.nativePilotNativeServiceAuthorityInput/v1",
        "operation": operation, "configurationOriginal": context["config_raw"].decode("ascii"),
        "configurationSha256": p.sha(context["config_raw"]), "assignmentPayloadOriginal": p.canonical(context["assignment"]).decode("ascii"),
        "cohortConfigurationOriginal": delivery["ownerConfigurationOriginal"], "precreationOriginal": delivery["windowOriginal"],
        "observationOriginal": delivery["observationOriginal"], "coldConfigurationOriginal": delivery["configurationOriginal"],
        "deliveryOriginal": context["delivery_original"], "runtimeOriginal": delivery["runtimeOriginal"],
        "peerOriginal": peer_raw.decode("ascii"), "peerSha256": p.sha(peer_raw),
        **{name: context["common"][name] for name in ("issuedAtUnixNanos", "expiresAtUnixNanos")}}


def _generation(context, ordinary_context, rows, peer, fragment):
    payload = {**context["common"], "apiVersion": "serverware.nativeGenerationCoordinatorAssignment/v2",
        "purpose": "native-generation-installation", "services": rows,
        "keyHistory": copy.deepcopy(fragment["generationInstall"]["keyHistory"]), "expectedPeer": peer}
    genesis = p.canonical({"apiVersion": "serverware.nativeGenerationCoordinatorGenesis/v1", "guest": context["guest"],
        "assignmentPayloadSha256": context["admitted"]["assignmentPayloadSha256"], "servicesSha256": p.sha(p.canonical(rows))})
    payload["journal"] = {"genesisSha256": p.sha(genesis), "sequence": 0, "headSha256": p.sha(genesis)}
    delivery = context["delivery"]
    return {"apiVersion": "serverware.nativePilotGenerationInstallAuthorityInput/v2", "payloadOriginal": p.canonical(payload).decode("ascii"),
        "nativeConfigurationOriginal": context["config_raw"].decode("ascii"), "nativeConfigurationSha256": p.sha(context["config_raw"]),
        "assignmentPayloadOriginal": p.canonical(context["assignment"]).decode("ascii"),
        "cohortConfigurationOriginal": delivery["ownerConfigurationOriginal"], "precreationOriginal": delivery["windowOriginal"],
        "observationOriginal": delivery["observationOriginal"], "coordinatorConfigurationOriginal": delivery["configurationOriginal"],
        "coordinatorDeliveryOriginal": context["delivery_original"], "coordinatorRuntimeOriginal": delivery["runtimeOriginal"],
        "ordinaryLaunchOriginal": ordinary_context["launchOriginal"], "services": copy.deepcopy(ordinary_context["services"]),
        "genesisOriginal": genesis.decode("ascii"), "recordOriginals": copy.deepcopy(fragment["generationInstall"]["recordOriginals"])}


def build(operation, *, fragment, pair_context, ordinary_context, peer_raw, retrieval_manifest_raw,
          endpoint_delivery_result_raw, prior_native_originals, boot, now_boottime_ns, now_unix_ns) -> bytes:
    p.require(operation in OPERATIONS)
    fragment = validate_policy(fragment)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    context = _context(operation, fragment, pair_context, **clocks)
    peer = retrieval._peer(peer_raw)
    rows, scope = _ordinary(context, ordinary_context, peer, **clocks)
    required = ("commitRequest",) if operation == "ledger" else authority.SIGNERS if operation == "retrieval" else ()
    p.fields(prior_native_originals, required)
    for name, raw in prior_native_originals.items():
        authority.grant_original(name, raw)
    if operation == "generationInstall":
        value = _generation(context, ordinary_context, rows, peer, fragment)
    else:
        value = _base(operation, context, peer_raw)
        if operation in authority.HISTORY_OPERATIONS:
            value.update(ordinaryLaunchOriginal=ordinary_context["launchOriginal"], services=copy.deepcopy(ordinary_context["services"]))
        if operation == "commitRequest":
            runtime = evidence.runtime(fragment["commitment"], assignment_original=context["assignment_raw"],
                issued_at_unix_ns=value["issuedAtUnixNanos"], expires_at_unix_ns=value["expiresAtUnixNanos"], now_unix_ns=now_unix_ns)
            observation = context["assignment"]["observationWindow"]
            scope.update(runtime=runtime, requestCommitmentKeyId=observation["requestCommitmentKeyId"],
                requestCommitmentKeyEpoch=observation["requestCommitmentKeyEpoch"])
            value.update(commitmentScopeOriginal=p.canonical(scope).decode("ascii"), runtimeEvidence=copy.deepcopy(fragment["commitment"]),
                assignmentOriginal=context["assignment_raw"].decode("ascii"))
        elif operation in authority.SIGNERS or operation == "retrieval":
            scope.update(generationId=fragment["spool"]["generationId"], proofScopeSha256=p.sha(context["proof_raw"]),
                retrievalNamespaceSha256=context["proof"]["retrieval_namespace_sha256"])
            value.update(spoolScopeOriginal=p.canonical(scope).decode("ascii"), proofScopeOriginal=context["proof_raw"].decode("ascii"))
            if operation in authority.SIGNERS:
                key_live(fragment["spool"]["originVerifier"], now_unix_ns)
                value["originVerifierOriginal"] = p.canonical(fragment["spool"]["originVerifier"]).decode("ascii")
            if operation == "ledger":
                companion = prior_native_originals["commitRequest"]
                value.update(companionOriginal=companion.decode("ascii"), companionPin={"path":
                    publication._ROOT + "native-service-commitRequest.json", "sha256": p.sha(companion)})
            if operation == "retrieval":
                p.require(retrieval.manifest_initialization(retrieval_manifest_raw, p.sha(retrieval_manifest_raw)) == "fresh-ledger")
                value.update(retrievalManifestOriginal=retrieval_manifest_raw.decode("ascii"),
                    endpointDeliveryResultOriginal=endpoint_delivery_result_raw.decode("ascii"),
                    nativeGrantOriginals={name: raw.decode("ascii") for name, raw in prior_native_originals.items()})
        elif operation == "persistence":
            # Authorization to initialize is explicit; only the retained native
            # receiver can prove that its actual resource is still fresh.
            genesis = p.canonical({"apiVersion": "serverware.nativeShadowPersistenceGenesis/v1",
                "proofScopeSha256": context["proof"]["binding_sha256"], "guest": context["guest"]})
            journal = p.canonical({"genesisSha256": p.sha(genesis), "headSequence": 0, "headSha256": p.sha(genesis)})
            value.update(proofScopeOriginal=context["proof_raw"].decode("ascii"), genesisOriginal=genesis.decode("ascii"),
                journalOriginal=journal.decode("ascii"), permissions=copy.deepcopy(fragment["persistence"]["permissions"]))
        else:
            p.require(operation == "trustedTime")
            trust = p.document(ordinary._original(context["recipe"]["trustOriginal"], 1024 * 1024), 1024 * 1024)
            clock = {"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1", "guest": context["guest"],
                "signingKeyId": trust["timeKey"]["keyId"], **copy.deepcopy(fragment["trustedTime"])}
            value["bootstrapOriginal"] = p.canonical(clock).decode("ascii")
    raw = p.canonical(value)
    p.require(len(raw) <= MAX_INPUT)
    prepare_input(operation, raw, **clocks)
    return raw


def prepare_input(operation, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    p.require(operation in OPERATIONS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return installation.prepare_input(input_raw, **clocks) if operation == "generationInstall" else authority.prepare_input(operation, input_raw, **clocks)


def checked_result(operation, input_raw, result, *, boot, now_boottime_ns, now_unix_ns) -> bytes:
    prepared = prepare_input(operation, input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = ordinary._original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    signed = installation.grant_original(raw) if operation == "generationInstall" else authority.grant_original(operation, raw)
    _same(signed["payload"], prepared["payload"])
    p.public_key(prepared["supervisor"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(prepared["domain"], signed["payload"]))
    return raw
