"""Pure fixed-five ordinary transitions from authenticated public originals.

The selected head digests authorize initial journal anchors, not receipts or
successful events. No private key, live owner, observation, history, timestamp
or renewed window is created. Native and ordinary invocations remain distinct.
Receiving owners retain responsibility for real process and resource admission.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as g
from catchplate import custody_spool_inputs as spool
from catchplate import native_pilot_native_service_authority as native_authority
from catchplate import native_pilot_native_service_profile as native
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_key_authority as history_keys
from catchplate import native_pilot_service_authority as authority
from catchplate import native_shadow_key_admission_profile as admission

p = g.p
API = "catchplate.nativePilotOrdinaryTransitionPolicy/v1"
DRS, CLEANUP, _, CURRENT, _ = g.ROLES
JOBS = (("dispatch", DRS), ("dispatch", CURRENT), ("head", DRS), ("cleanup", CLEANUP), ("current", CURRENT))
FIELDS = ("apiVersion", "dispatch", "spool", "regularAppendCapacity")
MAX_POLICY = 16384
MAX_INPUT = authority.MAX_INPUT_BYTES
MAX_CONTEXT = 128 * 1024 * 1024
EPOCH_FIELDS = ("apiVersion", "authorityRole", "authorityEpochSequence", "authorityEpochSha256",
    "checkpointSequence", "checkpointSha256", "checkpointAuthorityKeyId", "checkpointAuthorityKeySpkiSha256",
    "serviceSigningKeyId", "serviceSigningKeySpkiSha256", "endpointProcessIdentitySha256", "endpointGeneration",
    "serviceGeneration", "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")


def validate_policy(fragment):
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == API and len(p.canonical(fragment)) <= MAX_POLICY)
    for section, roles, field in (("dispatch", (DRS, CURRENT), "initialHeadSha256"),
            ("spool", (DRS, CLEANUP, CURRENT), "initialTransitionHeadSha256")):
        for row in p.fields(fragment[section], roles).values():
            p.fields(row, (field,))
            p.require(p.digest(row[field]) != p.sha(b""))
    p.integer(fragment["regularAppendCapacity"], maximum=32)
    return copy.deepcopy(fragment)


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def epoch_reference(history_raw, *, runtime, guest, adopted=False):
    """Authenticate the initial wrapper, then project Rust's exact epoch ref.

    This is public signature/byte binding, never live endpoint admission.
    """
    selected = adopted and guest["serviceRole"] in initial.ADOPTED_ROLES
    p.require(type(adopted) is bool and g.document(history_raw, g.MAX_BYTES)["apiVersion"]
        == (initial.ADOPTED_WRAPPER_API if selected else initial.WRAPPER_API))
    p.require((runtime["apiVersion"] == "catchplate.policyCustodyServiceRuntimeConfig/v12") == selected)
    history = initial.runtime_manifest(history_raw, runtime=runtime, guest=guest)
    epoch = history["firstRetainedEpoch"]["retainedEpoch"]
    value = {name: copy.deepcopy(epoch[name]) for name in ("apiVersion", "authorityRole", "authorityEpochSequence",
        "checkpointSequence", "checkpointSha256", "endpointProcessIdentitySha256", "endpointGeneration",
        "serviceGeneration", "operationGeneration", "durableEpoch", "durableEpochHeadSha256", "deploymentGenerationSha256")}
    value.update(authorityEpochSha256=epoch["epochSha256"],
        checkpointAuthorityKeyId=epoch["checkpointAuthority"]["keyId"],
        checkpointAuthorityKeySpkiSha256=epoch["checkpointAuthority"]["keySpkiSha256"],
        serviceSigningKeyId=epoch["serviceSigningKey"]["keyId"],
        serviceSigningKeySpkiSha256=epoch["serviceSigningKey"]["keySpkiSha256"])
    p.fields(value, EPOCH_FIELDS)
    public = authority._public(history_keys._key(epoch["serviceSigningKey"]))
    return value, p.encoded(public)


def _native_context(context, clocks, *, adopted=False):
    from catchplate import native_pilot_adopted_service_authority as adopted_authority
    operations = native.OPERATIONS + (("publication",) if adopted else ())
    p.fields(context, operations)
    total = 0
    for row in context.values():
        p.fields(row, ("inputOriginal", "grantOriginal"))
        for name, maximum in (("inputOriginal", native.MAX_INPUT), ("grantOriginal", 4 * 1024 * 1024 if adopted else native.MAX_OUTPUT)):
            p.require(type(row[name]) is bytes and 0 < len(row[name]) <= maximum)
            total += len(row[name])
    p.require(total <= MAX_CONTEXT)
    inputs, payloads, keys = {}, {}, {}
    for operation in operations:
        row = context[operation]
        checker = native.checked_adopted_result if adopted else native.checked_result
        raw = checker(operation, row["inputOriginal"],
            {"original": row["grantOriginal"].decode("ascii"), "sha256": p.sha(row["grantOriginal"])}, **clocks)
        inputs[operation] = p.document(row["inputOriginal"], native.MAX_INPUT)
        maximum = adopted_authority.PROFILES[operation][3] if adopted and operation in adopted_authority.PROFILES else native.MAX_OUTPUT
        payloads[operation] = g.document(raw, maximum)["payload"]
        if operation in spool.EFFECT_NATIVE or operation == "commitRequest":
            config = p.document(authority._original(inputs[operation]["configurationOriginal"], p.MAX_CONFIG), p.MAX_CONFIG)
            _, authorized = admission.authorization(config, clocks["now_unix_ns"])
            role = "custody-ledger-append" if operation == "commitRequest" else spool.EFFECT_NATIVE[operation][0]
            key = authorized[p.ROLES.index(role)]
            keys[operation] = {name: key[name] for name in ("role", "keyId", "keySpkiSha256", "publicKeyBase64url")}
            keys[operation]["grantSha256"] = p.sha(raw)
    return inputs, payloads, keys


def _services(context, inputs, payloads, clocks, *, adopted=False):
    p.fields(context, ("launchOriginal", "services"))
    rows = p.fields(context["services"], g.ROLES)
    # Byte-identical actual inputs, not a reconstructed history/guest summary.
    for operation in native_authority.HISTORY_OPERATIONS + ("generationInstall",):
        original = inputs[operation]
        p.require(context["launchOriginal"] == original["ordinaryLaunchOriginal"])
        for role in g.ROLES:
            p.fields(rows[role], authority._SERVICE + ("generationGrantOriginal",))
            p.require(rows[role] == original["services"][role])
    launch_raw = authority._original(context["launchOriginal"], 65536)
    launch, startup, lifetime = authority._launch(launch_raw, clocks["boot"], clocks["now_boottime_ns"], adopted=adopted)
    services = {}
    common = None
    for role in g.ROLES:
        item = authority._service(rows[role], role, launch, clocks["boot"], startup, lifetime,
            clocks["now_boottime_ns"], granted=True, adopted=adopted)
        if common is None:
            common = item["generation"]["scope"]
        else:
            _same(common, item["generation"]["scope"])
        for operation in native_authority.HISTORY_OPERATIONS:
            native_authority.require_ordinary_member(payloads[operation], role, runtime_raw=item["runtime_raw"],
                history_raw=item["history_raw"], generation_raw=item["grant_raw"])
        services[role] = item
    return services


def _base(item):
    _, semantic = spool._root(item)
    return {"guest": copy.deepcopy(item["guest"]), "runtimeConfigurationSha256": p.sha(item["runtime_raw"]),
        "authorityHistoryManifestSha256": semantic}


def _head_payload(fragment, services, payloads, keys, *, adopted=False):
    cleanup = services[CLEANUP]
    epoch, public = epoch_reference(cleanup["history_raw"], runtime=cleanup["header"], guest=cleanup["guest"], adopted=adopted)
    ingress = payloads["ingress"]
    return {**_base(services[DRS]), "apiVersion": "catchplate.nativeSpoolHeadGrant/v3",
        "purpose": "native-shared-spool-head", "scope": copy.deepcopy(ingress["scope"]),
        "originVerifier": copy.deepcopy(ingress["originVerifier"]),
        **{name: copy.deepcopy(keys[name]) for name in ("ingress", "ledger", "retrieval")},
        "proofScopeOriginal": ingress["proofScopeOriginal"],
        "initialTransitionHeadSha256": fragment["spool"][DRS]["initialTransitionHeadSha256"],
        "completion": {"terminal": copy.deepcopy(keys["terminal"]), "regularAppendCapacity": fragment["regularAppendCapacity"]},
        "effects": {**{name: copy.deepcopy(keys[name]) for name in spool.EFFECT_KEYS},
            "cleanupAuthorityEpoch": epoch, "cleanupPublicKeyBase64url": public,
            "cleanupInitialTransitionHeadSha256": fragment["spool"][CLEANUP]["initialTransitionHeadSha256"]}}


def build(operation, role, *, fragment, ordinary_context, native_context, prior_transition_originals,
          boot, now_boottime_ns, now_unix_ns, adopted=False) -> bytes:
    p.require((operation, role) in JOBS)
    fragment = validate_policy(fragment)
    required = ("head", "cleanup") if operation == "current" else ("head",) if operation == "cleanup" else ()
    p.fields(prior_transition_originals, required)
    for name, raw in prior_transition_originals.items():
        p.require(type(raw) is bytes and 0 < len(raw) <= (65536 if name == "head" else 131072))
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    inputs, payloads, keys = _native_context(native_context, clocks, adopted=adopted)
    services = _services(ordinary_context, inputs, payloads, clocks, adopted=adopted)
    item = services[role]
    selected = (role,) if operation == "dispatch" else (DRS, CLEANUP, CURRENT) if operation == "current" else (DRS, CLEANUP)
    value = {"apiVersion": authority.ADOPTED_INPUT_API if adopted else "catchplate.nativePilotServiceAuthorityInput/v1", "operation": operation,
        "serviceRole": role, "launchOriginal": ordinary_context["launchOriginal"],
        "services": {name: copy.deepcopy(ordinary_context["services"][name]) for name in selected}}
    if operation == "dispatch":
        ledger = keys["commitRequest"]
        payload = {**_base(item), "apiVersion": "catchplate.custodyCommitRequestServiceGrant/v1",
            "purpose": "commit-request-service-transition", "serviceRole": role,
            "scope": copy.deepcopy(payloads["commitRequest"]["scope"]),
            "nativeGrantSha256": p.sha(native_context["commitRequest"]["grantOriginal"]),
            "nativeLedgerKeyId": ledger["keyId"], "nativeLedgerKeySpkiSha256": ledger["keySpkiSha256"],
            "nativeLedgerPublicKeyBase64url": ledger["publicKeyBase64url"],
            "initialHeadSha256": fragment["dispatch"][role]["initialHeadSha256"]}
        value.update(nativeGrantOriginal=native_context["commitRequest"]["grantOriginal"].decode("ascii"),
            nativeConfigurationOriginal=inputs["commitRequest"]["configurationOriginal"],
            nativeConfigurationSha256=inputs["commitRequest"]["configurationSha256"])
    else:
        head = _head_payload(fragment, services, payloads, keys, adopted=adopted)
        value["nativeOriginals"] = {name: native_context[name]["grantOriginal"].decode("ascii") for name in spool.EFFECT_NATIVE}
        if operation == "head":
            payload = head
        else:
            head_raw = prior_transition_originals["head"]
            _same(authority._signed_spool("head", head_raw, services[DRS]), head)
            durable = services[DRS]
            epoch, public = epoch_reference(durable["history_raw"], runtime=durable["header"], guest=durable["guest"], adopted=adopted)
            payload = {**_base(item), "apiVersion": "catchplate." + authority._SPOOL[operation][1]
                + "/v" + authority._SPOOL[operation][2], "purpose": authority._SPOOL[operation][3],
                "headGrantOriginal": head_raw.decode("ascii"), "durableAuthorityEpoch": epoch,
                "durablePublicKeyBase64url": public,
                "initialTransitionHeadSha256": fragment["spool"][role]["initialTransitionHeadSha256"]}
            value["headGrantOriginal"] = head_raw.decode("ascii")
            if operation == "current":
                cleanup_raw = prior_transition_originals["cleanup"]
                cleanup = authority._signed_spool("cleanup", cleanup_raw, services[CLEANUP])
                _same(cleanup["durableAuthorityEpoch"], epoch)
                p.require(cleanup["durablePublicKeyBase64url"] == public)
                value["cleanupGrantOriginal"] = cleanup_raw.decode("ascii")
    value["payloadOriginal"] = g.canonical(payload).decode("ascii")
    raw = p.canonical(value)
    p.require(len(raw) <= MAX_INPUT)
    authority.prepare_input(operation, role, raw, adopted=adopted, **clocks)
    return raw


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns, adopted=False) -> bytes:
    p.require((operation, role) in JOBS)
    prepared = authority.prepare_input(operation, role, input_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=adopted)
    p.fields(result, ("original", "sha256"))
    raw = authority._original(result["original"], prepared["maximum"])
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    signed = p.fields(g.document(raw, prepared["maximum"]), ("payload", "signatureBase64url"))
    p.require(g.canonical(signed["payload"]) == prepared["payloadOriginal"])
    prepared["root"].verify(p.decoded(signed["signatureBase64url"], size=64), prepared["message"])
    return raw
