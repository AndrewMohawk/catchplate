"""Pure composition of constructed admission and the last two action requests.

Only the retained supervisor can establish where these public originals and
observations came from. This module authenticates signatures and exact-byte
associations; it does not reconstruct an owner, acquire Nitro evidence, install
a generation, deliver its origin, or prove cleanup. An origin handoff remains
an observed transport result with both action/retry flags false.
"""
from __future__ import annotations

import copy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_pilot_bridge_key_profile as keys
from catchplate import native_pilot_bridge_launch_publication as bridge_launch
from catchplate import native_pilot_driver_authority as authority
from catchplate import native_pilot_native_service_profile as services
from catchplate import native_pilot_publication_profiles as publication
from catchplate import native_pilot_scope_authority as scope_authority
from catchplate.native_shadow_time_profile import key_live

p = authority.p
API = "catchplate.nativePilotContinuationPolicy/v1"
FIELDS = ("apiVersion", "verifierSettings", "assignmentPublicKeyOriginal", "assignmentPublicKeySha256")
MAX_POLICY = p.MAX_CONFIG
MAX_INPUT = authority.MAX_INPUT
JOBS = ("driver-constructed", "observe-generation-origin", "stop")
OBSERVATION_FIELDS = ("payloadOriginal", "censusOriginal", "publicAdmissionOriginal", "bootstrapAdmissionOriginal")
PRIOR_FIELDS = ("inputOriginal", "result", "preparedAtBoottimeNs", "preparedAtUnixNanos")
STOP_PRIOR_FIELDS = PRIOR_FIELDS + ("originInputOriginal", "originResult", "originObservation")
BRIDGE_JOBS = ("native-delivery-bridge", "native-role-keys-bridge", "native-key-admission-bridge",
    "native-closure-bridge", "native-encrypted-delivery-bridge", "native-verifier-transport-bridge", "install-launch-bridge")


def _bytes(raw, maximum):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
    return raw


def _pem(fragment):
    text = fragment["assignmentPublicKeyOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= 4096)
    raw = text.encode("ascii")
    p.require(p.sha(raw) == p.digest(fragment["assignmentPublicKeySha256"]))
    public = serialization.load_pem_public_key(raw)
    p.require(isinstance(public, Ed25519PublicKey)
        and public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    return public


def validate_policy(fragment):
    """Independent static settings only, never a future verifier/scope template."""
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == API and len(p.canonical(fragment)) <= MAX_POLICY)
    services._verifier(fragment["verifierSettings"])
    _pem(fragment)
    return copy.deepcopy(fragment)


def _record(context, job):
    row = p.fields(context["records"][job], ("inputOriginal", "result"))
    _bytes(row["inputOriginal"], 32 * 1024 * 1024)
    p.require(type(row["result"]) is dict)
    return row


def _original_result(result, *, purpose, maximum):
    p.fields(result, ("original", "sha256", "pin"))
    raw, _ = authority._original(result["original"], maximum)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    authority._same(result["pin"], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    return raw


def _context(commissioning_context, scope_context):
    p.fields(commissioning_context, ("runtime", "records", "sourceInputs", "sourceResults",
        "conductorOriginals", "deadline", "epochLimit"))
    p.fields(commissioning_context["records"], BRIDGE_JOBS)
    p.fields(scope_context, ("inputOriginal", "scopeOriginal"))
    scope_input_raw = _bytes(scope_context["inputOriginal"], scope_authority.MAX_BRIDGE_INPUT)
    scope_input = p.fields(p.document(scope_input_raw, scope_authority.MAX_BRIDGE_INPUT), scope_authority.INPUT_FIELDS)
    scope_raw = _bytes(scope_context["scopeOriginal"], scope_authority.MAX_SCOPE)
    source = commissioning_context["runtime"]
    bootstrap = p.fields(source["bootstrapOriginals"], ("control", "configuration", "window", "deliveryConfiguration"))
    for name, maximum in (("control", 4096), ("configuration", 65536), ("window", 32768),
                          ("deliveryConfiguration", 65536)):
        _bytes(bootstrap[name], maximum)
    slot = ("bootstrap-admission", "driver-bootstrap")
    original_input = _bytes(commissioning_context["sourceInputs"][slot], MAX_INPUT)
    early_input = p.document(original_input, MAX_INPUT)
    early_result = p.document(_bytes(commissioning_context["sourceResults"][slot], 32768), 32768)
    early_raw = _original_result(early_result, purpose="driver-bootstrap-admission", maximum=8192)
    for name in bootstrap:
        p.require(early_input[name + "Original"] == bootstrap[name].decode("ascii"))
        if name != "control":
            p.require(scope_input[name + "Original"] == bootstrap[name].decode("ascii"))
    p.require(scope_input["observationOriginal"] == early_input["observationOriginal"]
        and scope_input["bootstrapAdmissionOriginal"] == early_raw.decode("ascii"))
    return source, bootstrap, scope_input, scope_raw, early_raw, original_input, early_result


def _verifier(fragment, source, records, bootstrap, *, clocks):
    first, second = records["native-role-keys-bridge"], records["native-key-admission-bridge"]
    p.fields(first["result"], ("original", "sha256")); p.fields(second["result"], ("original", "sha256"))
    first_raw, _ = authority._original(first["result"]["original"], keys.MAX_OUTPUT)
    second_raw, _ = authority._original(second["result"]["original"], keys.MAX_OUTPUT)
    p.require(first["result"]["sha256"] == p.sha(first_raw) and second["result"]["sha256"] == p.sha(second_raw))
    pair = keys.admitted_pair(first["inputOriginal"], first_raw, second["inputOriginal"], second_raw, **clocks)
    key_input = p.document(first["inputOriginal"], keys.MAX_INPUT)
    p.require(key_input["controlOriginal"] == bootstrap["control"].decode("ascii"))
    authority._same(key_input["recipeOriginals"], source["recipeOriginals"])
    authority._same(key_input["measured"], source["measured"])
    delivered = records["native-delivery-bridge"]
    delivered_raw = _original_result(delivered["result"], purpose="native-delivery-bridge", maximum=65536)
    p.require(key_input["deliveryInputOriginal"] == delivered["inputOriginal"].decode("ascii")
        and key_input["deliveryOriginal"] == delivered_raw.decode("ascii"))
    delivery = keys.c9.input_document(delivered["inputOriginal"])
    for field, name in (("ownerConfigurationOriginal", "configuration"), ("configurationOriginal", "deliveryConfiguration"),
                        ("windowOriginal", "window")):
        p.require(delivery[field] == bootstrap[name].decode("ascii"))
    settings = fragment["verifierSettings"]
    services._verifier(settings, now=clocks["now_unix_ns"])
    guest = pair["expectedScope"]["guest"]
    p.require(settings["uid"] != guest["uid"] and settings["gid"] != guest["gid"])
    operation = {name: guest[name] for name in ("bootIdBase64url", "timeNamespaceDevice",
        "timeNamespaceInode", "issuedAtBoottimeNs")}
    operation["deadlineBoottimeNs"] = guest["startupDeadlineBoottimeNs"]
    config = {"apiVersion": "catchplate.nativeShadowNitroVerifierConfiguration/v3",
        **copy.deepcopy(settings), "operation": operation, **pair}
    config_raw = p.canonical(config)
    p.require(len(config_raw) <= p.MAX_CONFIG)
    authority.bridge.authorization(config, clocks["now_unix_ns"])
    _, trust = authority._original(source["recipeOriginals"]["trustOriginal"], 1024 * 1024)
    assignment_key = key_live(trust["assignmentKey"], clocks["now_unix_ns"])
    p.require(_pem(fragment).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == assignment_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    pair_context = {"roleKeyInputOriginal": first["inputOriginal"].decode("ascii"),
        "roleKeyOriginal": first_raw.decode("ascii"), "admissionInputOriginal": second["inputOriginal"].decode("ascii"),
        "admissionOriginal": second_raw.decode("ascii")}
    return config_raw, pair_context


def _constructed(fragment, context, scope_context, observed, clocks):
    p.fields(observed, OBSERVATION_FIELDS)
    source, bootstrap, scope_input, scope_raw, early_raw, early_input, early_result = _context(context, scope_context)
    scope_authority.checked_result(scope_context["inputOriginal"],
        {"original": scope_raw.decode("ascii"), "sha256": p.sha(scope_raw)}, **clocks)
    authority.checked_result("bootstrap", early_input,
        {name: early_result[name] for name in ("original", "sha256")}, **clocks)
    p.require(observed["bootstrapAdmissionOriginal"] == early_raw.decode("ascii"))
    records = {job: _record(context, job) for job in BRIDGE_JOBS}
    verifier_raw, pair_context = _verifier(fragment, source, records, bootstrap, clocks=clocks)
    launch_row = records["install-launch-bridge"]
    time_grant = _bytes(source["trustedTime"]["grantOriginal"], 65536)
    prepared_launch = bridge_launch.prepare_bridge_bundle(launch_row["inputOriginal"],
        pair_context=pair_context, service_grant_original=time_grant, **clocks)
    expected = bridge_launch.launch._installation_result("bridge", p.sha(launch_row["inputOriginal"]),
        prepared_launch["window"], prepared_launch["pins"])
    authority._same(launch_row["result"], expected)
    launch_raw = prepared_launch["prepared"]["native-launch-bridge"]
    p.require(scope_input["launchOriginal"] == launch_raw.decode("ascii"))
    _, exported = authority._original(observed["publicAdmissionOriginal"], 8 * 1024 * 1024)
    p.fields(exported, authority.admission.PUBLIC)
    p.require(exported["phaseScopeOriginal"] == scope_raw.decode("ascii")
        and exported["phaseBundleOriginal"] == scope_input["publicBundleOriginal"]
        and exported["bootstrapObservationOriginal"] == scope_input["observationOriginal"]
        and exported["assignmentOriginal"] == source["recipeOriginals"]["assignmentOriginal"])
    components = p.document(launch_row["inputOriginal"], bridge_launch.launch.MAX_INPUT)["originals"]
    for job, component in (("native-closure-bridge", "closure"),
                           ("native-encrypted-delivery-bridge", "encryptedKeys"),
                           ("native-verifier-transport-bridge", "verifierTransport")):
        result = p.fields(records[job]["result"], ("original", "sha256"))
        p.require(result["original"] == components[component]
            and result["sha256"] == p.sha(components[component].encode("ascii")))
    for name, component in (("closureOriginal", "closure"), ("keyConfigurationOriginal", "keys"),
                            ("admissionAuthorizationOriginal", "admission")):
        p.require(exported[name] == components[component])
    value = {"apiVersion": "catchplate.nativePilotDriverAuthorityInput/v1", "operation": "constructed",
        **{name + "Original": raw.decode("ascii") for name, raw in bootstrap.items()}, **observed,
        "launchOriginal": launch_raw.decode("ascii"), "verifierConfigurationOriginal": verifier_raw.decode("ascii"),
        "verifierConfigurationSha256": p.sha(verifier_raw),
        **{name: fragment[name] for name in ("assignmentPublicKeyOriginal", "assignmentPublicKeySha256")}}
    raw = p.canonical(value)
    prepared = authority.prepare_input("constructed", raw, **clocks)
    return raw, prepared


def checked_constructed(input_raw, result, *, prepared_at_boottime_ns, prepared_at_unix_ns,
        boot, now_boottime_ns, now_unix_ns, deadline_boottime_ns):
    """Authenticate completed bytes without granting a post-start signing path.

    The retained caller must supply its actual original preparation samples.
    Complete issuer checks run at those samples; current boot, monotonicity,
    original lifetime and every inherited UNIX expiry remain enforced now.
    """
    prepared = authority.prepare_input("constructed", input_raw, boot=boot,
        now_boottime_ns=prepared_at_boottime_ns, now_unix_ns=prepared_at_unix_ns)
    p.require(p.integer(prepared_at_boottime_ns, maximum=p.MAX_U64) <= p.integer(now_boottime_ns, maximum=p.MAX_U64)
        and p.integer(prepared_at_unix_ns) <= p.integer(now_unix_ns) < prepared["epochLimit"]
        and now_boottime_ns < p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
        <= p.ns(prepared["window"]["lifetimeDeadlineBoottimeNs"]))
    raw = _original_result(result, purpose="driver-constructed-admission", maximum=16384)
    checked = authority._checked_result("constructed", input_raw,
        {name: result[name] for name in ("original", "sha256")}, prepared)
    p.require(checked == raw)
    return raw


def _origin(observed, *, input_raw, admission_raw, scope_raw):
    p.fields(observed, ("constructedObservation", "constructedAdmissionSha256"))
    value = p.document(input_raw, MAX_INPUT)
    _, public = authority._original(value["publicAdmissionOriginal"], 8 * 1024 * 1024)
    expected = {"apiVersion": "catchplate.nativeShadowDriverBridgeConstructed/v1",
        "observationSha256": p.sha(public["bootstrapObservationOriginal"].encode("ascii")),
        "scopeSha256": p.sha(scope_raw)}
    authority._same(observed["constructedObservation"], expected)
    p.require(observed["constructedAdmissionSha256"] == p.sha(admission_raw))


def _handoff(observed):
    p.fields(observed, ("originHandoff",))
    handoff = p.fields(observed["originHandoff"], ("apiVersion", "okForAction", "automaticRetryAllowed", "originSha256"))
    p.require(handoff["apiVersion"] == "catchplate.nativeGenerationOriginHandoff/v1"
        and handoff["okForAction"] is False and handoff["automaticRetryAllowed"] is False)
    p.digest(handoff["originSha256"])


def prepare(job, *, fragment, commissioning_context, scope_context, observed, prior_context,
        boot, now_boottime_ns, now_unix_ns, deadline_boottime_ns):
    """Return one actual input original, never an installed/cleanup verdict."""
    p.require(type(job) is str and job in JOBS)
    selected = validate_policy(fragment)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(p.integer(now_boottime_ns, maximum=p.MAX_U64) < p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
        and p.integer(now_unix_ns) < p.integer(commissioning_context["epochLimit"]))
    if job == "driver-constructed":
        p.require(prior_context is None)
        raw, prepared = _constructed(selected, commissioning_context, scope_context, observed, clocks)
        deadline = min(prepared["deadline"], commissioning_context["deadline"], deadline_boottime_ns)
    else:
        p.fields(prior_context, PRIOR_FIELDS if job == "observe-generation-origin" else STOP_PRIOR_FIELDS)
        sample = dict(boot=boot, now_boottime_ns=prior_context["preparedAtBoottimeNs"],
            now_unix_ns=prior_context["preparedAtUnixNanos"])
        input_raw = _bytes(prior_context["inputOriginal"], MAX_INPUT)
        original = p.document(input_raw, MAX_INPUT)
        # Rebuild only from retained originals, not a caller's expected payload.
        rebuilt, prepared = _constructed(selected, commissioning_context, scope_context,
            {name: original[name] for name in OBSERVATION_FIELDS}, sample)
        p.require(rebuilt == input_raw)
        _, config = authority._original(original["configurationOriginal"], 65536)
        scope_input = p.document(scope_context["inputOriginal"], scope_authority.MAX_BRIDGE_INPUT)
        _, operation = authority._original(scope_input["operationOriginal"], 65536)
        reserve = max(p.integer(config["lifecycle"]["cleanupReserveNanos"]),
            p.integer(operation["production"]["cleanupReserveNanos"]))
        deadline = min(deadline_boottime_ns, p.ns(prepared["window"]["lifetimeDeadlineBoottimeNs"]) - reserve)
        signed = checked_constructed(input_raw, prior_context["result"],
            prepared_at_boottime_ns=sample["now_boottime_ns"], prepared_at_unix_ns=sample["now_unix_ns"],
            deadline_boottime_ns=deadline, **clocks)
        if job == "observe-generation-origin":
            _origin(observed, input_raw=input_raw, admission_raw=signed, scope_raw=scope_context["scopeOriginal"])
            raw = p.canonical({"action": "observe-installed-generation"})
        else:
            _origin(prior_context["originObservation"], input_raw=input_raw,
                admission_raw=signed, scope_raw=scope_context["scopeOriginal"])
            expected = {"action": "observe-installed-generation"}
            p.require(_bytes(prior_context["originInputOriginal"], 1024) == p.canonical(expected))
            authority._same(prior_context["originResult"], expected)
            _handoff(observed)
            raw = p.canonical({"action": "stop"})
    epoch = min(commissioning_context["epochLimit"], prepared["epochLimit"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch)
    return {"inputOriginal": raw, "window": copy.deepcopy(prepared["window"]),
        "deadline": deadline, "epochLimit": epoch}


def build(job, **kwargs):
    return prepare(job, **kwargs)["inputOriginal"]
