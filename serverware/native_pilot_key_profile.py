"""Purpose-fixed public key authorizations for ten actual endpoint deliveries.

Every original and clock sample comes from an independently approved input or
its retained caller. These pure functions authenticate public associations;
they cannot establish kernel provenance, approve a policy or create a live
owner. The verified pair is not a fabricated Nitro verifier configuration.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as generation

from serverware import native_pilot_assignment as assignments
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_measured_configuration as measured_profile
from serverware import native_pilot_native_delivery_profile as native_delivery
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_shadow_retrieval_artifacts as retrieval

p = delivery.p
ROLES = cohort.ENDPOINT_ROLES
OPERATIONS = ("role-keys", "admission")
API = "serverware.nativePilotKeyAuthorityInput/v1"
ADOPTED_API = "serverware.nativePilotKeyAuthorityInput/v2"
ADOPTED_ROLES = cohort.ADOPTED_ENDPOINT_ROLES
MAX_INPUT = 32 * 1024 * 1024
MAX_OUTPUT = 65536
MAX_POLICY = 65536
POLICY_FIELDS = ("localRoles", "challengeBase64url", "issuedAtUnixNanos", "expiresAtUnixNanos")
INPUT_FIELDS = ("apiVersion", "operation", "role", "deliveryInputOriginal", "deliveryOriginal",
    "recipeOriginals", "measured", "policy")
DOMAINS = {"role-keys": "serverware.nativeShadowRoleKeyAssignment.signature/v2",
    "admission": admission.ADMISSION_DOMAIN}
REQUIRED_ROLES = {"retrieval": "custody-retrieval-response", "persistence": "custody-store-response",
    "trustedTime": "custody-trusted-time-response", "generationInstall": "custody-result-envelope",
    "commitRequest": "custody-ledger-append", "ingressAdmission": "custody-ingress-admission",
    "terminalAppend": "custody-terminal-append", "dispatchBarrier": "custody-dispatch-barrier",
    "activeEffectBarrier": "custody-active-effect-barrier", "activeEffectCommit": "custody-active-effect-commit"}


def input_document(raw):
    # The complete recipe is bounded at32MiB, not the C9 codec's4MiB.
    # C9 originals are literal strings here; their selected reader below
    # separately validates native unsigned metadata under its own cap.
    return p.document(raw, MAX_INPUT)


def canonical(value, *, adopted=False):
    return p.canonical(value)


def original(text, maximum, *, adopted=False):
    if not adopted:
        return c9._original(text, maximum)
    p.require(type(text) is str and text.isascii())
    raw = text.encode("ascii")
    return raw, generation.document(raw, maximum)


def preimage(domain, payload, *, adopted=False):
    # Native policy_shadow::canonical_json_bytes remains signed-i64 even
    # when an unsigned original or C9 source can describe full-u64 metadata.
    # Reject unsupported signed payloads, never issue unusable authority.
    return p.preimage(domain, payload)


def _policy(role, row, *, adopted=False):
    p.require(role in (ADOPTED_ROLES if adopted else ROLES))
    p.fields(row, POLICY_FIELDS)
    local = row["localRoles"]
    p.require(type(local) is list and 1 <= len(local) <= 16
        and all(type(name) is str and name in p.ROLES[:16] for name in local)
        and local == sorted(set(local), key=p.ROLES.index)
        and ("custody-publication-reconciliation" if role == "publicationReconciliation" else REQUIRED_ROLES[role]) in local)
    p.require(p.decoded(row["challengeBase64url"], size=32) != bytes(32))
    p.require(p.integer(row["issuedAtUnixNanos"]) < p.integer(row["expiresAtUnixNanos"]))
    return row


def validate_policy(fragment, *, adopted=False) -> dict:
    roles = ADOPTED_ROLES if adopted else ROLES
    p.fields(fragment, roles)
    for role in roles:
        _policy(role, fragment[role], adopted=adopted)
    p.require(len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def _delivery(role, input_raw, raw, *, boot, now, adopted=False, now_unix_ns=None):
    """The existing input9 is common to the earlier three and later seven."""
    if adopted:
        from serverware import native_pilot_adopted_delivery as successor
        context = successor.verify_delivery(input_raw, raw, boot=boot,
            now_boottime_ns=now, now_unix_ns=now_unix_ns)
        p.require(context["role"] == role)
        configuration = cohort.configuration(context["owner_configuration_raw"])
        c9._same(configuration[role + "Configuration"],
            {"path": launch.ADOPTED_DESTINATIONS["native-cold-" + role], "sha256": p.sha(context["configuration_raw"])})
        c9._same(context["payload"]["runtimeConfig"],
            {"path": launch.ADOPTED_DESTINATIONS["native-runtime-" + role], "sha256": p.sha(context["runtime_raw"])})
        return context["guest"], context["window"], context["observed"], context["runtime_raw"], context["cold"]
    value = p.fields(p.document(input_raw, c9.MAX_INPUT), c9.INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotDeliverySigningInput/v1" and value["role"] == role)
    cold_raw, _ = c9._original(value["configurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw, config = c9._original(value["ownerConfigurationOriginal"], cohort.MAX_BYTES)
    window_raw, signed_window = c9._original(value["windowOriginal"], 32768)
    _, observed = c9._original(value["observationOriginal"], cohort.MAX_BYTES)
    window = c9.endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed_window,
        observed, boot=boot, now=now)
    c9._same(config[role + "Configuration"],
        {"path": publication.DESTINATIONS["native-cold-" + role], "sha256": p.sha(cold_raw)})
    runtime_raw, _ = c9._original(value["runtimeOriginal"], 65536)
    launch.shape("native-runtime-" + role, runtime_raw)
    payload_raw, payload = c9._original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    p.fields(payload, delivery.FIELDS)
    _, activation = c9._original(value["activationOriginal"], 32768, array=True)
    c9._activation(activation, c9.ENDPOINTS[role])
    c9._credentials(payload["credentials"], cold["authority"])
    expected = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in c9.WINDOW_FIELDS},
        "runtimeConfig": {"path": publication.DESTINATIONS["native-runtime-" + role], "sha256": p.sha(runtime_raw)},
        "credentials": payload["credentials"], "activation": activation}
    p.require(p.canonical(expected) == payload_raw)
    signed = p.fields(p.document(raw, delivery.MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
        and p.canonical(signed["payload"]) == payload_raw)
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + payload_raw)
    return delivery._delivery_guest(payload, raw), window, observed, runtime_raw, cold


def _recipe(role, originals, measured, runtime_raw, observed, now, *, adopted=False):
    p.fields(originals, native_delivery.RECIPE_FIELDS)
    p.fields(measured, native_delivery.MEASURED_FIELDS)
    p.require(measured["apiVersion"] == "serverware.nativePilotMeasuredConfiguration/v2")
    p.digest(measured["recipeSha256"])
    envelope, bindings, key_root = measured_profile._assignment(
        {"apiVersion": "serverware.nativePilotMeasuredConfigurationRecipe/v2", **originals}, now)
    assignment = envelope["payload"]
    _, trust = c9._original(originals["trustOriginal"], 1024 * 1024)
    public = {row["role"]: row["key"]["publicKeyBase64url"] for row in trust["roleKeys"]}
    keys = [bindings[name] | {"publicKeyBase64url": public[name]} for name in p.ROLES]
    for field in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        p.require(len({key[field] for key in keys}) == len(p.ROLES) == 18)
    p.require(p.key_root(keys) == key_root)
    text = originals["closureSetOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= closure_set.MAX_BYTES)
    raw = text.encode("ascii")
    set_api = closure_set.PUBLICATION_API if adopted else closure_set.API
    leaf = assignments.closure_binding(envelope, raw, role, set_api_version=set_api)
    selected = closure_set.validate(raw, api_version=set_api)
    manifest = selected["members"][(ADOPTED_ROLES if adopted else ROLES).index(role)]["manifest"]
    p.require(manifest["manifestSha256"] == leaf["manifestSha256"]
        and manifest["runtimeConfigurationSha256"] == p.sha(runtime_raw)
        and manifest["workerExecutableSha256"] == observed[role]["executable"]["sha256"])
    proof_raw, _ = c9._original(measured["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(proof_raw)
    retrieval.require_assignment_scope(proof, p.canonical(assignment))
    binding_raw, binding = c9._original(measured["configurationBindingOriginal"], 65536)
    p.require(p.framed(b"serverware.policyShadowProductionCustodyConfiguration/v2", (binding_raw,))
        == measured["configurationBindingSha256"] == proof["production_configuration_binding_sha256"]
        and binding["assignmentId"] == assignment["assignmentId"]
        and binding["assignmentPayloadSha256"] == envelope["payloadSha256"]
        and binding["assignmentRevision"] == assignment["assignmentRevision"]
        and binding["nativeClosureSet"] == assignment["nativeClosureSet"]
        and binding["assertedCustodyKeySetRootSha256"] == key_root
        and binding["executionClosureManifestSha256"] == proof["execution_closure_manifest_sha256"]
        and binding["structurallyVerifiedSeccompPolicySha256"] == proof["structurally_verified_seccomp_policy_sha256"])
    production = p.fields(measured["production"], scope.PRODUCTION_FIELDS)
    measured_profile._production({name: production[name] for name in measured_profile.PRODUCTION_FIELDS})
    p.require(production["expectedConfigurationBindingSha256"] == measured["configurationBindingSha256"])
    for name in measured_profile.PRODUCTION_FIELDS:
        c9._same(production[name], binding[name])
    return envelope, keys, trust, manifest


def _verify(raw, operation, expected, key, *, adopted=False):
    signed = p.fields((generation.document if adopted else p.document)(raw, MAX_OUTPUT), ("payload", "signature"))
    p.fields(signed["payload"], p.AUTH_FIELDS if operation == "role-keys" else admission.ADMISSION_FIELDS)
    p.require(canonical(signed["payload"], adopted=adopted) == canonical(expected, adopted=adopted))
    p.public_key(key).verify(p.decoded(signed["signature"], size=64), preimage(DOMAINS[operation], expected, adopted=adopted))
    return signed


def prepare_input(operation, role, input_raw, *, boot, now_boottime_ns, now_unix_ns) -> dict:
    """Derive the sole permitted payload and verified public signing context."""
    p.require(operation in OPERATIONS)
    value = p.fields(input_document(input_raw),
        INPUT_FIELDS + (("roleKeyOriginal",) if operation == "admission" else ()))
    adopted = value["apiVersion"] == ADOPTED_API
    p.require(value["apiVersion"] in (API, ADOPTED_API) and role in (ADOPTED_ROLES if adopted else ROLES)
        and value["operation"] == operation and value["role"] == role)
    row = _policy(role, value["policy"], adopted=adopted)
    p.integer(now_unix_ns)
    delivery_input, _ = original(value["deliveryInputOriginal"], generation.MAX_BYTES if adopted else c9.MAX_INPUT, adopted=adopted)
    delivery_raw, _ = original(value["deliveryOriginal"], delivery.MAX_DELIVERY, adopted=adopted)
    guest, window, observed, runtime_raw, cold = _delivery(role, delivery_input, delivery_raw,
        boot=boot, now=now_boottime_ns, adopted=adopted, now_unix_ns=now_unix_ns)
    envelope, keys, trust, manifest = _recipe(role, value["recipeOriginals"], value["measured"],
        runtime_raw, observed, now_unix_ns, adopted=adopted)
    p.require(keys[-1]["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
        and keys[-1]["keyId"] != cold["authority"]["keyId"])
    assignment, checkpoint = envelope["payload"], trust["checkpoint"]
    issued, expires = row["issuedAtUnixNanos"], row["expiresAtUnixNanos"]
    if adopted and role == "retrieval":
        from serverware import native_pilot_adopted_delivery as successor
        source = generation.document(delivery_input, successor.MAX_INPUT)
        _, core_observed = successor._original(source["coreObservationOriginal"], successor.core.MAX_OBSERVATION)
        p.require(core_observed["issuedAtUnixNanos"] <= issued < expires <= core_observed["expiresAtUnixNanos"])
    p.freshness(issued, expires, now_unix_ns)
    p.require(assignment["issuedAtUnixNanos"] <= issued < expires <= assignment["expiresAtUnixNanos"]
        and trust["issuedAtUnixNanos"] <= issued < expires <= trust["expiresAtUnixNanos"]
        and checkpoint["asOfUnixNanos"] <= issued < expires <= checkpoint["asOfUnixNanos"] + 300_000_000_000
        and expires - issued <= p.integer(assignment["observationWindow"]["maximumEvidenceAgeNanos"]))
    for key in [trust["assignmentKey"], trust["timeKey"], *(item["key"] for item in trust["roleKeys"])]:
        p.require(key["notBeforeUnixNanos"] <= issued < expires <= key["notAfterUnixNanos"])
    p.integer(checkpoint["revocationGeneration"], maximum=p.MAX_U64)
    common = {"assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": assignment["assignmentRevision"], "guest": guest,
        "executionClosureManifestSha256": manifest["manifestSha256"], "fullKeySetRootSha256": p.key_root(keys),
        "challengeBase64url": row["challengeBase64url"], "trustCheckpointId": checkpoint["checkpointId"],
        "revocationGeneration": checkpoint["revocationGeneration"], "revocationRootSha256": checkpoint["revocationRootSha256"],
        "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires,
        "signingKeyId": keys[-1]["keyId"], "signingKeySpkiSha256": keys[-1]["keySpkiSha256"]}
    role_payload = {"apiVersion": "serverware.nativeShadowRoleKeyAssignment/v2",
        "profile": "preassigned-encrypted-local-v1", "purpose": "shadow-role-key-possession",
        "assignmentId": assignment["assignmentId"], **common, "localRoles": row["localRoles"]}
    p.fields(role_payload, p.AUTH_FIELDS)
    payload = role_payload
    if operation == "admission":
        role_raw, _ = original(value["roleKeyOriginal"], MAX_OUTPUT, adopted=adopted)
        _verify(role_raw, "role-keys", role_payload, keys[-1], adopted=adopted)
        local = [key for key in keys if key["role"] in row["localRoles"]]
        payload = {"apiVersion": "serverware.nativeShadowKeyAdmissionAssignment/v1",
            "purpose": "native-shadow-key-admission", **common,
            "keyAuthorizationSha256": p.sha(role_raw), "localKeySetRootSha256": p.key_root(local)}
        p.fields(payload, admission.ADMISSION_FIELDS)
    p.require(len(p.canonical(payload)) < MAX_OUTPUT)
    return copy.deepcopy({"payload": payload, "authorityKeys": keys, "trustCheckpoint": checkpoint,
        "manifest": manifest, "window": window})


def build(operation, role, *, fragment, delivery_input_raw, delivery_raw, measured, recipe_originals,
          boot, now_boottime_ns, now_unix_ns, role_key_raw=None, adopted=False) -> bytes:
    p.require(type(adopted) is bool and operation in OPERATIONS and role in (ADOPTED_ROLES if adopted else ROLES))
    fragment = validate_policy(fragment, adopted=adopted)
    p.require((type(role_key_raw) is bytes) if operation == "admission" else role_key_raw is None)
    value = {"apiVersion": ADOPTED_API if adopted else API, "operation": operation, "role": role,
        "deliveryInputOriginal": delivery_input_raw.decode("ascii"), "deliveryOriginal": delivery_raw.decode("ascii"),
        "recipeOriginals": recipe_originals, "measured": measured, "policy": fragment[role]}
    if operation == "admission":
        value["roleKeyOriginal"] = role_key_raw.decode("ascii")
    raw = canonical(value, adopted=adopted)
    p.require(len(raw) <= MAX_INPUT)
    prepare_input(operation, role, raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return raw


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns) -> bytes:
    context = prepare_input(operation, role, input_raw,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    adopted = input_document(input_raw)["apiVersion"] == ADOPTED_API
    p.fields(result, ("original", "sha256"))
    raw, _ = original(result["original"], MAX_OUTPUT, adopted=adopted)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    _verify(raw, operation, context["payload"], context["authorityKeys"][-1], adopted=adopted)
    return raw


def admitted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
                  *, boot, now_boottime_ns, now_unix_ns) -> dict:
    """Verified public pair/scope only; no Nitro, collateral or evidence defaults."""
    return _admitted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=False)


def admitted_adopted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
                         *, boot, now_boottime_ns, now_unix_ns) -> dict:
    """Explicit hot12/C9-v2 pair; never accepts a relabeled legacy input."""
    return _admitted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=True)


def _admitted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
                   *, boot, now_boottime_ns, now_unix_ns, adopted):
    options = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    first = input_document(role_key_input_raw)
    second = input_document(admission_input_raw)
    p.require(first["apiVersion"] == second["apiVersion"] == (ADOPTED_API if adopted else API))
    for name in INPUT_FIELDS:
        if name != "operation":
            p.require(canonical(first[name], adopted=adopted) == canonical(second[name], adopted=adopted))
    p.require(second["roleKeyOriginal"] == role_key_raw.decode("ascii"))
    for operation, input_raw, raw in (("role-keys", role_key_input_raw, role_key_raw),
            ("admission", admission_input_raw, admission_raw)):
        checked_result(operation, role, input_raw, {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **options)
    context = prepare_input("admission", role, admission_input_raw, **options)
    authorization = (generation.document if adopted else p.document)(role_key_raw, MAX_OUTPUT)
    admitted = (generation.document if adopted else p.document)(admission_raw, MAX_OUTPUT)
    key_payload, payload = authorization["payload"], admitted["payload"]
    local = [key for key in context["authorityKeys"] if key["role"] in key_payload["localRoles"]]
    expected = {"apiVersion": "serverware.nativeShadowKeyAdmissionScope/v1", "purpose": "native-shadow-key-admission",
        "assignmentId": key_payload["assignmentId"],
        **{name: payload[name] for name in ("assignmentPayloadSha256", "assignmentRevision", "keyAuthorizationSha256",
            "guest", "executionClosureManifestSha256", "fullKeySetRootSha256", "localKeySetRootSha256", "challengeBase64url")},
        "admissionAuthorizationSha256": p.sha(admission_raw), "localKeys": local,
        "structurallyVerifiedSeccompPolicySha256": context["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "workerExecutableSha256": context["manifest"]["workerExecutableSha256"]}
    p.fields(expected, admission.SCOPE_FIELDS)
    return copy.deepcopy({"authorization": authorization, "admissionAuthorization": admitted, "expectedScope": expected,
        "authorityKeys": context["authorityKeys"], "trustCheckpoint": context["trustCheckpoint"]})
