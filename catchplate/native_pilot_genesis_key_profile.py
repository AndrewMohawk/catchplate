"""Cold-only public key-admission preparation; never approval or a live owner.

Complete independently approved C9 and cold-binding originals select every
key, process observation and interval. The existing native output wires stay
unchanged. No hot cohort fallback, key generation, attestation, default local
role or renewed deadline is provided by this public-data profile.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_closure_set as sets
from catchplate import native_pilot_genesis_delivery_authority as delivery
from catchplate import native_pilot_publication_cold_binding as binding
from catchplate import native_shadow_key_admission_profile as admission

p = g.p
API = "catchplate.nativePilotGenesisKeyAuthorityInput/v1"
ROLES = sets.GENESIS_ROLES
OPERATIONS = ("role-keys", "admission")
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 65536
SOURCE_FIELDS = ("deliveryInputOriginal", "deliveryOriginal", "coldBindingInputOriginal", "coldBindingInputSha256")
INPUT_FIELDS = ("apiVersion", "operation", "role", *SOURCE_FIELDS, "policy")
POLICY_FIELDS = ("localRoles", "challengeBase64url", "issuedAtUnixNanos", "expiresAtUnixNanos")
DOMAINS = {"role-keys": "catchplate.nativeShadowRoleKeyAssignment.signature/v2", "admission": admission.ADMISSION_DOMAIN}
REQUIRED_ROLES = {"publicationGenesisRetrieval": "custody-retrieval-response",
    "publicationGenesis": "custody-publication-reconciliation"}
BOOTSTRAP = {"apiVersion": "catchplate.nativePublicationGenesisBootstrapRuntime/v1",
    "purpose": "measure-publication-genesis-before-runtime-admission"}


def same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    return value.encode("ascii")


def preimage(domain, payload):
    p.require(domain in (*DOMAINS.values(), "catchplate.nativeCustodyClosureAssignment.signature/v6"))
    return (b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))


def policy(role, value):
    p.require(role in ROLES)
    p.fields(value, POLICY_FIELDS)
    local = value["localRoles"]
    p.require(type(local) is list and 1 <= len(local) <= 16
        and all(type(item) is str and item in p.ROLES[:16] for item in local)
        and local == sorted(set(local), key=p.ROLES.index))
    if role in REQUIRED_ROLES:
        p.require(local == [REQUIRED_ROLES[role]])
    # Native admission requires nonempty roles even for the coordinator. Its
    # complete independent policy, not this helper, must choose those roles.
    p.require(p.decoded(value["challengeBase64url"], size=32) != bytes(32))
    p.require(p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))
    return value


def source_context(role, value, *, boot, now_boottime_ns, now_unix_ns):
    """Authenticate literal data; caller approval supplies its provenance."""
    p.require(role in ROLES)
    input_raw = original(value["deliveryInputOriginal"], delivery.MAX_INPUT)
    signed_raw = original(value["deliveryOriginal"], 65536)
    checked = delivery.verified_delivery(role, input_raw, signed_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    # Retain checked public data, not the transient cryptography verifier.
    # Public-key bytes and the exact signed source originals remain pinned.
    observed = {name: item for name, item in checked.items() if name != "key"}
    binding_raw = original(value["coldBindingInputOriginal"], binding.MAX_INPUT)
    approved = binding.input_document(binding_raw)
    bound = binding.result_document(binding.prepare(binding_raw, expected_input_sha256=value["coldBindingInputSha256"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns))
    _, assignment, trust, keys, _ = binding._authorities(approved, now_unix_ns)
    set_raw = original(approved["closureSetOriginal"], sets.MAX_BYTES)
    selected = sets.validate(set_raw, api_version=sets.GENESIS_BOOTSTRAP_API)
    leaf = sets.leaf_binding(selected, role, api_version=sets.GENESIS_BOOTSTRAP_API)
    manifest = selected["members"][ROLES.index(role)]["manifest"]
    scope = g.document(bound["genesisScopeOriginal"].encode("ascii"), 16384)
    guest, runtime_raw = observed["guest"], observed["runtime_raw"]
    p.require(guest["serviceRole"] == "production-bridge" and p.sha(runtime_raw) == guest["runtimeConfigurationSha256"]
        and manifest["workerExecutableSha256"] == observed["executable_sha256"]
        and manifest["imageSha256"] == observed["image_sha256"])
    if role == ROLES[-1]:
        runtime = g.document(runtime_raw, g.MAX_BYTES)
        p.require(runtime["apiVersion"] == "catchplate.nativePublicationGenesisCoordinatorRuntime/v2"
            and manifest["runtimeConfigurationSha256"] == p.sha(g.canonical(BOOTSTRAP))
            and manifest["runtimeConfigurationSha256"] != p.sha(runtime_raw))
        # The full late runtime contains authenticated ordinary grants for
        # this exact commissioning scope, not just the same boot/window.
        same(runtime["scope"], scope)
    else:
        same(g.document(runtime_raw, 65536), {"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": role})
        p.require(manifest["runtimeConfigurationSha256"] == p.sha(runtime_raw))
    for field in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"):
        same(guest[field], scope[field])
    p.require(p.ns(guest["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"]
        < scope["expiresAtBoottimeNanos"] <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))
    supervisor = keys[-1]
    p.require(supervisor["role"] == "custody-supervisor-capability"
        and supervisor["keyId"] != observed["cold"]["authority"]["keyId"]
        and supervisor["publicKeyBase64url"] != observed["cold"]["authority"]["publicKeyBase64url"])
    checkpoint = trust["checkpoint"]
    key_bounds = [trust["assignmentKey"], trust["timeKey"], *(row["key"] for row in trust["roleKeys"])]
    epoch_limit = min(bound["expiresAtUnixNanos"], trust["expiresAtUnixNanos"], assignment["payload"]["expiresAtUnixNanos"],
        trust["issuedAtUnixNanos"] + binding.MAX_AGE + 1,
        assignment["payload"]["issuedAtUnixNanos"] + binding.MAX_AGE + 1,
        checkpoint["asOfUnixNanos"] + binding.MAX_AGE, *(row["notAfterUnixNanos"] for row in key_bounds))
    deadline = min(observed["deadline"], scope["expiresAtBoottimeNanos"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    source = {"delivery": observed, "deliveryInputOriginal": input_raw, "deliveryOriginal": signed_raw,
        "coldBindingInputOriginal": binding_raw, "coldBindingInputSha256": p.sha(binding_raw),
        "coldBinding": bound, "assignment": assignment, "closureSet": selected}
    return {"source": source, "guest": guest, "window": observed["window"], "manifest": manifest, "leaf": leaf,
        "authorityKeys": keys, "trustCheckpoint": checkpoint, "deadline": deadline, "epochLimit": epoch_limit,
        "issuedFloor": bound["issuedAtUnixNanos"]}


def require_interval(context, issued, expires, now):
    p.freshness(issued, expires, now, binding.MAX_AGE)
    p.require(context["issuedFloor"] <= issued < expires <= context["epochLimit"])
    maximum_age = p.integer(context["source"]["assignment"]["payload"]["observationWindow"]["maximumEvidenceAgeNanos"])
    p.require(expires - issued <= maximum_age)
    return min(context["epochLimit"], expires, issued + binding.MAX_AGE + 1)


def input_document(raw):
    # The larger outer envelope contains literal originals, not native numeric
    # DTOs. Each native document is decoded separately with the u64 codec.
    value = p.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == API and value.get("operation") in OPERATIONS and value.get("role") in ROLES)
    p.fields(value, INPUT_FIELDS + (("roleKeyOriginal",) if value["operation"] == "admission" else ()))
    return value


def prepare_input(operation, role, input_raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(input_raw)
    p.require(operation in OPERATIONS and role in ROLES and value["operation"] == operation and value["role"] == role)
    row = policy(role, value["policy"])
    context = source_context(role, value, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    epoch_limit = require_interval(context, row["issuedAtUnixNanos"], row["expiresAtUnixNanos"], now_unix_ns)
    assignment, checkpoint = context["source"]["assignment"], context["trustCheckpoint"]
    supervisor, keys = context["authorityKeys"][-1], context["authorityKeys"]
    common = {"assignmentPayloadSha256": assignment["payloadSha256"], "assignmentRevision": assignment["payload"]["assignmentRevision"],
        "guest": context["guest"], "executionClosureManifestSha256": context["manifest"]["manifestSha256"],
        "fullKeySetRootSha256": p.key_root(keys), "challengeBase64url": row["challengeBase64url"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": row["issuedAtUnixNanos"],
        "expiresAtUnixNanos": row["expiresAtUnixNanos"], "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    role_payload = {"apiVersion": "catchplate.nativeShadowRoleKeyAssignment/v2", "profile": "preassigned-encrypted-local-v1",
        "purpose": "shadow-role-key-possession", "assignmentId": assignment["payload"]["assignmentId"], **common,
        "localRoles": copy.deepcopy(row["localRoles"])}
    p.fields(role_payload, p.AUTH_FIELDS)
    payload = role_payload
    if operation == "admission":
        role_raw = original(value["roleKeyOriginal"], MAX_OUTPUT)
        verify_result(role_raw, "role-keys", role_payload, supervisor)
        payload = {"apiVersion": "catchplate.nativeShadowKeyAdmissionAssignment/v1", "purpose": "native-shadow-key-admission",
            **common, "keyAuthorizationSha256": p.sha(role_raw),
            "localKeySetRootSha256": p.key_root([key for key in keys if key["role"] in row["localRoles"]])}
        p.fields(payload, admission.ADMISSION_FIELDS)
    p.require(len(g.canonical(payload)) + 128 <= MAX_OUTPUT)
    return {**context, "payload": payload, "epochLimit": epoch_limit, "operation": operation}


def verify_result(raw, operation, expected, supervisor):
    signed = p.fields(g.document(raw, MAX_OUTPUT), ("payload", "signature"))
    p.fields(signed["payload"], p.AUTH_FIELDS if operation == "role-keys" else admission.ADMISSION_FIELDS)
    same(signed["payload"], expected)
    p.public_key(supervisor).verify(p.decoded(signed["signature"], size=64), preimage(DOMAINS[operation], expected))
    return signed


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    context = prepare_input(operation, role, input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == result["sha256"])
    verify_result(raw, operation, context["payload"], context["authorityKeys"][-1])
    return raw


def admitted_pair(role, role_key_input_raw, role_key_raw, admission_input_raw, admission_raw,
        *, boot, now_boottime_ns, now_unix_ns):
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    first, second = input_document(role_key_input_raw), input_document(admission_input_raw)
    p.require(first["operation"] == "role-keys" and second["operation"] == "admission")
    for field in INPUT_FIELDS:
        if field != "operation":
            # The outer literals may exceed the bounded native-document codec.
            p.require(p.canonical(first[field]) == p.canonical(second[field]))
    p.require(second["roleKeyOriginal"] == role_key_raw.decode("ascii"))
    context = prepare_input("admission", role, admission_input_raw, **clocks)
    authorization = g.document(role_key_raw, MAX_OUTPUT)
    admitted = verify_result(admission_raw, "admission", context["payload"], context["authorityKeys"][-1])
    # prepare_input verified the exact preceding role original under the same
    # complete sources; no duplicate owner or cached approval is constructed.
    payload, key_payload = admitted["payload"], authorization["payload"]
    local = [key for key in context["authorityKeys"] if key["role"] in key_payload["localRoles"]]
    expected = {"apiVersion": "catchplate.nativeShadowKeyAdmissionScope/v1", "purpose": "native-shadow-key-admission",
        "assignmentId": key_payload["assignmentId"],
        **{name: payload[name] for name in ("assignmentPayloadSha256", "assignmentRevision", "keyAuthorizationSha256", "guest",
            "executionClosureManifestSha256", "fullKeySetRootSha256", "localKeySetRootSha256", "challengeBase64url")},
        "admissionAuthorizationSha256": p.sha(admission_raw), "localKeys": local,
        "structurallyVerifiedSeccompPolicySha256": context["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "workerExecutableSha256": context["manifest"]["workerExecutableSha256"]}
    p.fields(expected, admission.SCOPE_FIELDS)
    return copy.deepcopy({"authorization": authorization, "admissionAuthorization": admitted, "expectedScope": expected,
        **{name: context[name] for name in ("authorityKeys", "trustCheckpoint", "source", "deadline", "epochLimit")}})
