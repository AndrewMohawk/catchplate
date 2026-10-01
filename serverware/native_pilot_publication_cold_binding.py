"""Unsigned, independently selected cold-publication commitment and scope.

This is NOT ProductionCustodyConfiguration, a measured hot-driver binding,
assignment admission, a generation grant or a runtime owner. The fixed native
cold retrieval Scope checks an independently selected nonempty binding and its
assignment/set/key joins; it does not construct a hot configuration. Native
cold grants additionally authenticate actual guests, histories and deadlines.
Operational adoption separately checks the real current hot configuration.

The caller must independently approve/hash-pin the COMPLETE canonical input
and supply actual clock/domain samples. No untrusted field supplies a clock,
driver identity, future grant or permission to sign. All output is public data.
"""
from __future__ import annotations

import copy

from serverware import authority_policy_canary_native_opening as opening
from serverware import custody_generation_grants as codec
from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_closure_set as closure
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_retrieval_artifacts as retrieval

API = "serverware.nativePilotPublicationColdBindingInput/v1"
RESULT_API = "serverware.nativePilotPublicationColdBinding/v1"
BINDING_API = "serverware.nativePublicationGenesisConfigurationBinding/v1"
BINDING_DOMAIN = BINDING_API.encode("ascii")
GENESIS_API = "serverware.nativePublicationGenesisScope/v1"
MAX_INPUT = codec.MAX_BYTES
MAX_OUTPUT = 65536
MAX_AGE = 300_000_000_000
FIELDS = ("apiVersion", "trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal",
    "commissioningIdSha256", "initialPublicationRevision", "window")
WINDOW_FIELDS = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNanos", "expiresAtBoottimeNanos", "issuedAtUnixNanos", "expiresAtUnixNanos")
RESULT_FIELDS = ("apiVersion", "inputSha256", "configurationBindingOriginal", "configurationBindingSha256",
    "proofScopeOriginal", "genesisScopeOriginal", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
BINDING_FIELDS = ("apiVersion", "purpose", "inputSha256", "assignmentOriginalSha256", "assignmentId",
    "assignmentPayloadSha256", "assignmentRevision", "authorityId", "storageRealmSha256", "retrievalNamespaceSha256",
    "authorityKeyIndependenceSha256", "assertedCustodyKeySetRootSha256", "trustOriginalSha256", "trustCheckpoint",
    "closureSetOriginalSha256", "nativeClosureSet", "executionClosureManifestSha256",
    "structurallyVerifiedSeccompPolicySha256", "coordinatorExecutableSha256", "custodyKeys",
    "commissioningIdSha256", "initialPublicationRevision", "window")
GENESIS_FIELDS = ("apiVersion", "commissioningIdSha256", "productionConfigurationBindingSha256",
    "assignmentPayloadSha256", "assignmentRevision", "proofScopeOriginal", "retrievalNamespaceSha256",
    "initialPublicationRevision", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
TRUST_FIELDS = ("apiVersion", "checkpoint", "assignmentKey", "timeKey", "roleKeys", "issuedAtUnixNanos", "expiresAtUnixNanos")
CHECKPOINT_FIELDS = ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256")


def _digest(value):
    p.require(p.digest(value) != p.sha(b""))
    return value


def _original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    return raw, codec.document(raw, min(maximum, codec.MAX_BYTES))


def _window(value):
    p.fields(value, WINDOW_FIELDS)
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    for name in ("timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
        p.integer(value[name], minimum=0 if name == "timeNamespaceDevice" else 1, maximum=p.MAX_U64)
    p.require(value["issuedAtBoottimeNanos"] < value["expiresAtBoottimeNanos"])
    p.require(p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))
    return value


def input_document(raw):
    """Closed canonical grammar only; prepare performs public authentication."""
    value = p.fields(codec.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API)
    _digest(value["commissioningIdSha256"])
    p.integer(value["initialPublicationRevision"], maximum=p.MAX_U64)
    _window(value["window"])
    trust_raw, _ = _original(value["trustOriginal"], 1024 * 1024)
    p.require(p.sha(trust_raw) == p.digest(value["trustSha256"]))
    _original(value["assignmentOriginal"], assignment.MAX_BYTES)
    _original(value["closureSetOriginal"], closure.MAX_BYTES)
    return value


def _authorities(value, now):
    """Authenticate the signed assignment and every selected custody key.

    Only the scope-relevant assignment grammar/identities are interpreted here.
    Its unrelated fleet/policy semantics remain native assignment admission.
    """
    trust_raw, trust = _original(value["trustOriginal"], 1024 * 1024)
    p.fields(trust, TRUST_FIELDS)
    p.require(trust["apiVersion"] == "serverware.nativeShadowGuestTrust/v1"
        and p.sha(trust_raw) == value["trustSha256"])
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], now, MAX_AGE)
    checkpoint = p.fields(trust["checkpoint"], CHECKPOINT_FIELDS)
    _digest(checkpoint["checkpointId"]); _digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now < checkpoint["asOfUnixNanos"] + MAX_AGE)
    signing = launch._key(trust["assignmentKey"], now)
    launch._key(trust["timeKey"], now)
    materials = {trust["assignmentKey"]["publicKeyBase64url"], trust["timeKey"]["publicKeyBase64url"]}
    p.require(len(materials) == 2 and type(trust["roleKeys"]) is list and 1 <= len(trust["roleKeys"]) <= 128)
    selected = {}
    for item in trust["roleKeys"]:
        p.fields(item, ("role", "key"))
        role, key = item["role"], item["key"]
        p.require(type(role) is str and role.isascii() and 1 <= len(role) <= 128 and role not in selected)
        launch._key(key, now)
        p.require(key["publicKeyBase64url"] not in materials)
        materials.add(key["publicKeyBase64url"]); selected[role] = key
    p.require(set(p.ROLES).issubset(selected))
    raw, envelope = _original(value["assignmentOriginal"], assignment.MAX_BYTES)
    p.fields(envelope, assignment.FIELDS)
    p.require(envelope["apiVersion"] == envelope["signatureDomain"] == assignment.DOMAINS[2]
        and envelope["kind"] == "PolicyShadowAssignment" and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["canonicalProfile"] == "serverware.canonicalJson/ascii-integer-v1"
        and envelope["signingKeyId"] == trust["assignmentKey"]["keyId"]
        and envelope["signingKeySpkiSha256"] == trust["assignmentKey"]["keySpkiSha256"])
    payload = opening.assignment_payload(envelope["payload"], version=2)
    payload_raw = codec.canonical(payload)
    p.require(p.sha(payload_raw) == p.digest(envelope["payloadSha256"]))
    # Same native signature framing, but preserve the actual Rust u64 codec.
    signing.verify(p.decoded(envelope["signature"], size=64), b"serverware.signedEnvelope/v1\0"
        + assignment.DOMAINS[2].encode("ascii") + b"\0serverware.canonicalJson/ascii-integer-v1\0" + payload_raw)
    _digest(payload["assignmentId"])
    p.integer(payload["assignmentRevision"], maximum=p.MAX_U64)
    for name in ("generationEpoch", "minimumGenerationTombstoneEpoch"):
        p.integer(payload[name], maximum=p.MAX_U64)
    p.require(payload["minimumGenerationTombstoneEpoch"] <= payload["generationEpoch"])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now, MAX_AGE)
    _, root = opening._keys(payload)
    keys = []
    for role in p.ROLES:
        rows = [row for row in payload["authorityKeyIndependence"]["bindings"]
            if row["role"] == role and row["scopeSha256"] == payload["assignmentId"]]
        p.require(len(rows) == 1)
        row, key = rows[0], selected[role]
        public = {name: row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
        p.require(public["keyId"] == key["keyId"] and public["keySpkiSha256"] == key["keySpkiSha256"])
        public["publicKeyBase64url"] = key["publicKeyBase64url"]
        p.public_key(public); keys.append(public)
    p.require(p.key_root(keys) == root)
    bounds = [trust["assignmentKey"], trust["timeKey"], *selected.values()]
    floor = max(trust["issuedAtUnixNanos"], payload["issuedAtUnixNanos"], checkpoint["asOfUnixNanos"],
        *(key["notBeforeUnixNanos"] for key in bounds))
    ceiling = min(trust["expiresAtUnixNanos"], payload["expiresAtUnixNanos"],
        checkpoint["asOfUnixNanos"] + MAX_AGE, *(key["notAfterUnixNanos"] for key in bounds))
    window = value["window"]
    p.require(floor <= window["issuedAtUnixNanos"] < window["expiresAtUnixNanos"] <= ceiling
        and window["expiresAtUnixNanos"] - window["issuedAtUnixNanos"] <= MAX_AGE)
    return raw, envelope, trust, keys, root


def _proof(binding, binding_sha):
    names = ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "authorityId", "storageRealmSha256",
        "retrievalNamespaceSha256", "authorityKeyIndependenceSha256", None, "assertedCustodyKeySetRootSha256",
        "executionClosureManifestSha256", "structurallyVerifiedSeccompPolicySha256")
    values = [binding_sha if name is None else binding[name] for name in names]
    proof = dict(zip(retrieval.SCOPE_VALUES, values, strict=True))
    roots = binding["nativeClosureSet"]
    values.extend((roots["setRootSha256"], roots["seccompSetRootSha256"]))
    proof.update(api_version=retrieval.SCOPE_SET_API, execution_closure_set_root_sha256=roots["setRootSha256"],
        structurally_verified_seccomp_set_root_sha256=roots["seccompSetRootSha256"])
    for target, role in (("store_response_authority", "custody-store-response"),
                         ("retrieval_response_authority", "custody-retrieval-response")):
        key = next(row for row in binding["custodyKeys"] if row["role"] == role)
        proof[target] = dict(zip(("role", "key_id", "key_spki_sha256", "key_material_sha256"),
            (key[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")), strict=True))
    proof["binding_sha256"] = p.framed(retrieval.SCOPE_SET_API.encode("ascii"), (codec.canonical(values),))
    return proof


def result_document(raw):
    """Check closed output and all internal hashes/joins; NOT input approval."""
    value = p.fields(codec.document(raw, MAX_OUTPUT), RESULT_FIELDS)
    p.require(value["apiVersion"] == RESULT_API)
    _digest(value["inputSha256"])
    binding_raw, binding = _original(value["configurationBindingOriginal"], MAX_OUTPUT)
    p.fields(binding, BINDING_FIELDS)
    p.require(binding["apiVersion"] == BINDING_API and binding["purpose"] == "cold-publication-genesis"
        and binding["inputSha256"] == value["inputSha256"])
    for name in BINDING_FIELDS:
        if name.endswith("Sha256") or name in ("assignmentId", "authorityId"):
            _digest(binding[name])
    for name in ("assignmentRevision", "initialPublicationRevision"):
        p.integer(binding[name], maximum=p.MAX_U64)
    for digest in p.fields(binding["nativeClosureSet"], ("setRootSha256", "seccompSetRootSha256")).values():
        _digest(digest)
    checkpoint = p.fields(binding["trustCheckpoint"], CHECKPOINT_FIELDS)
    _digest(checkpoint["checkpointId"]); _digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["asOfUnixNanos"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    _window(binding["window"])
    p.require(type(binding["custodyKeys"]) is list
        and tuple(row["role"] for row in binding["custodyKeys"]) == p.ROLES)
    for key in binding["custodyKeys"]:
        p.public_key(key)
    p.require(p.key_root(binding["custodyKeys"]) == binding["assertedCustodyKeySetRootSha256"])
    binding_sha = p.framed(BINDING_DOMAIN, (binding_raw,))
    p.require(binding_sha == p.digest(value["configurationBindingSha256"]))
    proof_raw, proof = _original(value["proofScopeOriginal"], 16384)
    p.require(proof_raw == codec.canonical(_proof(binding, binding_sha)))
    scope_raw, scope = _original(value["genesisScopeOriginal"], 16384)
    p.fields(scope, GENESIS_FIELDS)
    window = binding["window"]
    expected = {"apiVersion": GENESIS_API, "commissioningIdSha256": binding["commissioningIdSha256"],
        "productionConfigurationBindingSha256": binding_sha, "assignmentPayloadSha256": binding["assignmentPayloadSha256"],
        "assignmentRevision": binding["assignmentRevision"], "proofScopeOriginal": proof_raw.decode("ascii"),
        "retrievalNamespaceSha256": binding["retrievalNamespaceSha256"],
        "initialPublicationRevision": binding["initialPublicationRevision"],
        **{name: window[name] for name in WINDOW_FIELDS[:5]}}
    p.require(scope_raw == codec.canonical(expected))
    for name in WINDOW_FIELDS[:3] + WINDOW_FIELDS[5:]:
        p.require(codec.canonical(value[name]) == codec.canonical(window[name]))
    p.require(p.ns(value["issuedAtBoottimeNs"]) == window["issuedAtBoottimeNanos"]
        and p.ns(value["deadlineBoottimeNs"]) == window["expiresAtBoottimeNanos"])
    return value


def prepare(input_original, *, expected_input_sha256, boot, now_boottime_ns, now_unix_ns):
    """Validate complete approved public input and derive only cold data."""
    p.require(type(input_original) is bytes and 0 < len(input_original) <= MAX_INPUT
        and p.sha(input_original) == p.digest(expected_input_sha256))
    value = input_document(input_original)
    window = value["window"]
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    p.require(type(boot) is tuple and len(boot) == 3)
    p.decoded(boot[0], size=16)
    p.integer(boot[1], minimum=0, maximum=p.MAX_U64); p.integer(boot[2], maximum=p.MAX_U64)
    p.require((window["bootIdBase64url"], window["timeNamespaceDevice"], window["timeNamespaceInode"]) == boot
        and window["issuedAtBoottimeNanos"] <= now_boottime_ns < window["expiresAtBoottimeNanos"]
        and window["issuedAtUnixNanos"] <= now_unix_ns < window["expiresAtUnixNanos"])
    assignment_raw, envelope, trust, keys, root = _authorities(value, now_unix_ns)
    payload = envelope["payload"]
    set_raw, _ = _original(value["closureSetOriginal"], closure.MAX_BYTES)
    selected = assignment._closure_selection(payload, set_raw, set_api_version=closure.GENESIS_BOOTSTRAP_API)
    anchor = closure.leaf_binding(selected, "publicationGenesisCoordinator", api_version=closure.GENESIS_BOOTSTRAP_API)
    manifest = selected["members"][-1]["manifest"]
    authority = payload["custodyAuthority"]
    binding = {"apiVersion": BINDING_API, "purpose": "cold-publication-genesis", "inputSha256": expected_input_sha256,
        "assignmentOriginalSha256": p.sha(assignment_raw), "assignmentId": payload["assignmentId"],
        "assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": payload["assignmentRevision"],
        **{name: authority[name] for name in ("authorityId", "storageRealmSha256", "retrievalNamespaceSha256")},
        "authorityKeyIndependenceSha256": payload["authorityKeyIndependence"]["independenceRootSha256"],
        "assertedCustodyKeySetRootSha256": root, "trustOriginalSha256": value["trustSha256"],
        "trustCheckpoint": copy.deepcopy(trust["checkpoint"]), "closureSetOriginalSha256": p.sha(set_raw),
        "nativeClosureSet": copy.deepcopy(payload["nativeClosureSet"]),
        "executionClosureManifestSha256": anchor["manifestSha256"],
        "structurallyVerifiedSeccompPolicySha256": anchor["structurallyVerifiedPolicySha256"],
        "coordinatorExecutableSha256": manifest["workerExecutableSha256"], "custodyKeys": keys,
        "commissioningIdSha256": value["commissioningIdSha256"],
        "initialPublicationRevision": value["initialPublicationRevision"], "window": copy.deepcopy(window)}
    binding_raw = codec.canonical(binding)
    binding_sha = p.framed(BINDING_DOMAIN, (binding_raw,))
    proof_raw = codec.canonical(_proof(binding, binding_sha))
    genesis = {"apiVersion": GENESIS_API, "commissioningIdSha256": value["commissioningIdSha256"],
        "productionConfigurationBindingSha256": binding_sha, "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": payload["assignmentRevision"], "proofScopeOriginal": proof_raw.decode("ascii"),
        "retrievalNamespaceSha256": authority["retrievalNamespaceSha256"],
        "initialPublicationRevision": value["initialPublicationRevision"],
        **{name: window[name] for name in WINDOW_FIELDS[:5]}}
    result = {"apiVersion": RESULT_API, "inputSha256": expected_input_sha256,
        "configurationBindingOriginal": binding_raw.decode("ascii"), "configurationBindingSha256": binding_sha,
        "proofScopeOriginal": proof_raw.decode("ascii"), "genesisScopeOriginal": codec.canonical(genesis).decode("ascii"),
        **{name: window[name] for name in WINDOW_FIELDS[:3] + WINDOW_FIELDS[5:]},
        "issuedAtBoottimeNs": str(window["issuedAtBoottimeNanos"]), "deadlineBoottimeNs": str(window["expiresAtBoottimeNanos"])}
    raw = codec.canonical(result)
    result_document(raw)
    return raw
