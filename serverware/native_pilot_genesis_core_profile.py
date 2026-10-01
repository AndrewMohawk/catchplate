"""Cold-core byte/signature joins, never a live owner or fresh authority.

Grant roots and their provenance belong to the actual completed assembly.
This narrow checker reauthenticates its fixed Prepared/Stored/Completion and
ordinary witnesses; it does not replace native receipt/history admission.
"""
from __future__ import annotations

import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_authority as ordinary
from serverware import native_pilot_publication_cold_binding as binding

p = g.p
API = "serverware.nativePilotGenesisCoreObservation/v1"
MAX_CORE, MAX_BUNDLE, MAX_OBSERVATION = 512 * 1024, 4 * 1024 * 1024, 32768
FILENAME = "core-00000000000000000001.json"
FILE_FIELDS = ("device", "inode", "mode", "uid", "gid", "nlink", "length", "mtimeNanos", "ctimeNanos")
DIRECTORY_FIELDS = ("device", "inode", "mode", "uid", "gid")
HASH_FIELDS = ("bundleSha256", "scopeSha256", "commissioningIdSha256", "parentConfigurationSha256",
    "parentPrecreationSha256", "ordinaryConfigurationSha256", "endpointConfigurationSha256",
    "endpointPreparationSha256", "endpointResourcesSha256", "retrievalDeliverySha256", "nativeGrantSha256",
    "retrievalGrantSha256", "coreSha256", "objectSha256", "fsveritySha256")
FIELDS = ("apiVersion", *HASH_FIELDS, "filename", "directory", "file", "issuedAtBoottimeNs",
    "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
CORE_FIELDS = ("apiVersion", "nativeGrantSha256", "genesis", "observedAtUnixNanos", "trustCheckpointSha256",
    "signingKeyId", "signingKeySpkiSha256")
STORED_FIELDS = ("apiVersion", "guest", "grantSha256", "coreSha256", "objectSha256", "fsveritySha256",
    "retrievalIdSha256", "retrievalProofSha256", "previousHeadSha256", "sequence", "storedAtBoottimeNanos",
    "originalDeadlineBoottimeNanos", "signingKeyId", "signingKeySpkiSha256")
WITNESS_FIELDS = ("apiVersion", "scopeSha256", "commissioningIdSha256", "completionSha256",
    "predecessorEvidenceSha256", "grantSha256", "authorityEpoch", "completedAtBoottimeNanos", "signatureBase64url")
PREPARED_DOMAIN = "serverware.nativePublicationGenesisPreparation.signature/v1"
STORAGE_DOMAIN = "serverware.nativePublicationGenesisStorage.signature/v1"
COMPLETION_DOMAIN = "serverware.nativePublicationGenesisCompletion.signature/v1"


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def _sha(value):
    return p.sha(g.canonical(value))


def _uint(value, *, minimum=1):
    return p.integer(value, minimum=minimum, maximum=p.MAX_U64)


def _key(row):
    public = p.decoded(row["publicKeyBase64url"], size=32)
    p.require(public != bytes(32) and row["keySpkiSha256"] == p.sha(bytes.fromhex("302a300506032b6570032100") + public))
    p.digest(row["keyId"])
    return Ed25519PublicKey.from_public_bytes(public)


def _ordinary_message(domain, payload):
    raw = g.canonical(payload)
    return b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw


def _shapes(bundle_raw):
    bundle = p.fields(g.document(bundle_raw, MAX_BUNDLE), ("completion", "durable", "current"))
    completion = p.fields(bundle["completion"], ("apiVersion", "prepared", "stored", "receiptOriginal",
        "completedAtBoottimeNanos", "signature"))
    p.require(completion["apiVersion"] == "serverware.nativePublicationGenesisCompletion/v1")
    prepared = p.fields(completion["prepared"], ("core", "preparedAtBoottimeNanos", "signature"))
    core = p.fields(prepared["core"], CORE_FIELDS)
    p.require(core["apiVersion"] == "serverware.nativeInitialPublicationCore/v1")
    stored = p.fields(completion["stored"], ("payload", "signature"))
    payload = p.fields(stored["payload"], STORED_FIELDS)
    p.require(payload["apiVersion"] == "serverware.nativePublicationGenesisStorage/v1"
        and type(payload["sequence"]) is int and payload["sequence"] == 1)
    raw = g.canonical(core)
    p.require(0 < len(raw) <= MAX_CORE and payload["objectSha256"] == p.sha(raw)
        and payload["coreSha256"] == p.framed(b"serverware.nativeInitialPublicationCore/v1", (raw,)))
    return bundle, completion, prepared, core, stored, payload, raw


def verify_file_metadata(actual, expected):
    for row in (actual, expected):
        p.fields(row, FILE_FIELDS)
        for name in FILE_FIELDS:
            _uint(row[name], minimum=0 if name in ("device", "mtimeNanos", "ctimeNanos") else 1)
        p.require(row["mode"] == stat.S_IFREG | 0o400 and row["nlink"] == 1
            and 0 < row["length"] <= MAX_CORE and row["uid"] < (1 << 32) - 1 and row["gid"] < (1 << 32) - 1)
    _same(actual, expected)


def observation(raw, bundle_raw=None):
    value = p.fields(g.document(raw, MAX_OBSERVATION), FIELDS)
    p.require(value["apiVersion"] == API and value["filename"] == FILENAME)
    for name in HASH_FIELDS:
        p.require(p.digest(value[name]) != p.sha(b""))
    verify_file_metadata(value["file"], value["file"])
    directory = p.fields(value["directory"], DIRECTORY_FIELDS)
    for name in DIRECTORY_FIELDS:
        _uint(directory[name], minimum=0 if name == "device" else 1)
    p.require(directory["mode"] == stat.S_IFDIR | 0o700 and directory["uid"] == value["file"]["uid"]
        and directory["gid"] == value["file"]["gid"] and directory["device"] == value["file"]["device"])
    p.require(p.ns(value["issuedAtBoottimeNs"]) < p.ns(value["deadlineBoottimeNs"])
        and p.integer(value["issuedAtUnixNanos"]) < p.integer(value["expiresAtUnixNanos"]))
    if bundle_raw is not None:
        _, _, _, core, _, stored, core_raw = _shapes(bundle_raw)
        scope = core["genesis"]["scope"]
        p.require(value["bundleSha256"] == p.sha(bundle_raw) and value["scopeSha256"] == _sha(scope)
            and value["commissioningIdSha256"] == scope["commissioningIdSha256"]
            and value["nativeGrantSha256"] == core["nativeGrantSha256"]
            and value["retrievalGrantSha256"] == stored["grantSha256"]
            and value["retrievalDeliverySha256"] == stored["guest"]["deliverySha256"]
            and value["coreSha256"] == stored["coreSha256"] and value["objectSha256"] == p.sha(core_raw)
            and value["fsveritySha256"] == stored["fsveritySha256"]
            and value["file"]["uid"] == stored["guest"]["uid"] and value["file"]["gid"] == stored["guest"]["gid"]
            and value["file"]["length"] == len(core_raw)
            and p.ns(value["issuedAtBoottimeNs"]) == scope["issuedAtBoottimeNanos"]
            and p.ns(value["deadlineBoottimeNs"]) <= stored["originalDeadlineBoottimeNanos"] == scope["expiresAtBoottimeNanos"])
    return value


def verify(bundle_raw, *, scope, native_grant_raw, retrieval_grant_raw, ordinary_payloads, ordinary_grant_sha256,
           retrieval_guest, genesis_raw, now_boottime_ns, now_unix_ns):
    """Pinned payloads MUST come from the actual owner's verified grant roots."""
    p.fields(ordinary_payloads, ordinary.initial.ROLES)
    p.fields(ordinary_grant_sha256, ordinary.initial.ROLES)
    first, second = (ordinary_payloads[role] for role in ordinary.initial.ROLES)
    for name in ("scope", "native", "retrieval", "durableAuthorityEpoch", "durablePublicKeyBase64url",
            "currentAuthorityEpoch", "currentPublicKeyBase64url"):
        _same(first[name], second[name])
    _same(first["scope"], scope)
    native = p.fields(g.document(native_grant_raw, g.MAX_BYTES), ("payload", "signature"))["payload"]
    retrieval = p.fields(g.document(retrieval_grant_raw, 65536), ("payload", "signature"))["payload"]
    for grant in (native, retrieval):
        _same(grant["scope"], scope)
        p.freshness(grant["authorization"]["issuedAtUnixNanos"], grant["authorization"]["expiresAtUnixNanos"], now_unix_ns, binding.MAX_AGE)
    _same(native["retrievalGuest"], retrieval_guest); _same(retrieval["authorization"]["guest"], retrieval_guest)
    _same(retrieval["native"], first["native"])
    _same(native["retrieval"], {name: first["retrieval"][name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")})
    p.require(first["native"]["grantSha256"] == p.sha(native_grant_raw)
        and first["retrieval"]["grantSha256"] == p.sha(retrieval_grant_raw))
    bundle, completion, prepared, core, stored, payload, core_raw = _shapes(bundle_raw)
    evidence = p.fields(core["genesis"], ("apiVersion", "scope", "genesisOriginal", "grantSha256", "authorityEpoch",
        "observedAtBoottimeNanos", "signatureBase64url"))
    _same(evidence["scope"], scope)
    p.require(evidence["grantSha256"] == ordinary_grant_sha256[ordinary.initial.ROLES[0]])
    state = {"apiVersion": "serverware.nativePublicationInitialState/v1", "scopeSha256": _sha(scope),
        "publicationRevision": scope["initialPublicationRevision"], "state": "uninstalled", "ledgerEventOrdinal": 0,
        **{name: None for name in ("predecessorGenerationSha256", "committedGenerationSha256", "publishedGenerationSha256",
            "firstIngressSequence", "lastIngressSequence", "preparedPublicationSha256")}}
    p.require(evidence["apiVersion"] == "serverware.nativePublicationGenesis/v1"
        and evidence["genesisOriginal"].encode("ascii") == g.canonical(state)
        and core["nativeGrantSha256"] == p.sha(native_grant_raw)
        and core["trustCheckpointSha256"] == native["authorization"]["trustCheckpointId"] == retrieval["authorization"]["trustCheckpointId"])
    for field in ("signingKeyId", "signingKeySpkiSha256"):
        p.require(core[field] == first["native"]["keyId" if field == "signingKeyId" else "keySpkiSha256"]
            and payload[field] == first["retrieval"]["keyId" if field == "signingKeyId" else "keySpkiSha256"])
    _same(payload["guest"], retrieval_guest)
    p.require(payload["grantSha256"] == p.sha(retrieval_grant_raw)
        and payload["previousHeadSha256"] == p.sha(genesis_raw) == retrieval["store"]["genesisSha256"]
        and payload["originalDeadlineBoottimeNanos"] == scope["expiresAtBoottimeNanos"])
    identity = p.framed(b"serverware.nativeInitialPublicationCore/v1", (core_raw,))
    rid = p.framed(b"serverware.nativeInitialPublicationRetrievalId/v1",
        (scope["retrievalNamespaceSha256"].encode("ascii"), identity.encode("ascii")))
    p.require(payload["retrievalIdSha256"] == rid and payload["retrievalProofSha256"] == p.framed(
        b"serverware.nativeInitialPublicationRetrievalProof/v1", (scope["proofScopeOriginal"].encode("ascii"), rid.encode("ascii"), core_raw)))
    moments = (scope["issuedAtBoottimeNanos"], evidence["observedAtBoottimeNanos"], prepared["preparedAtBoottimeNanos"],
        payload["storedAtBoottimeNanos"], completion["completedAtBoottimeNanos"])
    p.require(all(_uint(left) <= _uint(right) for left, right in zip(moments, moments[1:]))
        and moments[-1] <= now_boottime_ns < _uint(scope["expiresAtBoottimeNanos"]))
    floor = max(grant["authorization"]["issuedAtUnixNanos"] for grant in (native, retrieval))
    epoch_limit = min(*(grant["authorization"]["expiresAtUnixNanos"] for grant in (native, retrieval)),
        *(grant["authorization"]["issuedAtUnixNanos"] + binding.MAX_AGE + 1 for grant in (native, retrieval)),
        p.integer(core["observedAtUnixNanos"]) + binding.MAX_AGE + 1)
    p.require(floor <= core["observedAtUnixNanos"] <= now_unix_ns < epoch_limit)
    native_key, retrieval_key = _key(first["native"]), _key(first["retrieval"])
    native_key.verify(p.decoded(prepared["signature"], size=64), ordinary.native_message(PREPARED_DOMAIN,
        [core, prepared["preparedAtBoottimeNanos"]]))
    retrieval_key.verify(p.decoded(stored["signature"], size=64), ordinary.native_message(STORAGE_DOMAIN, payload))
    native_key.verify(p.decoded(completion["signature"], size=64), ordinary.native_message(COMPLETION_DOMAIN,
        [completion[name] for name in ("apiVersion", "prepared", "stored", "receiptOriginal", "completedAtBoottimeNanos")]))
    for prefix, row, domain, fields in (
        ("durable", evidence, b"serverware.nativePublicationGenesisEvidence.signature/v1",
            ("apiVersion", "scope", "genesisOriginal", "grantSha256", "authorityEpoch", "observedAtBoottimeNanos")),
        ("durable", bundle["durable"], b"serverware.nativePublicationGenesisWitness.signature/v1", WITNESS_FIELDS[:-1]),
        ("current", bundle["current"], b"serverware.nativePublicationGenesisWitness.signature/v1", WITNESS_FIELDS[:-1])):
        if row is not evidence: p.fields(row, WITNESS_FIELDS)
        _same(row["authorityEpoch"], first[prefix + "AuthorityEpoch"])
        key = _key({"publicKeyBase64url": first[prefix + "PublicKeyBase64url"],
            "keyId": row["authorityEpoch"]["serviceSigningKeyId"],
            "keySpkiSha256": row["authorityEpoch"]["serviceSigningKeySpkiSha256"]})
        key.verify(p.decoded(row["signatureBase64url"], size=64), _ordinary_message(domain, [row[name] for name in fields]))
    for role, row, predecessor in ((ordinary.initial.ROLES[0], bundle["durable"], evidence),
            (ordinary.initial.ROLES[1], bundle["current"], bundle["durable"])):
        p.require(row["apiVersion"] == "serverware.nativePublicationGenesisWitness/v1"
            and row["grantSha256"] == ordinary_grant_sha256[role]
            and row["scopeSha256"] == _sha(scope) and row["commissioningIdSha256"] == scope["commissioningIdSha256"]
            and row["completionSha256"] == _sha(completion) and row["predecessorEvidenceSha256"] == _sha(predecessor))
    p.require(completion["completedAtBoottimeNanos"] <= _uint(bundle["durable"]["completedAtBoottimeNanos"])
        <= _uint(bundle["current"]["completedAtBoottimeNanos"]) <= now_boottime_ns)
    return {"core": core_raw, "prepared": g.canonical(prepared), "stored": g.canonical(stored),
        "head": g.canonical({"apiVersion": "serverware.nativeLedgerSpoolStoreHead/v1", "sequence": 1,
            "previousHeadSha256": payload["previousHeadSha256"], "storedOriginalSha256": _sha(stored)}),
        "scope": scope, "storedPayload": payload, "epochFloor": floor, "epochLimit": epoch_limit}
