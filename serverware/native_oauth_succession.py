"""Portable succession originals, never a conversion of reconnect authority.

Only pure provider encodings and scalar predicates are shared. The signed
purpose, original rows, historical application assignment and effect windows
remain distinct. This module imports no control-plane storage or signer graph.
"""
import os
import re
import uuid
from serverware import native_oauth_refresh as m
from serverware import native_oauth_exchange as provider
from serverware import authority_oauth_retirement_succession_catalog as catalog

INTENT = "serverware.nativeOAuthSuccessionIntent/v1"
STATE = "serverware.nativeOAuthSuccessionState/v1"
GRANT = "serverware.oauthRetiredScopeSuccessionAuthorization/v1"
SIGNED_GRANT = "serverware.signedOAuthRetiredScopeSuccessionAuthorization/v1"
STATEMENT = "serverware.nativeOAuthSuccessionStatement/v1"
ACTION = "credential.oauth.measured-succession"
CHANNEL = "serverware.nativeOAuthSuccessionChannel/v1"
CONFIG = "serverware.nativeOAuthSuccessionConfiguration/v1"
TLS = "serverware.nativeOAuthSuccessionTls/v1"
TRANSPORT = "serverware.nativeOAuthSuccessionTransport/v1"
MAX_MESSAGE, MAX_STATE, MAX_GRANT = 8 * 1024 * 1024, 64 * 1024, 128 * 1024
MAX_ARGUMENT, MAX_REQUEST, MAX_RESPONSE = 2 * 1024 * 1024, 3 * 1024 * 1024, 11 * 1024 * 1024 // 4
LIMITS = {"materialCapacity": 16, "affectedLineageCapacity": 7, "populationCapacity": 16,
    "historyCapacity": 64, "authorizationMaxSeconds": 3600}
PHASES = frozenset({"inspect", "material-claim", "contact", "finish", "recover", "prepare", "claim", "capture", "stage", "cancel"})
INTENT_FIELDS = provider.INTENT_FIELDS | {"authorizationOriginal", "scopeRequestOriginal", "scopeResponseOriginal"}
STATE_FIELDS = provider.STATE_FIELDS | {"successionBinding"}
BINDING_FIELDS = frozenset({"authorizationSha256", "scopeRowSha256", "materialClosureSha256", "credentialId", "credentialVersion",
    "providerSubject", "providerAccount", "expiresAtEpochNs"})
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "providerId", "scope", "predecessors", "previousHeadSha256", "credentialId", "credentialVersion", "credentialRowSha256",
    "generationRowSha256", "providerSubject", "providerAccount", "clientId", "enrollmentSha256", "requesterId", "scopes",
    "metadataSha256", "affectedLineages", "materials", "exchangeOrigins", "inventoryRoots", "issuedAtEpochNs", "admissionExpiresAtEpochNs",
    "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"})
HUMAN_FIELDS = frozenset({"action", "resource_id", "payload_digest", "actor_id", "request", "approval_id",
    "credential_policy", "enrollment_original", "authorization_original"})
ARGUMENT_FIELDS = HUMAN_FIELDS | {"control_plane_configuration_digest", "assignment_original", "native_evidence"}
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "deploymentId",
    "instanceId", "providerId", "enrollmentSha256", "exchangeId", "inputSha256", "challenge", "policyHash", "dataPlaneBinarySha256",
    "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256", "issuedAtEpochNs", "expiresAtEpochNs",
    "authorizationSha256", "scopeRowSha256", "materialId"})
PREDECESSORS = frozenset({"refresh-family", "pending-family", "provider-capture", "reconnect-fence", "succession"})
SOURCES = frozenset({"initial-capture", "setup-capture", "reconnect-capture", "succession-capture", "initial-pending", "setup-pending",
    "reconnect-candidate", "succession-candidate", "refresh-issued", "refresh-superseded", "credential-current"})
PIN_FIELDS = frozenset({"materialId", "sourceKind", "sourceId", "sourceVersion", "sourceRowSha256", "custodyRowSha256",
    "tokenSecretSha256", "tokenEnvelopeSha256", "enrollmentSha256", "tokenPurposes"})
LINEAGE_FIELDS = frozenset({"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256",
    "predecessorKind", "predecessorId", "predecessorSha256"})


def array(raw, maximum):
    m.require(type(raw) is bytes and len(raw) < maximum)
    value = m.document(b'{"items":' + raw + b'}', maximum + 10)["items"]
    m.require(type(value) is list)
    return value


def material_id(kind, source_id, version):
    m.require(kind in SOURCES); provider.identifier(source_id); m.integer(version)
    return str(uuid.uuid5(uuid.UUID(source_id), "serverware.oauthRetiredMaterial/v1:" + kind + ":" + str(version)))


def claim_id(authorization_id, item):
    provider.identifier(authorization_id); provider.identifier(item)
    return str(uuid.uuid5(uuid.UUID(authorization_id), "serverware.oauthRetiredMaterialClaim/v1:" + item))


def attempt_id(claim, purpose):
    provider.identifier(claim); m.require(purpose in {"access", "refresh"})
    return str(uuid.uuid5(uuid.UUID(claim), "serverware.oauthRetiredMaterialContact/v1:" + purpose))


def pins(values):
    m.require(type(values) is list and len(values) <= 16)
    for pin in values:
        m.require(type(pin) is dict and set(pin) == PIN_FIELDS
            and pin["materialId"] == material_id(pin["sourceKind"], pin["sourceId"], pin["sourceVersion"])
            and pin["tokenPurposes"] in [["access"], ["refresh"], ["access", "refresh"]])
        for name in ("sourceRowSha256", "tokenEnvelopeSha256", "enrollmentSha256"):
            m.digest(pin[name])
        if pin["tokenSecretSha256"] is None:
            m.require(pin["sourceKind"] == "credential-current")
        else:
            m.digest(pin["tokenSecretSha256"])
        if pin["custodyRowSha256"] is not None:
            m.digest(pin["custodyRowSha256"])
        if pin["sourceKind"] not in {"credential-current", "reconnect-candidate", "succession-candidate"}:
            m.require(pin["sourceVersion"] == 1)
    m.require([item["materialId"] for item in values] == sorted({item["materialId"] for item in values}))
    return values


def grant(raw):
    envelope = m.document(raw, MAX_GRANT)
    m.require(set(envelope) == {"schema", "payload", "signatureBase64Url"} and envelope["schema"] == SIGNED_GRANT)
    m.decoded(envelope["signatureBase64Url"], 64, 64)
    value = envelope["payload"]
    m.require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT
        and value["purpose"] == "measured-oauth-retired-scope-succession" and value["providerId"] in provider.AUTHORIZATION)
    provider.identifier(value["authorizationId"]); provider.identifier(value["credentialId"])
    m.integer(value["credentialVersion"], maximum=2**63 - 2)
    for name in ("configurationDigest", "credentialRowSha256", "generationRowSha256", "enrollmentSha256", "metadataSha256"):
        m.digest(value[name])
    if value["previousHeadSha256"] is not None:
        m.digest(value["previousHeadSha256"])
    for name, maximum in (("sourceRevision", 128), ("deploymentId", 128), ("providerSubject", 512), ("providerAccount", 512),
            ("clientId", 2048), ("requesterId", 512)):
        m.text(value[name], maximum)
    m.require(value["requesterId"].startswith("oidc:") and type(value["scopes"]) is list
        and value["scopes"] == sorted(set(value["scopes"])))
    m.scopes(" ".join(value["scopes"]))
    scope = value["scope"]
    m.require(type(scope) is dict and set(scope) == {"kind", "providerId", "providerSubject", "externalImpactAuthorized"}
        and scope["kind"] in {"family", "provider"} and scope["providerId"] == value["providerId"]
        and scope["externalImpactAuthorized"] is True
        and scope["providerSubject"] == (value["providerSubject"] if scope["kind"] == "family" else None))
    predecessors = value["predecessors"]
    m.require(type(predecessors) is list and 1 <= len(predecessors) <= 10)
    for pin in predecessors:
        m.require(type(pin) is dict and set(pin) == {"kind", "id", "rowSha256", "journalSha256"} and pin["kind"] in PREDECESSORS)
        provider.identifier(pin["id"]); m.digest(pin["rowSha256"]); m.digest(pin["journalSha256"])
        m.require(pin["kind"] != "provider-capture" or scope["kind"] == "provider")
    m.require([(item["kind"], item["id"]) for item in predecessors] == sorted({(item["kind"], item["id"]) for item in predecessors}))
    members = value["affectedLineages"]
    m.require(type(members) is list and 1 <= len(members) <= 7)
    for pin in members:
        m.require(type(pin) is dict and set(pin) == LINEAGE_FIELDS and pin["predecessorKind"] in PREDECESSORS | {"active"})
        provider.identifier(pin["credentialId"]); m.integer(pin["credentialVersion"])
        m.digest(pin["credentialRowSha256"]); m.digest(pin["generationRowSha256"])
        if pin["predecessorKind"] == "active":
            m.require(pin["predecessorId"] is None and pin["predecessorSha256"] is None)
        else:
            provider.identifier(pin["predecessorId"]); m.digest(pin["predecessorSha256"])
    m.require([pin["credentialId"] for pin in members] == sorted({pin["credentialId"] for pin in members}))
    target = [pin for pin in members if pin["credentialId"] == value["credentialId"]]
    m.require(len(target) == 1 and all(target[0][name] == value[name]
        for name in ("credentialVersion", "credentialRowSha256", "generationRowSha256")))
    pins(value["materials"])
    m.require(value["providerId"] != "google" or all(len(pin["tokenPurposes"]) == 1 for pin in value["materials"]))
    origins = value["exchangeOrigins"]
    m.require(type(origins) is list and len(origins) <= 16)
    for entry in origins:
        m.require(type(entry) is dict and set(entry) == {"exchangeId", "sourceKind", "custodyRowSha256"}
            and entry["sourceKind"] in {"initial", "setup", "reconnect", "succession"})
        provider.identifier(entry["exchangeId"]); m.digest(entry["custodyRowSha256"])
    m.require([item["exchangeId"] for item in origins] == sorted({item["exchangeId"] for item in origins}))
    roots = value["inventoryRoots"]
    m.require(type(roots) is list and [item.get("part") for item in roots if type(item) is dict] == sorted(catalog.SNAPSHOT_PARTS))
    for item in roots:
        m.require(set(item) == {"part", "root"})
        root, part = item["root"], item["part"]
        cap = 16 if part in {"credentials", "pending", "setup", "exchanges", "refreshes", "work"} else 32 if part in {"family-fences", "pending-fences"} else 64
        m.require(type(root) is dict and set(root) == {"table", "rootRevision", "rootDigest", "leafCount"}
            and root["table"] == catalog.SNAPSHOT_PARTS[part])
        m.integer(root["rootRevision"], minimum=0); m.integer(root["leafCount"], minimum=0, maximum=cap); m.digest(root["rootDigest"])
    start, admission, contact, retained, pending, end = (m.integer(value[name]) for name in ("issuedAtEpochNs", "admissionExpiresAtEpochNs",
        "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"))
    m.require(start < admission <= contact <= retained <= pending <= end <= start + 3600_000_000_000
        and contact - start <= 600_000_000_000 and retained - contact <= 600_000_000_000
        and len(m.canonical(value)) <= MAX_GRANT - 512)
    return envelope


def binding(value):
    m.require(type(value) is dict and set(value) == BINDING_FIELDS)
    for name in ("authorizationSha256", "scopeRowSha256", "materialClosureSha256"):
        m.digest(value[name])
    provider.identifier(value["credentialId"]); m.integer(value["credentialVersion"], maximum=2**63 - 2)
    m.text(value["providerSubject"], 512); m.text(value["providerAccount"], 512); m.integer(value["expiresAtEpochNs"])
    return value


def intent(value):
    m.require(type(value) is dict and set(value) == INTENT_FIELDS and value["schema"] == INTENT and len(m.canonical(value)) <= MAX_MESSAGE)
    authority = grant(m.decoded(value["authorizationOriginal"], MAX_GRANT))["payload"]
    m.require(all(value[name] == authority[name] for name in ("providerId", "requesterId", "scopes"))
        and type(value["metadata"]) is dict and m.sha(m.canonical(value["metadata"])) == authority["metadataSha256"]
        and type(value["credentialPolicy"]) is dict)
    m.text(value["credentialName"], 256)
    m.decoded(value["scopeRequestOriginal"], MAX_REQUEST); m.decoded(value["scopeResponseOriginal"], MAX_RESPONSE)
    return value


def private_state(raw):
    value = m.document(raw, MAX_STATE)
    m.require(set(value) == STATE_FIELDS and value["schema"] == STATE)
    bound = binding(value["successionBinding"]); provider.identifier(value["exchangeId"])
    m.require(type(value["state"]) is str and re.fullmatch(r"[0-9a-f]{32}_[A-Za-z0-9_-]{43}", value["state"])
        and value["state"][:32] == uuid.UUID(value["exchangeId"]).hex)
    m.decoded(value["state"][33:], 32, 32); m.decoded(value["codeVerifier"], 32, 32)
    m.digest(value["browserNonceSha256"]); m.digest(value["enrollmentSha256"])
    m.require(value["redirectUri"] == provider.callback_uri(value["callbackOrigin"], value["providerId"])
        and provider.origin(value["portalOrigin"]) != value["callbackOrigin"] and type(value["metadata"]) is dict
        and value["metadata"].get(m.ASSOCIATION) == value[m.ASSOCIATION]
        and value["metadata"].get("provider_subject") == bound["providerSubject"]
        and value["metadata"].get("provider_account") == bound["providerAccount"])
    issued, contact, retained, pending = (m.integer(value[name]) for name in
        ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"))
    m.require(issued < contact <= retained <= pending <= bound["expiresAtEpochNs"])
    return value


def prepare(value, *, authorization, scope_original, closure_sha256, enrollment_original, callback_origin, portal_origin, limits, issued_ns):
    """Fresh entropy only after the real owner observes full accepted closure."""
    intent(value); m.digest(closure_sha256)
    m.require(authorization == grant(m.decoded(value["authorizationOriginal"], MAX_GRANT))["payload"])
    enrollment = m.document(enrollment_original, 32768, exact=False)["payload"]
    association = provider.association(enrollment_original, enrollment)
    m.require(value["metadata"].get(m.ASSOCIATION) == association and enrollment["providerId"] == authorization["providerId"]
        and enrollment["clientId"] == authorization["clientId"] and enrollment["redirectUri"] == provider.callback_uri(callback_origin, authorization["providerId"])
        and provider.origin(portal_origin) != callback_origin and m.sha(enrollment_original) == authorization["enrollmentSha256"]
        and enrollment["issuedAtEpochNs"] <= issued_ns < authorization["contactExpiresAtEpochNs"]
        and authorization["expiresAtEpochNs"] <= enrollment["expiresAtEpochNs"])
    identifier = authorization["authorizationId"]
    nonce, verifier = m.encoded(os.urandom(32)), m.encoded(os.urandom(32))
    state = {"schema": STATE, "exchangeId": identifier, "state": uuid.UUID(identifier).hex + "_" + m.encoded(os.urandom(32)),
        "browserNonceSha256": m.sha(nonce.encode("ascii")), "codeVerifier": verifier,
        **{name: value[name] for name in ("providerId", "requesterId", "credentialName", "scopes", "metadata", "credentialPolicy")},
        "redirectUri": enrollment["redirectUri"], "issuedAtEpochNs": issued_ns,
        **{name: authorization[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")},
        "enrollmentSha256": m.sha(enrollment_original), m.ASSOCIATION: association, "limits": limits,
        "portalOrigin": portal_origin, "callbackOrigin": callback_origin,
        "successionBinding": {"authorizationSha256": m.sha(m.decoded(value["authorizationOriginal"], MAX_GRANT)),
            "scopeRowSha256": m.sha(scope_original.encode("ascii")), "materialClosureSha256": closure_sha256,
            **{name: authorization[name] for name in ("credentialId", "credentialVersion", "providerSubject", "providerAccount", "expiresAtEpochNs")}}}
    raw = m.canonical(state); private_state(raw)
    return raw, nonce
