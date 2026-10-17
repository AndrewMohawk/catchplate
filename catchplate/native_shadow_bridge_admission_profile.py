"""Explicit combined native context and production scope; old purposes unchanged."""
from catchplate import native_shadow_nitro_profile as p

CONFIG_FIELDS = tuple(name if name != "expectedStatement" else "expectedScope" for name in p.CONFIG_FIELDS) + ("admissionAuthorization",)
SCOPE_FIELDS = ("apiVersion", "purpose", "assignmentId", "assignmentPayloadSha256", "assignmentRevision",
    "keyAuthorizationSha256", "admissionAuthorizationSha256", "guest", "executionClosureManifestSha256",
    "structurallyVerifiedSeccompPolicySha256", "workerExecutableSha256", "fullKeySetRootSha256", "localKeySetRootSha256",
    "localKeys", "challengeBase64url", "productionConfigurationBindingSha256")
STATEMENT_FIELDS = SCOPE_FIELDS + ("nativeContext", "nativeContextSha256")
CONTEXT_FIELDS = ("apiVersion", "profile", "guestSha256", "executionClosureManifestSha256", "processId", "processStartTicks",
    "pidfdInode", "parentProcessId", "parentStartTicks", "parentPidfdInode", "cgroupSha256", "rootDevice", "rootInode", "observedAtBoottimeNs")
ADMISSION_FIELDS = ("apiVersion", "purpose", "assignmentPayloadSha256", "assignmentRevision", "keyAuthorizationSha256",
    "guest", "executionClosureManifestSha256", "fullKeySetRootSha256", "localKeySetRootSha256", "challengeBase64url",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos",
    "signingKeyId", "signingKeySpkiSha256", "productionConfigurationBindingSha256")
ADMISSION_DOMAIN = "catchplate.nativeShadowBridgeAdmissionAssignment.signature/v1"
POSSESSION_DOMAIN = "catchplate.nativeShadowBridgeAdmissionPossession.signature/v1"
RESULT_DOMAIN = "catchplate.nativeShadowBridgeContextResult.signature/v1"
PREFIX = b"catchplate/native-shadow-bridge-admission-evidence/v1\0"


def authorization(config, now):
    p.fields(config, CONFIG_FIELDS)
    p.require(config["apiVersion"] == "catchplate.nativeShadowNitroVerifierConfiguration/v3")
    auth = p.fields(config["authorization"], ("payload", "signature"))
    a = p.fields(auth["payload"], p.AUTH_FIELDS)
    scope = p.fields(config["expectedScope"], SCOPE_FIELDS)
    p.require(a["apiVersion"] == "catchplate.nativeShadowRoleKeyAssignment/v2"
        and a["profile"] == "preassigned-encrypted-local-v1" and a["purpose"] == "shadow-role-key-possession"
        and scope["apiVersion"] == "catchplate.nativeShadowBridgeAdmissionScope/v1"
        and scope["purpose"] == "native-shadow-context-and-production-admission")
    p.guest(a["guest"]); p.guest(scope["guest"])
    p.require(a["guest"] == scope["guest"])
    for name in ("assignmentId", "assignmentPayloadSha256", "executionClosureManifestSha256", "fullKeySetRootSha256"):
        p.require(p.digest(a[name]) == p.digest(scope[name]))
    p.require(p.integer(a["assignmentRevision"]) == p.integer(scope["assignmentRevision"])
        and scope["keyAuthorizationSha256"] == p.sha(p.canonical(auth))
        and a["challengeBase64url"] == scope["challengeBase64url"]
        and p.decoded(a["challengeBase64url"], size=32) != bytes(32))
    for name in ("admissionAuthorizationSha256", "structurallyVerifiedSeccompPolicySha256", "workerExecutableSha256", "localKeySetRootSha256", "productionConfigurationBindingSha256"):
        p.digest(scope[name])
    p.freshness(a["issuedAtUnixNanos"], a["expiresAtUnixNanos"], now)
    checkpoint = p.fields(config["trustCheckpoint"], ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256"))
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now <= checkpoint["asOfUnixNanos"] + 300_000_000_000
        and a["trustCheckpointId"] == p.digest(checkpoint["checkpointId"])
        and p.integer(a["revocationGeneration"]) == p.integer(checkpoint["revocationGeneration"])
        and a["revocationRootSha256"] == p.digest(checkpoint["revocationRootSha256"]))
    keys = config["authorityKeys"]
    p.require(type(keys) is list and len(keys) == 18)
    for index, key in enumerate(keys):
        p.public_key(key)
        p.require(key["role"] == p.ROLES[index])
    for name in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        p.require(len({key[name] for key in keys}) == 18)
    p.require(p.key_root(keys) == a["fullKeySetRootSha256"])
    roles = a["localRoles"]
    p.require(type(roles) is list and 1 <= len(roles) <= 16 and all(role in p.ROLES[:16] for role in roles)
        and roles == sorted(set(roles), key=p.ROLES.index))
    local = [keys[p.ROLES.index(role)] for role in roles]
    p.require(scope["localKeys"] == local and p.key_root(local) == scope["localKeySetRootSha256"])
    supervisor = keys[-1]
    p.require(a["signingKeyId"] == supervisor["keyId"] and a["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
    p.public_key(supervisor).verify(p.decoded(auth["signature"], size=64),
        p.preimage("catchplate.nativeShadowRoleKeyAssignment.signature/v2", a))
    admission = p.fields(config["admissionAuthorization"], ("payload", "signature"))
    grant = p.fields(admission["payload"], ADMISSION_FIELDS)
    p.require(grant["apiVersion"] == "catchplate.nativeShadowBridgeAdmissionAssignment/v1"
        and grant["purpose"] == "native-shadow-context-and-production-admission"
        and scope["admissionAuthorizationSha256"] == p.sha(p.canonical(admission)))
    for name in ("assignmentPayloadSha256", "assignmentRevision", "keyAuthorizationSha256", "guest", "executionClosureManifestSha256",
                 "fullKeySetRootSha256", "localKeySetRootSha256", "challengeBase64url", "productionConfigurationBindingSha256"):
        p.require(grant[name] == scope[name])
    for name in ("trustCheckpointId", "revocationGeneration", "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256"):
        p.require(grant[name] == a[name])
    p.freshness(grant["issuedAtUnixNanos"], grant["expiresAtUnixNanos"], now)
    p.public_key(supervisor).verify(p.decoded(admission["signature"], size=64), p.preimage(ADMISSION_DOMAIN, grant))
    p.integer(config["maximumResultAgeNanos"], maximum=30_000_000_000)
    return scope, keys


def statement(value, scope):
    p.fields(value, STATEMENT_FIELDS)
    p.require(value["apiVersion"] == "catchplate.nativeShadowBridgeAdmissionStatement/v1")
    for name in SCOPE_FIELDS[1:]:
        p.require(value[name] == scope[name])
    context = p.fields(value["nativeContext"], CONTEXT_FIELDS)
    p.require(context["apiVersion"] == "catchplate.nativeShadowKeyAdmissionContext/v1"
        and context["profile"] == "same-process-native-originals-v1"
        and context["guestSha256"] == p.sha(p.canonical(scope["guest"]))
        and context["executionClosureManifestSha256"] == scope["executionClosureManifestSha256"]
        and value["nativeContextSha256"] == p.sha(p.canonical(context)))
    for name in ("processId", "parentProcessId"):
        p.integer(context[name], minimum=2, maximum=(1 << 31) - 1)
    p.require(context["processId"] != context["parentProcessId"])
    for name in ("processStartTicks", "pidfdInode", "parentStartTicks", "parentPidfdInode", "rootDevice", "rootInode"):
        p.integer(context[name], maximum=(1 << 64) - 1)
    p.require(context["pidfdInode"] != context["parentPidfdInode"])
    p.digest(context["cgroupSha256"])
    observed = p.ns(context["observedAtBoottimeNs"])
    p.require(p.ns(scope["guest"]["issuedAtBoottimeNs"]) <= observed < p.ns(scope["guest"]["startupDeadlineBoottimeNs"]))
    return value
