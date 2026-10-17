"""Closed public bridge runtime versions and bounds; never runtime admission.

The explicit v10 carries actual ordinary runtime/generation originals; v11
also requires the helper bootstrap manifest. The selected terminal v12 adds
literal histories to each row. Shape checks do not authenticate their roots,
signatures, process identities, credentials or successful service startup.
"""
from __future__ import annotations

from catchplate import custody_generation_grants as generation

p = generation.p
MAX_LEGACY_RUNTIME = 65536
MAX_RUNTIME = 4 * 1024 * 1024
MAX_BRIDGE_INPUT = 16 * 1024 * 1024
PREFIX = "catchplate.policyCustodyProductionRpcRuntime/v"
ADOPTED_VERSION = 14
ADOPTED_LAUNCH = "catchplate.nativeProofBridgeLaunch/v10"
VERSIONS = tuple(range(4, 13)) + (ADOPTED_VERSION,)
LARGE_VERSIONS = (10, 11, 12, ADOPTED_VERSION)
LAUNCH_RUNTIME = {**{"catchplate.nativeProofBridgeLaunch/v" + str(version): version + 4
    for version in range(1, 9)}, ADOPTED_LAUNCH: ADOPTED_VERSION}
BASE_FIELDS = ("apiVersion", "startupTimeoutMillis", "listenerSocketPath", "expectedFacadePeer",
    "journalDirectoryIdentity", "expectedHelperEndpointRoles", "expectedDriverProcessIdentitySha256",
    "expectedDriverConfigurationGenerationSha256", "expectedOperationGeneration", "expectedSharedConfigurationSha256",
    "expectedServiceConfigurationSha256", "expectedServiceSigningCredentialSha256", "expectedServiceRestartEpoch",
    "expectedServiceReadinessEpoch", "expectedServiceAuthorityHistoryManifestSha256",
    "expectedProductionDispatchProtocolSetSha256", "expectedMaximumDurabilityWorkerNanos", "serviceSessions",
    "histories", "parentSignerEndpoints", "proofEndpoints")


def version(value):
    p.require(type(value) is dict)
    selected = {PREFIX + str(number): number for number in VERSIONS}.get(value.get("apiVersion"))
    p.require(selected is not None)
    return selected


def maximum_for_version(number):
    p.require(type(number) is int and number in VERSIONS)
    return MAX_RUNTIME if number in LARGE_VERSIONS else MAX_LEGACY_RUNTIME


def maximum_for_launch(api):
    p.require(type(api) is str and api in LAUNCH_RUNTIME)
    return maximum_for_version(LAUNCH_RUNTIME[api])


def _original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    return generation.document(value.encode("ascii"), maximum)


def shape(raw):
    # The size successor does not change native canonical integer grammar.
    # Relabelling a large document also cannot widen the legacy byte bound.
    value = p.document(raw, MAX_RUNTIME)
    selected = version(value)
    if selected not in LARGE_VERSIONS:
        p.require(len(raw) <= MAX_LEGACY_RUNTIME)
    extra = (() if selected == 4 else ("generationAdmission",))
    if selected >= 6:
        extra += ("commitRequest",)
    if selected >= 7:
        extra += ("spool",)
    if selected in LARGE_VERSIONS:
        extra += ("ordinaryInitialHistories",)
    if selected in (11, 12, ADOPTED_VERSION):
        extra += ("helperBootstrap",)
    if selected == ADOPTED_VERSION:
        extra += ("publication",)
    p.fields(value, BASE_FIELDS + extra)
    p.integer(value["startupTimeoutMillis"], maximum=30000)
    for field in extra:
        p.require(type(value[field]) is dict)
    if selected >= 5:
        row = p.fields(value["generationAdmission"], ("apiVersion", "grants"))
        p.require(row["apiVersion"] == "catchplate.custodyGenerationServices/v1")
        for digest in p.fields(row["grants"], generation.ROLES).values():
            p.digest(digest)
    if selected >= 6:
        row = p.fields(value["commitRequest"], ("apiVersion", "serviceGrantOriginals"))
        p.require(row["apiVersion"] == "catchplate.nativeCommitRequestServices/v1")
        for original in p.fields(row["serviceGrantOriginals"],
                ("durable-recovery-store", "current-signature-authority")).values():
            _original(original, 65536)
    if selected >= 7:
        effect = selected >= 9
        row = p.fields(value["spool"], ("apiVersion", "headGrantOriginal", "currentGrantOriginal", "originFdName")
            + (("cleanupGrantOriginal",) if effect else ()))
        p.require(row["apiVersion"] == "catchplate.nativeSpoolServices/v" + str(3 if effect else selected - 6)
            and row["originFdName"] == "generation-origin")
        _original(row["headGrantOriginal"], 65536)
        for field in ("currentGrantOriginal",) + (("cleanupGrantOriginal",) if effect else ()):
            _original(row[field], 131072 if selected in LARGE_VERSIONS else 65536)
    if selected in LARGE_VERSIONS:
        for role, row in p.fields(value["ordinaryInitialHistories"], generation.ROLES).items():
            p.fields(row, ("runtimeOriginal", "generationGrantOriginal") + (("historyOriginal",) if selected in (12, ADOPTED_VERSION) else ()))
            if selected in (12, ADOPTED_VERSION):
                _original(row["historyOriginal"], 1024 * 1024)
            runtime = _original(row["runtimeOriginal"], generation.MAX_BYTES)
            p.require(type(runtime.get("runtime")) is dict)
            if selected == ADOPTED_VERSION and role in (generation.ROLES[0], generation.ROLES[3]):
                p.require(runtime["runtime"].get("apiVersion") == "catchplate.policyCustodyServiceRuntimeConfig/v12"
                    and runtime["runtime"].get("publicationAdmission") == {"grantFdName": "publication-grant"})
            grant = p.fields(_original(row["generationGrantOriginal"], 65536), ("payload", "signatureBase64url"))
            payload = p.fields(grant["payload"], generation.GRANT)
            p.require(payload["apiVersion"] == "catchplate.custodyServiceGenerationGrant/v1"
                and payload["serviceRole"] == role)
            p.decoded(grant["signatureBase64url"], size=64)
    if selected in (11, 12, ADOPTED_VERSION):
        from catchplate import native_pilot_helper_bootstrap_profile as helper
        helper.shape(p.canonical(value["helperBootstrap"]))
    if selected == ADOPTED_VERSION:
        publication_shape(value["publication"])
    return value


def publication_shape(value):
    """Exact adopted selection and literal signed wires, not grant admission.

    The native client independently authenticates both root signatures and
    their histories, adoption, durable key and cross-service associations.
    Keep the native 4 MiB aggregate runtime cap despite the per-grant limit.
    """
    p.fields(value, ("apiVersion", "durableGrantOriginal", "currentGrantOriginal"))
    p.require(value["apiVersion"] == "catchplate.nativePublicationServices/v2")
    for field, role in (("durableGrantOriginal", generation.ROLES[0]),
                        ("currentGrantOriginal", generation.ROLES[3])):
        signed = p.fields(_original(value[field], 3 * 1024 * 1024), ("payload", "signatureBase64url"))
        payload = p.fields(signed["payload"], ("apiVersion", "purpose", "serviceRole", "guest",
            "runtimeConfigurationSha256", "authorityHistoryManifestSha256", "admission", "native", "retrieval",
            "initialTransitionHeadSha256", "initialDurableTransitionHeadSha256", "durableAuthorityEpoch", "durablePublicKeyBase64url"))
        p.require(payload["apiVersion"] == "catchplate.nativePublicationServiceGrant/v2"
            and payload["purpose"] == "native-policy-publication-state" and payload["serviceRole"] == role
            and type(payload["admission"]) is dict and type(payload["admission"].get("adoption")) is dict)
        p.decoded(signed["signatureBase64url"], size=64)
    return value


def runtime_version(raw):
    return version(shape(raw))


def original(value):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= MAX_RUNTIME)
    raw = value.encode("ascii")
    return raw, shape(raw)


def launch_for_runtime(raw):
    selected = runtime_version(raw)
    p.require(selected >= 5)
    return "catchplate.nativeProofBridgeLaunch/v" + str(selected - 4)
