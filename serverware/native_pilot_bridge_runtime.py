"""Closed public bridge runtime versions and bounds; never runtime admission.

The explicit v10 carries actual ordinary runtime/generation originals for the
native initial-history adapter. Shape checks do not authenticate their roots,
signatures, process identities, credentials or successful service startup.
"""
from __future__ import annotations

from serverware import custody_generation_grants as generation

p = generation.p
MAX_LEGACY_RUNTIME = 65536
MAX_RUNTIME = 4 * 1024 * 1024
MAX_BRIDGE_INPUT = 16 * 1024 * 1024
PREFIX = "serverware.policyCustodyProductionRpcRuntime/v"
LAUNCH_RUNTIME = {"serverware.nativeProofBridgeLaunch/v" + str(version): version + 4
    for version in range(1, 7)}
BASE_FIELDS = ("apiVersion", "startupTimeoutMillis", "listenerSocketPath", "expectedFacadePeer",
    "journalDirectoryIdentity", "expectedHelperEndpointRoles", "expectedDriverProcessIdentitySha256",
    "expectedDriverConfigurationGenerationSha256", "expectedOperationGeneration", "expectedSharedConfigurationSha256",
    "expectedServiceConfigurationSha256", "expectedServiceSigningCredentialSha256", "expectedServiceRestartEpoch",
    "expectedServiceReadinessEpoch", "expectedServiceAuthorityHistoryManifestSha256",
    "expectedProductionDispatchProtocolSetSha256", "expectedMaximumDurabilityWorkerNanos", "serviceSessions",
    "histories", "parentSignerEndpoints", "proofEndpoints")


def version(value):
    p.require(type(value) is dict)
    selected = {PREFIX + str(number): number for number in range(4, 11)}.get(value.get("apiVersion"))
    p.require(selected is not None)
    return selected


def maximum_for_version(number):
    p.require(type(number) is int and 4 <= number <= 10)
    return MAX_RUNTIME if number == 10 else MAX_LEGACY_RUNTIME


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
    if selected != 10:
        p.require(len(raw) <= MAX_LEGACY_RUNTIME)
    extra = (() if selected == 4 else ("generationAdmission",))
    if selected >= 6:
        extra += ("commitRequest",)
    if selected >= 7:
        extra += ("spool",)
    if selected == 10:
        extra += ("ordinaryInitialHistories",)
    p.fields(value, BASE_FIELDS + extra)
    p.integer(value["startupTimeoutMillis"], maximum=30000)
    for field in extra:
        p.require(type(value[field]) is dict)
    if selected >= 5:
        row = p.fields(value["generationAdmission"], ("apiVersion", "grants"))
        p.require(row["apiVersion"] == "serverware.custodyGenerationServices/v1")
        for digest in p.fields(row["grants"], generation.ROLES).values():
            p.digest(digest)
    if selected >= 6:
        row = p.fields(value["commitRequest"], ("apiVersion", "serviceGrantOriginals"))
        p.require(row["apiVersion"] == "serverware.nativeCommitRequestServices/v1")
        for original in p.fields(row["serviceGrantOriginals"],
                ("durable-recovery-store", "current-signature-authority")).values():
            _original(original, 65536)
    if selected >= 7:
        effect = selected >= 9
        row = p.fields(value["spool"], ("apiVersion", "headGrantOriginal", "currentGrantOriginal", "originFdName")
            + (("cleanupGrantOriginal",) if effect else ()))
        p.require(row["apiVersion"] == "serverware.nativeSpoolServices/v" + str(3 if effect else selected - 6)
            and row["originFdName"] == "generation-origin")
        _original(row["headGrantOriginal"], 65536)
        for field in ("currentGrantOriginal",) + (("cleanupGrantOriginal",) if effect else ()):
            _original(row[field], 131072 if selected == 10 else 65536)
    if selected == 10:
        for role, row in p.fields(value["ordinaryInitialHistories"], generation.ROLES).items():
            p.fields(row, ("runtimeOriginal", "generationGrantOriginal"))
            runtime = _original(row["runtimeOriginal"], generation.MAX_BYTES)
            p.require(type(runtime.get("runtime")) is dict)
            grant = p.fields(_original(row["generationGrantOriginal"], 65536), ("payload", "signatureBase64url"))
            payload = p.fields(grant["payload"], generation.GRANT)
            p.require(payload["apiVersion"] == "serverware.custodyServiceGenerationGrant/v1"
                and payload["serviceRole"] == role)
            p.decoded(grant["signatureBase64url"], size=64)
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
    return "serverware.nativeProofBridgeLaunch/v" + str(selected - 4)
