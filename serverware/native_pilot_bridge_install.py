"""Install only the approved public pre-allocation bridge runtime originals.

The closed bundle is {apiVersion,driverControlSha256,driverObservationOriginal,
runtimeOriginal,outgoingOriginal}; apiVersion is
serverware.nativePilotBridgeRuntimeBundle/v1. The complete canonical bundle and
its SHA must be independently approved. Originals are literal canonical ASCII
strings, not reconstructed configuration or pipe-observation approval.

Existing protected driver control/configuration/window/cold files are retained
and rechecked. Only the fixed runtime and outgoing-configuration destinations
are created, in that order. No private credential bytes, keys, authority history,
launch, C9 delivery or live resource are manufactured or installed. A separate
provisioner must supply the later service-owned credentials; actual C9/native
consumers still verify their contents, signatures, live resources and authority.

Publication is exclusive and one-shot. Partial files remain on failure; there is
no rollback/retry/adoption. An external supervisor must bound filesystem stalls.
"""
from __future__ import annotations

from serverware import native_pilot_delivery_authority as native_delivery
from serverware import native_pilot_bridge_runtime as bridge_runtime
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_driver_outgoing as outgoing
from serverware import native_shadow_driver_resources as resources
from serverware import native_shadow_guest_delivery as delivery
from serverware.native_shadow_proof_cohort_control import _Original

p = delivery.p
MAX_INPUT = 512 * 1024
MAX_BRIDGE_INPUT = bridge_runtime.MAX_BRIDGE_INPUT
FIELDS = ("apiVersion", "driverControlSha256", "driverObservationOriginal", "runtimeOriginal", "outgoingOriginal")
OUTGOING_FIELDS = ("apiVersion", "driverConfigurationSha256", "driverWindowSha256", "driverObservationSha256",
    "invocationId", "deliveryConfiguration", "runtime", "bridgeLaunchVersion")
RUNTIME_DESTINATION = "/etc/serverware/native-pilot-inputs/bridge-runtime.json"
PURPOSES = ("bridge-runtime", "bridge-outgoing")
_USED = False


def shape(purpose: str, raw: bytes) -> dict:
    """Closed public shape only; never a live owner or grant-admission verdict.

    PublicPublisher calls this by local import. The installer additionally
    invokes the real outgoing selector with its retained cold driver UID.
    """
    p.require(purpose in PURPOSES)
    if purpose == "bridge-outgoing":
        value = p.fields(p.document(raw, 8192), OUTGOING_FIELDS)
        p.require(value["apiVersion"] == "serverware.nativeShadowDriverOutgoingInputs/v1"
            and value["bridgeLaunchVersion"] in ("serverware.nativeProofBridgeLaunch/v5", "serverware.nativeProofBridgeLaunch/v6",
                "serverware.nativeProofBridgeLaunch/v7", "serverware.nativeProofBridgeLaunch/v8", bridge_runtime.ADOPTED_LAUNCH))
        for name in ("driverConfigurationSha256", "driverWindowSha256", "driverObservationSha256"):
            p.digest(value[name])
        delivery._pin(value["deliveryConfiguration"])
        delivery._pin(value["runtime"])
        p.require(value["runtime"]["path"] == RUNTIME_DESTINATION)
        publication._invocation(value["invocationId"])
        return value
    value = bridge_runtime.shape(raw)
    p.require(bridge_runtime.version(value) in (9, 10, 11, 12, 14)
        and value["listenerSocketPath"] == resources.LISTENER_PATH)
    p.integer(value["startupTimeoutMillis"], maximum=30000)
    generation = p.fields(value["generationAdmission"], ("apiVersion", "grants"))
    p.require(generation["apiVersion"] == "serverware.custodyGenerationServices/v1")
    for digest in p.fields(generation["grants"], driver.ROLES).values():
        p.digest(digest)
    commitment = p.fields(value["commitRequest"], ("apiVersion", "serviceGrantOriginals"))
    p.require(commitment["apiVersion"] == "serverware.nativeCommitRequestServices/v1")
    grants = p.fields(commitment["serviceGrantOriginals"], ("durable-recovery-store", "current-signature-authority"))
    for original in grants.values():
        scope._original(original, 65536)
    spool = p.fields(value["spool"], ("apiVersion", "headGrantOriginal", "currentGrantOriginal", "originFdName", "cleanupGrantOriginal"))
    p.require(spool["apiVersion"] == "serverware.nativeSpoolServices/v3" and spool["originFdName"] == "generation-origin")
    for name in ("headGrantOriginal", "currentGrantOriginal", "cleanupGrantOriginal"):
        scope._original(spool[name], 131072 if bridge_runtime.version(value) in bridge_runtime.LARGE_VERSIONS and name != "headGrantOriginal" else 65536)
    histories = value["histories"]
    p.require(type(histories) is list and len(histories) == 5)
    roles = []
    for row in histories:
        p.fields(row, ("serviceRole", "manifestCredential", "manifestSha256", "rootKeyId", "rootKeySpkiSha256"))
        p.require(row["serviceRole"] in driver.ROLES)
        roles.append(row["serviceRole"])
        name = row["manifestCredential"]
        p.require(type(name) is str and name.isascii() and 1 <= len(name) <= 128
            and all(character.isalnum() or character in "-_." for character in name))
        for name in ("manifestSha256", "rootKeyId", "rootKeySpkiSha256"):
            p.digest(row[name])
    p.require(len(set(roles)) == 5)
    # History/key credentials are names and public pins only. Their independently
    # provisioned service-owned originals remain the later C9 loader's inputs.
    return value


def install(bundle_original: bytes, *, expected_sha256: str) -> dict:
    """Return installed public pins; never acknowledge launch or readiness."""
    global _USED
    p.require(not _USED)
    _USED = True
    p.require(type(bundle_original) is bytes and 0 < len(bundle_original) <= MAX_BRIDGE_INPUT
        and p.sha(bundle_original) == p.digest(expected_sha256))
    value = p.fields(p.document(bundle_original, MAX_BRIDGE_INPUT), FIELDS)
    adopted = value["apiVersion"] == "serverware.nativePilotBridgeRuntimeBundle/v2"
    p.require(adopted or value["apiVersion"] == "serverware.nativePilotBridgeRuntimeBundle/v1")
    held, publisher = [], None

    def retain(path, maximum, digest):
        original = _Original(path, maximum, digest)
        held.append(original)
        return original.raw

    try:
        control_raw = retain(driver.CONTROL, 4096, p.digest(value["driverControlSha256"]))
        control = p.fields(p.document(control_raw, 4096),
            ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
        p.require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
        p.digest(control["supervisorExecutableSha256"])
        config_raw = retain(driver.CONFIGURATION, 65536, p.digest(control["configurationSha256"]))
        window_raw = retain(driver.WINDOW, 32768, p.digest(control["windowSha256"]))
        observation_raw, _ = scope._original(value["driverObservationOriginal"], 65536)
        config, window = precreation._driver(config_raw, window_raw, observation_raw)
        cold_pin = config["deliveryConfiguration"]
        cold_raw = retain(cold_pin["path"], 65536, cold_pin["sha256"])
        cold = delivery.configuration(cold_raw, cold_pin["sha256"])
        scope._same([cold["uid"], cold["gid"]], [config["uid"], config["gid"]])
        runtime_raw, _ = bridge_runtime.original(value["runtimeOriginal"])
        outgoing_raw, _ = scope._original(value["outgoingOriginal"], 8192)
        runtime = shape("bridge-runtime", runtime_raw)
        p.require(adopted == (bridge_runtime.version(runtime) == 14)
            and (bridge_runtime.version(runtime) in bridge_runtime.LARGE_VERSIONS or len(bundle_original) <= MAX_INPUT))
        selected = shape("bridge-outgoing", outgoing_raw)
        scope._same(selected, {"apiVersion": "serverware.nativeShadowDriverOutgoingInputs/v1",
            "driverConfigurationSha256": p.sha(config_raw), "driverWindowSha256": p.sha(window_raw),
            "driverObservationSha256": p.sha(observation_raw), "invocationId": window["invocationId"],
            "deliveryConfiguration": cold_pin, "runtime": {"path": RUNTIME_DESTINATION, "sha256": p.sha(runtime_raw)},
            "bridgeLaunchVersion": bridge_runtime.launch_for_runtime(runtime_raw)})
        outgoing._selection(runtime_raw, selected["bridgeLaunchVersion"], cold["uid"])
        outgoing._peer(runtime["expectedFacadePeer"], cold["uid"])
        p.require(publication.DESTINATIONS["bridge-runtime"] == RUNTIME_DESTINATION
            and publication.DESTINATIONS["bridge-outgoing"] == outgoing.CONFIGURATION
            and publication.LIMITS["bridge-runtime"] == bridge_runtime.MAX_RUNTIME and publication.LIMITS["bridge-outgoing"] == 8192)

        def check(previous=0):
            for original in held:
                original.check()
            return native_delivery._live(window, previous)

        previous = check()
        publisher = publication.PublicPublisher.open()
        publisher.require_absent(PURPOSES)
        pins = {}
        for purpose, raw in zip(PURPOSES, (runtime_raw, outgoing_raw), strict=True):
            previous = check(previous)
            pins[purpose] = publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
            previous = check(previous)
        publisher.check()
        check(previous)
        return {"apiVersion": "serverware.nativePilotBridgeRuntimeInstallation/v" + ("2" if adopted else "1"), "bundleSha256": expected_sha256,
            "configurationSha256": p.sha(config_raw), "windowSha256": p.sha(window_raw),
            "observationSha256": p.sha(observation_raw), "invocationId": window["invocationId"],
            "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"], "pins": pins}
    finally:
        if publisher is not None:
            publisher.close()  # Descriptors only; complete/partial files remain.
        for original in reversed(held):
            original.close()
