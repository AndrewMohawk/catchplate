"""Fixed publication slots for existing pilot authority wire originals.

These are closed file destinations and bounded shape checks, not approval or
signature/resource verification. Purpose-specific producers and receiving live
owners retain those duties. No operator-supplied destination or role is added.
"""
from __future__ import annotations

from serverware import custody_generation_grants as generation
from serverware import custody_spool_inputs as spool
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_proof_cohort_assignment as cohort

_ROOT = "/etc/serverware/native-pilot-inputs/"
_NATIVE_OPERATIONS = ("ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "retrieval", "commitRequest", "persistence", "trustedTime")
_LAUNCH_INPUTS = {"trust": 1024 * 1024, "time-bootstrap": 65536, "assignment": 4 * 1024 * 1024,
    "closure": 1024 * 1024, "keys": 65536, "encrypted-keys": 65536, "admission": 65536, "verifier": 32768}
# family, exact role (if encoded by that wire), maximum original bytes
PROFILES = {
    "driver-bootstrap-configuration": ("driver-bootstrap-input", None, 65536),
    "driver-bootstrap-window": ("driver-bootstrap-input", None, 32768),
    "driver-bootstrap-control": ("driver-bootstrap-input", None, 4096),
    "cohort-configuration": ("cohort-config", None, 32768),
    "cohort-control": ("cohort-control", None, 4096),
    "ordinary-launch": ("ordinary-launch", None, 65536),
    "bridge-runtime": ("bridge-runtime", None, 65536),
    "bridge-outgoing": ("bridge-outgoing", None, 8192),
    "endpoint-peer": ("endpoint-input", "peer", 4096),
    "endpoint-proof-scope": ("endpoint-input", "proof-scope", 16384),
    "endpoint-retrieval-manifest": ("endpoint-input", "retrieval-manifest", 32768),
    "endpoint-assignment": ("endpoint-input", "assignment", 4 * 1024 * 1024),
    "native-generation-install-grant": ("generation-install", None, 4 * 1024 * 1024),
    **{"native-service-" + operation: ("native-service", operation,
        4 * 1024 * 1024 if operation in _NATIVE_OPERATIONS[:6] + ("commitRequest",) else 65536)
       for operation in _NATIVE_OPERATIONS},
    **{"native-launch-" + role: ("native-launch", role, 32768)
       for role in cohort.ENDPOINT_ROLES + ("bridge",)},
    **{"native-runtime-" + role: ("native-runtime", role, 65536)
       for role in cohort.ENDPOINT_ROLES},
    **{"native-" + role + "-" + suffix: ("native-launch-input", role, maximum)
       for role in cohort.ENDPOINT_ROLES + ("bridge",) for suffix, maximum in _LAUNCH_INPUTS.items()},
    **{"native-cold-" + role: ("native-cold", role, 65536)
       for role in cohort.ENDPOINT_ROLES},
    **{"ordinary-cold-" + role: ("ordinary-cold", role, 65536)
       for role in generation.ROLES},
    "driver-bootstrap-admission": ("bootstrap", None, 8192),
    "driver-constructed-admission": ("constructed", None, 16384),
    **{"native-delivery-" + role: ("native-delivery", role, 65536)
       for role in cohort.ENDPOINT_ROLES + ("bridge",)},
    **{"ordinary-delivery-" + role: ("ordinary-delivery", role, 65536)
       for role in generation.ROLES},
    **{"ordinary-initial-history-" + role: ("ordinary-initial-history", role, generation.MAX_BYTES)
       for role in generation.ROLES},
    **{"ordinary-generation-" + role: ("generation", role, 65536)
       for role in generation.ROLES},
    **{"ordinary-dispatch-" + role: ("dispatch", role, 65536)
       for role in commitment.ROLES},
    "ordinary-head": ("head", generation.ROLES[0], 65536),
    "ordinary-cleanup": ("cleanup", generation.ROLES[1], 131072),
    "ordinary-current": ("current", generation.ROLES[3], 131072),
}
DESTINATIONS = {purpose: _ROOT + purpose + ".json" for purpose in PROFILES}
DESTINATIONS.update({
    "driver-bootstrap-configuration": "/etc/serverware/native-shadow-driver-bootstrap.json",
    "driver-bootstrap-window": "/etc/serverware/native-shadow-driver-bootstrap-window.json",
    "driver-bootstrap-control": "/etc/serverware/native-shadow-driver-bootstrap-control.json",
    "cohort-configuration": "/etc/serverware/native-shadow-proof-cohort.json",
    "cohort-control": "/etc/serverware/native-shadow-proof-cohort-control.json",
    "ordinary-launch": "/etc/serverware/custody-effects-five.json",
    "bridge-outgoing": "/etc/serverware/native-shadow-driver-outgoing.json",
})


def _configuration(family, role, raw, maximum):
    if family == "native-cold":
        delivery.configuration(raw, p.sha(raw))
        return
    if family == "ordinary-cold":
        generation.configuration(raw, p.sha(raw), role)
        return
    if family == "cohort-config":
        value = cohort.configuration(raw)
        p.require(cohort.endpoint_driver_selected(value))
        for endpoint in cohort.ENDPOINT_ROLES:
            pin = value[endpoint + "Configuration"]
            delivery._pin(pin)
            p.require(pin["path"] == DESTINATIONS["native-cold-" + endpoint])
        return
    value = p.document(raw, maximum)
    if family == "cohort-control":
        p.fields(value, ("apiVersion", "cohortExecutableSha256", "configurationSha256", "precreationSha256"))
        p.require(value["apiVersion"] == "serverware.nativeShadowProofCohortControl/v1")
        for field in ("cohortExecutableSha256", "configurationSha256", "precreationSha256"):
            p.digest(value[field])
        return
    p.require(family == "ordinary-launch")
    p.fields(value, ("apiVersion", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
        "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
    p.require(value["apiVersion"] == "serverware.custodyFiveServiceLaunch/v6")
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    for name in ("timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(value[name], maximum=p.MAX_U64)
    cohort._invocation(value["invocationId"])
    p.require(p.ns(value["startupDeadlineBoottimeNs"]) <= p.ns(value["lifetimeDeadlineBoottimeNs"]))
    for service, row in p.fields(value["services"], generation.ROLES).items():
        p.fields(row, ("executableSha256", "deliveryConfiguration"))
        p.digest(row["executableSha256"])
        delivery._pin(row["deliveryConfiguration"])
        p.require(row["deliveryConfiguration"]["path"] == DESTINATIONS["ordinary-cold-" + service])


def _signed(raw, maximum, *, native=False, constructed=False, c9=False):
    # Ordinary grants retain their existing integral-u64 canonical codec.
    value = generation.document(raw, maximum) if not native else p.document(raw, maximum)
    signature = "signature" if native else "signatureBase64url"
    fields = ("payload", signature)
    if constructed:
        fields += ("bootstrapAdmissionOriginal",)
    if c9:
        fields += ("apiVersion",)
    p.fields(value, fields)
    p.decoded(value[signature], size=64)
    p.require(type(value["payload"]) is dict)
    return value


def _driver(family, raw, maximum):
    # Reuse the producer's closed payload field inventory, not its signer.
    from serverware import native_pilot_driver_authority as driver
    constructed = family == "constructed"
    signed = _signed(raw, maximum, native=True, constructed=constructed)
    value = p.fields(signed["payload"], driver.CONSTRUCTED_FIELDS if constructed else driver.BOOTSTRAP_FIELDS)
    api, purpose = (("serverware.nativeShadowConstructedDriverAdmission/v1", "constructed-native-driver-admission")
                    if constructed else ("serverware.nativeShadowBootstrapDriverAdmission/v1", "native-driver-bootstrap-admission"))
    p.require(value["apiVersion"] == api and value["purpose"] == purpose)
    for field in ("configurationSha256", "windowSha256", "signingKeySpkiSha256"):
        p.digest(value[field])
    p.require(p.ns(value["startupDeadlineBoottimeNs"]) <= p.ns(value["lifetimeDeadlineBoottimeNs"]))
    if constructed:
        early = signed["bootstrapAdmissionOriginal"]
        p.require(type(early) is str and early.isascii())
        original = early.encode("ascii")
        _driver("bootstrap", original, 8192)
        p.require(value["bootstrapAdmissionSha256"] == p.sha(original))
    else:
        observed = value["bootstrapObservationOriginal"]
        p.require(type(observed) is str and observed.isascii())
        p.document(observed.encode("ascii"), 65536)


def _initial_history(role, raw, maximum):
    """Initial-only grammar and commitments, without a selected trust anchor.

    Public keys/signature encodings are checked, not authorized here. Only the
    separately approved producer and actual pinned receiver authenticate them;
    a wrapper-provided root must never become this publisher's approval.
    """
    from serverware import native_pilot_ordinary_initial_authority as ceremony
    from serverware import native_pilot_ordinary_initial_profile as initial
    from serverware import native_pilot_ordinary_key_authority as authority
    from serverware import native_pilot_ordinary_key_profile as key

    value = p.fields(generation.document(raw, maximum), initial.WRAPPER_FIELDS)
    p.require(value["apiVersion"] == initial.WRAPPER_API)
    state = initial.validate_state(value["initialState"])
    p.require(state["serviceRole"] == role)
    history = p.fields(value["history"], generation.HISTORY)
    expected_role = {"authorityKind": "isolated-service", "role": role}
    p.require(history["apiVersion"] == authority.HISTORY_API
        and history["authorityRole"] == expected_role)
    for field in ("adjacentTransitions", "compactionAnchors", "replayTombstones"):
        p.require(type(history[field]) is list and history[field] == [])
    anchor = p.fields(history["firstRetainedEpoch"], authority.ANCHOR_FIELDS)
    epoch = p.fields(anchor["retainedEpoch"], authority.EPOCH_FIELDS)
    identity = key.validate_identity(epoch["endpointProcessIdentity"])
    p.require(identity["identitySha256"] == state["endpointProcessIdentitySha256"]
        and (role != generation.ROLES[0] or identity["endpointRole"] == "settlement-store"))
    for item in state["directories"].values():
        p.require((item["identity"]["uid"], item["identity"]["gid"])
            == (identity["endpointUid"], identity["endpointGid"]))
    authorities = {"root": history["rootAuthority"], "checkpoint": epoch["checkpointAuthority"],
        "service": epoch["serviceSigningKey"]}
    public = [authority._key(authorities[name]) for name in ceremony.KEY_NAMES]
    p.require(len({item["keyId"] for item in authorities.values()}) == 3
        and len({item["keySpkiSha256"] for item in authorities.values()}) == 3
        and len({authority._raw_key(item) for item in public}) == 3)
    checkpoint = key.validate_checkpoint(value["initialCheckpoint"])
    payload = checkpoint["payload"]
    ceremony._initial_payload(state, payload, authorities)
    p.require(checkpoint["authorityKeyId"] == authorities["checkpoint"]["keyId"]
        and checkpoint["authorityKeySpkiSha256"] == authorities["checkpoint"]["keySpkiSha256"]
        and payload["endpointRole"] == identity["endpointRole"]
        and payload["validFromBoottime"]["domain"] == payload["validUntilBoottime"]["domain"] == key._boot(state))
    expected, anchor_raw, _ = ceremony._anchor(state, identity, authorities, checkpoint)
    p.require(generation.canonical({name: anchor[name] for name in authority.ANCHOR_FIELDS[:7]})
        == generation.canonical(expected))
    for field in ceremony.ANCHOR_SIGNATURE_FIELDS:
        p.decoded(anchor[field], size=64)
    p.require(p.digest(anchor["retainedAnchorSha256"]) == p.framed(authority.ANCHOR_DIGEST_DOMAIN,
        (anchor_raw, *(anchor[name].encode("ascii") for name in ceremony.ANCHOR_SIGNATURE_FIELDS))))
    authority._retention(history["retention"], epoch)
    retention = history["retention"]
    p.require(retention["oldestReplayableRecordSequence"] == retention["currentRecordSequence"] == 0)
    for field in ("maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones"):
        p.require(retention[field] == 1)
    p.require(p.digest(history["manifestSha256"]) == p.framed(authority.HISTORY_DOMAIN,
        (generation.canonical([history[name] for name in generation.HISTORY[:-1]]),)))


def shape(purpose, raw):
    """Validate the selected public envelope, never authenticate its authority."""
    p.require(type(purpose) is str and purpose in PROFILES)
    family, role, maximum = PROFILES[purpose]
    if family == "ordinary-initial-history":
        _initial_history(role, raw, maximum)
        return
    if family == "endpoint-input":
        from serverware import native_pilot_assignment as assignments
        from serverware import native_shadow_retrieval_artifacts as retrieval
        p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
        if role == "peer":
            retrieval._peer(raw)
        elif role == "proof-scope":
            p.require(retrieval.scope_original(raw).get("api_version") == retrieval.SCOPE_SET_API)
        elif role == "retrieval-manifest":
            p.require(retrieval.manifest_initialization(raw, p.sha(raw)) == retrieval.FRESH_INITIALIZATION)
        else:
            p.require(role == "assignment")
            value = assignments.shape(p.document(raw, maximum))
            p.require(assignments.version(value) == 2)
        return
    if family == "driver-bootstrap-input":
        from serverware import native_pilot_bootstrap_install as bootstrap_install
        bootstrap_install.shape(purpose, raw)
        return
    if family in ("native-launch", "native-runtime", "native-launch-input"):
        from serverware import native_pilot_launch_publication as launch
        launch.shape(purpose, raw)
        return
    if family == "native-service":
        from serverware import native_pilot_native_service_authority as authority
        signed = authority.grant_original(role, raw)
        p.decoded(signed["signature"], size=64)
        value = signed["payload"]
        p.guest(value["guest"])
        for field in ("assignmentPayloadSha256", "keyAuthorizationSha256", "signingKeyId", "signingKeySpkiSha256"):
            p.digest(value[field])
        return
    if family in ("bridge-runtime", "bridge-outgoing"):
        from serverware import native_pilot_bridge_install as bridge_install
        bridge_install.shape(purpose, raw)
        return
    if family == "generation-install":
        from serverware import native_pilot_generation_install_authority as installation
        signed = installation.grant_original(raw)
        p.decoded(signed["signature"], size=64)
        value = signed["payload"]
        p.guest(value["guest"])
        p.require(value["guest"]["serviceRole"] == "production-bridge")
        p.fields(value["services"], generation.ROLES)
        p.fields(value["keyHistory"], ("currentKeyEpoch", "predecessors"))
        p.fields(value["journal"], ("genesisSha256", "sequence", "headSha256"))
        for field in ("assignmentPayloadSha256", "keyAuthorizationSha256", "signingKeyId", "signingKeySpkiSha256"):
            p.digest(value[field])
        return
    if family in ("native-cold", "ordinary-cold", "cohort-config", "cohort-control", "ordinary-launch"):
        _configuration(family, role, raw, maximum)
        return
    if family in ("bootstrap", "constructed"):
        _driver(family, raw, maximum)
        return
    c9 = family in ("native-delivery", "ordinary-delivery")
    signed = _signed(raw, maximum, c9=c9)
    value = signed["payload"]
    if c9:
        p.fields(value, delivery.FIELDS)
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
            and value["serviceRole"] == ("production-bridge" if family == "native-delivery" else role))
        p.digest(value["configurationSha256"])
        p.digest(value["authorityKeyId"])
        delivery._pin(value["runtimeConfig"])
        p.require(type(value["credentials"]) is list and 1 <= len(value["credentials"]) <= 64
            and type(value["activation"]) is list and 1 <= len(value["activation"]) <= 64)
        return
    if family == "generation":
        p.fields(value, generation.GRANT)
        p.require(value["apiVersion"] == "serverware.custodyServiceGenerationGrant/v1"
            and value["purpose"] == "cold-service-generation-admission" and value["serviceRole"] == role)
    elif family == "dispatch":
        p.fields(value, commitment.SERVICE_FIELDS)
        p.require(value["apiVersion"] == "serverware.custodyCommitRequestServiceGrant/v1"
            and value["purpose"] == "commit-request-service-transition" and value["serviceRole"] == role)
    else:
        p.fields(value, spool.HEAD + ("completion", "effects") if family == "head" else spool.CURRENT)
        api, purpose_name = {
            "head": ("serverware.nativeSpoolHeadGrant/v3", "native-shared-spool-head"),
            "cleanup": ("serverware.nativeActiveEffectCleanupGrant/v1", "native-active-effect-cleanup"),
            "current": ("serverware.nativeSpoolCurrentGrant/v3", "native-spool-current-signature"),
        }[family]
        p.require(value["apiVersion"] == api and value["purpose"] == purpose_name)
    p.guest(value["guest"])
    p.require(value["guest"]["serviceRole"] == role)
    p.digest(value["runtimeConfigurationSha256"])
    p.digest(value["authorityHistoryManifestSha256"])
