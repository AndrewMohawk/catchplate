"""Closed fixed-child input authoring; no process or readiness authority.

These functions sign explicitly approved data using an already provisioned C9
delivery key. Actual kernel originals and descriptor transfer remain owned by
the Rust cohort parent and the operator's retained activation owners.
"""
from __future__ import annotations

import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from serverware import native_shadow_guest_delivery as delivery

p = delivery.p
PRECREATE_DOMAIN = b"serverware.nativeShadowProofCohortPrecreation.signature/v1\0"
RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v1\0"
SIX_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v2\0"
SEVEN_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v3\0"
EIGHT_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v4\0"
ELEVEN_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v5\0"
ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "bridge")
SIX_ROLES = ROLES + ("commitRequest",)
SEVEN_ROLES = SIX_ROLES + ("ingressAdmission",)
EIGHT_ROLES = SEVEN_ROLES + ("terminalAppend",)
EFFECT_ROLES = ("dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
ELEVEN_ROLES = EIGHT_ROLES + EFFECT_ROLES
ENDPOINT_ROLES = tuple(role for role in ELEVEN_ROLES if role != "bridge")
COLD_NAMES = tuple(role + "Configuration" for role in ROLES)
CONFIG_FIELDS = ("apiVersion", "authority", "executableSha256") + COLD_NAMES
WINDOW_FIELDS = ("configurationSha256", "authorityKeyId", "bootIdBase64url", "timeNamespaceDevice",
                 "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs",
                 "lifetimeDeadlineBoottimeNs", "invocationId")
RELEASE_FIELDS = ("apiVersion", "configurationSha256", "precreationSha256", "observationSha256",
                  "invocationId") + ROLES + ("signingKeyId",)
ORIGINAL_FIELDS = ("apiVersion", "configurationSha256", "precreationSha256", "invocationId") + ROLES
MAX_BYTES = 32768


def configuration(raw):
    """Closed source selection; v1 never admits cleanup fields or messages."""
    value = p.document(raw, MAX_BYTES)
    if value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v1":
        return p.fields(value, CONFIG_FIELDS)
    if value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v2":
        p.fields(value, CONFIG_FIELDS + ("cleanup",))
    elif value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v3":
        p.fields(value, CONFIG_FIELDS + ("cleanup", "commitRequestConfiguration"))
    elif value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v4":
        p.fields(value, CONFIG_FIELDS + ("cleanup", "commitRequestConfiguration", "ingressAdmissionConfiguration"))
    elif value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v5":
        p.fields(value, CONFIG_FIELDS + ("cleanup", "commitRequestConfiguration", "ingressAdmissionConfiguration", "terminalAppendConfiguration"))
    elif value.get("apiVersion") == "serverware.nativeShadowProofCohortConfiguration/v7":
        p.fields(value, ("apiVersion", "authority", "executableSha256", "cleanup", "externalDriver")
            + tuple(role + "Configuration" for role in ENDPOINT_ROLES))
        from serverware.native_shadow_endpoint_driver import configuration as external_configuration
        external_configuration(value["externalDriver"])
    else:
        p.fields(value, CONFIG_FIELDS + ("cleanup", "commitRequestConfiguration", "ingressAdmissionConfiguration", "terminalAppendConfiguration")
            + tuple(role + "Configuration" for role in EFFECT_ROLES))
        p.require(value["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v6")
    from serverware import native_shadow_proof_cohort_cleanup as cleanup
    cleanup.configuration(value)
    return value


def roles(config):
    """Only source-fixed inventories; never a supplied endpoint list."""
    p.require(config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v1",
        "serverware.nativeShadowProofCohortConfiguration/v2", "serverware.nativeShadowProofCohortConfiguration/v3",
        "serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5",
        "serverware.nativeShadowProofCohortConfiguration/v6", "serverware.nativeShadowProofCohortConfiguration/v7"))
    if endpoint_driver_selected(config):
        return ENDPOINT_ROLES
    if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v6":
        return ELEVEN_ROLES
    if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v5":
        return EIGHT_ROLES
    if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v4":
        return SEVEN_ROLES
    return SIX_ROLES if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v3" else ROLES


def originals_fields(config):
    return ("apiVersion", "configurationSha256", "precreationSha256", "invocationId") + roles(config) + (
        ("externalDriver",) if endpoint_driver_selected(config) else ())


def release_fields(config):
    return ("apiVersion", "configurationSha256", "precreationSha256", "observationSha256", "invocationId") + roles(config) + ("signingKeyId",) + (
        ("externalDriverSha256",) if endpoint_driver_selected(config) else ())


def endpoint_driver_selected(config):
    return config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v7"


def external_driver_sha256(config, observed):
    from serverware.native_shadow_endpoint_driver import original
    p.require(endpoint_driver_selected(config))
    return p.sha(p.canonical(original(observed["externalDriver"], config["externalDriver"])))


def originals_api(config):
    if endpoint_driver_selected(config):
        return "serverware.nativeShadowProofCohortOriginals/v6"
    if roles(config) == ELEVEN_ROLES:
        return "serverware.nativeShadowProofCohortOriginals/v5"
    if roles(config) == EIGHT_ROLES:
        return "serverware.nativeShadowProofCohortOriginals/v4"
    if roles(config) == SEVEN_ROLES:
        return "serverware.nativeShadowProofCohortOriginals/v3"
    return "serverware.nativeShadowProofCohortOriginals/v2" if roles(config) == SIX_ROLES else "serverware.nativeShadowProofCohortOriginals/v1"


def release_api(config):
    if endpoint_driver_selected(config):
        return "serverware.nativeShadowProofCohortRelease/v6"
    if roles(config) == ELEVEN_ROLES:
        return "serverware.nativeShadowProofCohortRelease/v5"
    if roles(config) == EIGHT_ROLES:
        return "serverware.nativeShadowProofCohortRelease/v4"
    if roles(config) == SEVEN_ROLES:
        return "serverware.nativeShadowProofCohortRelease/v3"
    return "serverware.nativeShadowProofCohortRelease/v2" if roles(config) == SIX_ROLES else "serverware.nativeShadowProofCohortRelease/v1"


def release_domain(config):
    if endpoint_driver_selected(config):
        return b"serverware.nativeShadowProofCohortRelease.signature/v6\0"
    if roles(config) == ELEVEN_ROLES:
        return ELEVEN_RELEASE_DOMAIN
    if roles(config) == EIGHT_ROLES:
        return EIGHT_RELEASE_DOMAIN
    if roles(config) == SEVEN_ROLES:
        return SEVEN_RELEASE_DOMAIN
    return SIX_RELEASE_DOMAIN if roles(config) == SIX_ROLES else RELEASE_DOMAIN


def _invocation(value):
    p.require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) and value != "0" * 32)


def _key(signing_key, authority):
    p.fields(authority, ("publicKeyBase64url", "keyId"))
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    raw = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(raw != bytes(32) and p.encoded(raw) == authority["publicKeyBase64url"]
              and authority["keyId"] == p.sha(raw))


def _configuration_public(raw, expected_sha256, originals, commit_request_original, ingress_admission_original,
                   terminal_append_original, dispatch_barrier_original, active_effect_barrier_original, active_effect_commit_original):
    config = configuration(raw)
    p.require(p.sha(raw) == p.digest(expected_sha256))
    p.digest(config["executableSha256"])
    authority = p.fields(config["authority"], ("publicKeyBase64url", "keyId"))
    public = p.decoded(authority["publicKeyBase64url"], size=32)
    p.require(public != bytes(32) and authority["keyId"] == p.sha(public))
    Ed25519PublicKey.from_public_bytes(public)
    selected = roles(config)
    if endpoint_driver_selected(config):
        p.require(originals[-1] is None)  # the measured driver is not a parked child
        originals = originals[:-1]
    p.require((commit_request_original is not None) == (selected in (SIX_ROLES, SEVEN_ROLES, EIGHT_ROLES, ELEVEN_ROLES, ENDPOINT_ROLES)))
    p.require((ingress_admission_original is not None) == (selected in (SEVEN_ROLES, EIGHT_ROLES, ELEVEN_ROLES, ENDPOINT_ROLES)))
    p.require((terminal_append_original is not None) == (selected in (EIGHT_ROLES, ELEVEN_ROLES, ENDPOINT_ROLES)))
    if commit_request_original is not None:
        originals += (commit_request_original,)
    if ingress_admission_original is not None:
        originals += (ingress_admission_original,)
    if terminal_append_original is not None:
        originals += (terminal_append_original,)
    for original in (dispatch_barrier_original, active_effect_barrier_original, active_effect_commit_original):
        p.require((original is not None) == (selected in (ELEVEN_ROLES, ENDPOINT_ROLES)))
        if original is not None:
            originals += (original,)
    cold_names = tuple(role + "Configuration" for role in selected)
    cold = []
    for name, original in zip(cold_names, originals, strict=True):
        delivery._pin(config[name])
        value = delivery.configuration(original, config[name]["sha256"])
        p.require(value["authority"] == config["authority"])
        cold.append(value)
    p.require(len(cold) == len(selected) and len({v["uid"] for v in cold}) == len(selected)
        and len({v["gid"] for v in cold}) == len(selected)
        and len({config[name]["path"] for name in cold_names}) == len(selected))
    return config


def _configuration(raw, expected_sha256, originals, signing_key, commit_request_original, ingress_admission_original,
                   terminal_append_original, dispatch_barrier_original, active_effect_barrier_original, active_effect_commit_original):
    config = _configuration_public(raw, expected_sha256, originals, commit_request_original,
        ingress_admission_original, terminal_append_original, dispatch_barrier_original,
        active_effect_barrier_original, active_effect_commit_original)
    _key(signing_key, config["authority"])
    return config


def _window(value, config, configuration_sha256, boot, now):
    p.fields(value, WINDOW_FIELDS)
    p.require(value["configurationSha256"] == configuration_sha256
              and value["authorityKeyId"] == config["authority"]["keyId"])
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    p.integer(value["timeNamespaceDevice"], maximum=(1 << 64) - 1)
    p.integer(value["timeNamespaceInode"], maximum=(1 << 64) - 1)
    p.integer(now, maximum=(1 << 64) - 1)
    p.require((value["bootIdBase64url"], value["timeNamespaceDevice"], value["timeNamespaceInode"]) == boot)
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= now < startup <= lifetime and startup - issued <= 30_000_000_000
              and now + 250_000_000 < lifetime)
    _invocation(value["invocationId"])


def _signed(signing_key, domain, payload):
    raw = p.canonical(payload)
    signature = signing_key.sign(domain + raw)
    signing_key.public_key().verify(signature, domain + raw)
    return p.encoded(signature)


def sign_precreation(*, configuration_raw, configuration_sha256, retrieval_configuration_raw,
                     persistence_configuration_raw, trusted_time_configuration_raw, generation_install_configuration_raw,
                     bridge_configuration_raw, payload_raw, boot, now, signing_key,
                     commit_request_configuration_raw=None, ingress_admission_configuration_raw=None, terminal_append_configuration_raw=None,
                     dispatch_barrier_configuration_raw=None, active_effect_barrier_configuration_raw=None, active_effect_commit_configuration_raw=None):
    """Authorize only bounded cohort resource preparation, not any service."""
    config = _configuration(configuration_raw, configuration_sha256,
        (retrieval_configuration_raw, persistence_configuration_raw, trusted_time_configuration_raw,
         generation_install_configuration_raw, bridge_configuration_raw), signing_key, commit_request_configuration_raw,
         ingress_admission_configuration_raw, terminal_append_configuration_raw, dispatch_barrier_configuration_raw,
         active_effect_barrier_configuration_raw, active_effect_commit_configuration_raw)
    payload = p.document(payload_raw, MAX_BYTES)
    _window(payload, config, configuration_sha256, boot, now)
    result = p.canonical({"apiVersion": "serverware.nativeShadowProofCohortPrecreation/v1",
                         "payload": payload, "signatureBase64url": _signed(signing_key, PRECREATE_DOMAIN, payload)})
    p.require(len(result) <= MAX_BYTES)
    return result


def prepare_release(*, configuration_raw, configuration_sha256, retrieval_configuration_raw,
                 persistence_configuration_raw, trusted_time_configuration_raw, generation_install_configuration_raw,
                 bridge_configuration_raw, precreation_raw, observations_raw, payload_raw,
                 boot, now, commit_request_configuration_raw=None, ingress_admission_configuration_raw=None, terminal_append_configuration_raw=None,
                 dispatch_barrier_configuration_raw=None, active_effect_barrier_configuration_raw=None, active_effect_commit_configuration_raw=None):
    """Validate exact public originals at supplied clocks; no release authority.

    observations_raw must come from the retained actual cohort's one observation
    frame. This data/signature API alone does not authenticate such provenance.
    Rust rechecks the same children, executable originals and complete signed
    C9 files before consuming the actual activation descriptors and gates.
    """
    config = _configuration_public(configuration_raw, configuration_sha256,
        (retrieval_configuration_raw, persistence_configuration_raw, trusted_time_configuration_raw,
         generation_install_configuration_raw, bridge_configuration_raw), commit_request_configuration_raw,
         ingress_admission_configuration_raw, terminal_append_configuration_raw, dispatch_barrier_configuration_raw,
         active_effect_barrier_configuration_raw, active_effect_commit_configuration_raw)
    key = Ed25519PublicKey.from_public_bytes(p.decoded(config["authority"]["publicKeyBase64url"], size=32))
    precreation = p.fields(p.document(precreation_raw, MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(precreation["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    _window(precreation["payload"], config, configuration_sha256, boot, now)
    key.verify(p.decoded(precreation["signatureBase64url"], size=64),
               PRECREATE_DOMAIN + p.canonical(precreation["payload"]))
    observed = p.fields(p.document(observations_raw, MAX_BYTES), originals_fields(config))
    p.require(observed["apiVersion"] == originals_api(config)
              and observed["configurationSha256"] == configuration_sha256
              and observed["precreationSha256"] == p.sha(precreation_raw)
              and observed["invocationId"] == precreation["payload"]["invocationId"])
    identities = []
    for role in roles(config):
        child = p.fields(observed[role], ("processId", "startTimeTicks", "executable"))
        p.integer(child["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(child["startTimeTicks"], maximum=(1 << 64) - 1)
        exe = p.fields(child["executable"], ("device", "inode", "length", "sha256"))
        p.integer(exe["device"], maximum=(1 << 64) - 1)
        p.integer(exe["inode"], maximum=(1 << 64) - 1)
        p.integer(exe["length"], maximum=64 * 1024 * 1024)
        p.require(exe["sha256"] == config["executableSha256"])
        identities.append((child["processId"], exe["device"], exe["inode"]))
    p.require(len({v[0] for v in identities}) == len(roles(config)) and len({v[1:] for v in identities}) == len(roles(config)))
    payload = p.fields(p.document(payload_raw, MAX_BYTES), release_fields(config))
    p.require(payload["apiVersion"] == release_api(config)
              and payload["configurationSha256"] == configuration_sha256
              and payload["precreationSha256"] == p.sha(precreation_raw)
              and payload["observationSha256"] == p.sha(observations_raw)
              and payload["invocationId"] == observed["invocationId"]
              and payload["signingKeyId"] == config["authority"]["keyId"])
    if endpoint_driver_selected(config):
        p.require(payload["externalDriverSha256"] == external_driver_sha256(config, observed))
    for name in roles(config):
        role = p.fields(payload[name], ("launch", "image"))
        delivery._pin(role["launch"]); delivery._pin(role["image"])
    domain = release_domain(config)
    p.require(len(p.canonical({"payload": payload, "signatureBase64url": ""})) + 86 <= MAX_BYTES)
    return {"payload": payload, "key": key, "window": precreation["payload"],
        "deadline": p.ns(precreation["payload"]["startupDeadlineBoottimeNs"]),
        "domain": domain, "message": domain + p.canonical(payload)}


def sign_release(*, configuration_raw, configuration_sha256, retrieval_configuration_raw,
                 persistence_configuration_raw, trusted_time_configuration_raw, generation_install_configuration_raw,
                 bridge_configuration_raw, precreation_raw, observations_raw, payload_raw,
                 boot, now, signing_key, commit_request_configuration_raw=None, ingress_admission_configuration_raw=None,
                 terminal_append_configuration_raw=None, dispatch_barrier_configuration_raw=None,
                 active_effect_barrier_configuration_raw=None, active_effect_commit_configuration_raw=None):
    """One unchanged release signature under the independently supplied key."""
    context = prepare_release(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
        retrieval_configuration_raw=retrieval_configuration_raw, persistence_configuration_raw=persistence_configuration_raw,
        trusted_time_configuration_raw=trusted_time_configuration_raw,
        generation_install_configuration_raw=generation_install_configuration_raw,
        bridge_configuration_raw=bridge_configuration_raw, precreation_raw=precreation_raw,
        observations_raw=observations_raw, payload_raw=payload_raw, boot=boot, now=now,
        commit_request_configuration_raw=commit_request_configuration_raw,
        ingress_admission_configuration_raw=ingress_admission_configuration_raw,
        terminal_append_configuration_raw=terminal_append_configuration_raw,
        dispatch_barrier_configuration_raw=dispatch_barrier_configuration_raw,
        active_effect_barrier_configuration_raw=active_effect_barrier_configuration_raw,
        active_effect_commit_configuration_raw=active_effect_commit_configuration_raw)
    _key(signing_key, configuration(configuration_raw)["authority"])
    result = p.canonical({"payload": context["payload"],
        "signatureBase64url": _signed(signing_key, context["domain"], context["payload"])})
    p.require(len(result) <= MAX_BYTES)
    return result
