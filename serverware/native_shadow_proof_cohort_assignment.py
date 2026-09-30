"""Closed fixed-child input authoring; no process or readiness authority.

These functions sign explicitly approved data using an already provisioned C9
delivery key. Actual kernel originals and descriptor transfer remain owned by
the Rust cohort parent and the operator's retained activation owners.
"""
from __future__ import annotations

import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_shadow_guest_delivery as delivery

p = delivery.p
PRECREATE_DOMAIN = b"serverware.nativeShadowProofCohortPrecreation.signature/v1\0"
RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v1\0"
SIX_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v2\0"
SEVEN_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v3\0"
EIGHT_RELEASE_DOMAIN = b"serverware.nativeShadowProofCohortRelease.signature/v4\0"
ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "bridge")
SIX_ROLES = ROLES + ("commitRequest",)
SEVEN_ROLES = SIX_ROLES + ("ingressAdmission",)
EIGHT_ROLES = SEVEN_ROLES + ("terminalAppend",)
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
    else:
        p.fields(value, CONFIG_FIELDS + ("cleanup", "commitRequestConfiguration", "ingressAdmissionConfiguration", "terminalAppendConfiguration"))
        p.require(value["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v5")
    from serverware import native_shadow_proof_cohort_cleanup as cleanup
    cleanup.configuration(value)
    return value


def roles(config):
    """Only fixed five/six/seven/eight inventories; never a supplied endpoint list."""
    p.require(config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v1",
        "serverware.nativeShadowProofCohortConfiguration/v2", "serverware.nativeShadowProofCohortConfiguration/v3",
        "serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5"))
    if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v5":
        return EIGHT_ROLES
    if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v4":
        return SEVEN_ROLES
    return SIX_ROLES if config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v3" else ROLES


def originals_fields(config):
    return ("apiVersion", "configurationSha256", "precreationSha256", "invocationId") + roles(config)


def release_fields(config):
    return ("apiVersion", "configurationSha256", "precreationSha256", "observationSha256", "invocationId") + roles(config) + ("signingKeyId",)


def originals_api(config):
    if roles(config) == EIGHT_ROLES:
        return "serverware.nativeShadowProofCohortOriginals/v4"
    if roles(config) == SEVEN_ROLES:
        return "serverware.nativeShadowProofCohortOriginals/v3"
    return "serverware.nativeShadowProofCohortOriginals/v2" if roles(config) == SIX_ROLES else "serverware.nativeShadowProofCohortOriginals/v1"


def release_api(config):
    if roles(config) == EIGHT_ROLES:
        return "serverware.nativeShadowProofCohortRelease/v4"
    if roles(config) == SEVEN_ROLES:
        return "serverware.nativeShadowProofCohortRelease/v3"
    return "serverware.nativeShadowProofCohortRelease/v2" if roles(config) == SIX_ROLES else "serverware.nativeShadowProofCohortRelease/v1"


def release_domain(config):
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


def _configuration(raw, expected_sha256, originals, signing_key, commit_request_original, ingress_admission_original, terminal_append_original):
    config = configuration(raw)
    p.require(p.sha(raw) == p.digest(expected_sha256))
    p.digest(config["executableSha256"])
    _key(signing_key, config["authority"])
    selected = roles(config)
    p.require((commit_request_original is not None) == (selected in (SIX_ROLES, SEVEN_ROLES, EIGHT_ROLES)))
    p.require((ingress_admission_original is not None) == (selected in (SEVEN_ROLES, EIGHT_ROLES)))
    p.require((terminal_append_original is not None) == (selected == EIGHT_ROLES))
    if commit_request_original is not None:
        originals += (commit_request_original,)
    if ingress_admission_original is not None:
        originals += (ingress_admission_original,)
    if terminal_append_original is not None:
        originals += (terminal_append_original,)
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
                     commit_request_configuration_raw=None, ingress_admission_configuration_raw=None, terminal_append_configuration_raw=None):
    """Authorize only bounded cohort resource preparation, not any service."""
    config = _configuration(configuration_raw, configuration_sha256,
        (retrieval_configuration_raw, persistence_configuration_raw, trusted_time_configuration_raw,
         generation_install_configuration_raw, bridge_configuration_raw), signing_key, commit_request_configuration_raw, ingress_admission_configuration_raw, terminal_append_configuration_raw)
    payload = p.document(payload_raw, MAX_BYTES)
    _window(payload, config, configuration_sha256, boot, now)
    result = p.canonical({"apiVersion": "serverware.nativeShadowProofCohortPrecreation/v1",
                         "payload": payload, "signatureBase64url": _signed(signing_key, PRECREATE_DOMAIN, payload)})
    p.require(len(result) <= MAX_BYTES)
    return result


def sign_release(*, configuration_raw, configuration_sha256, retrieval_configuration_raw,
                 persistence_configuration_raw, trusted_time_configuration_raw, generation_install_configuration_raw,
                 bridge_configuration_raw, precreation_raw, observations_raw, payload_raw,
                 boot, now, signing_key, commit_request_configuration_raw=None, ingress_admission_configuration_raw=None, terminal_append_configuration_raw=None):
    """Sign exact separately approved originals; never synthesize peer14.

    observations_raw must come from the retained actual cohort's one observation
    frame. This data/signature API alone does not authenticate such provenance.
    Rust rechecks the same children, executable originals and complete signed
    C9 files before consuming the actual activation descriptors and gates.
    """
    config = _configuration(configuration_raw, configuration_sha256,
        (retrieval_configuration_raw, persistence_configuration_raw, trusted_time_configuration_raw,
         generation_install_configuration_raw, bridge_configuration_raw), signing_key, commit_request_configuration_raw, ingress_admission_configuration_raw, terminal_append_configuration_raw)
    precreation = p.fields(p.document(precreation_raw, MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(precreation["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    _window(precreation["payload"], config, configuration_sha256, boot, now)
    signing_key.public_key().verify(p.decoded(precreation["signatureBase64url"], size=64),
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
    for name in roles(config):
        role = p.fields(payload[name], ("launch", "image"))
        delivery._pin(role["launch"]); delivery._pin(role["image"])
    result = p.canonical({"payload": payload, "signatureBase64url": _signed(signing_key, release_domain(config), payload)})
    p.require(len(result) <= MAX_BYTES)
    return result
