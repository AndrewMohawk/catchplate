"""Issue only the existing pre-start driver window over approved exact originals.

The closed input is apiVersion nativePilotDriverWindowAuthorityInput/v1 plus
configurationOriginal, deliveryConfigurationOriginal and payloadOriginal. All
three are literal canonical ASCII JSON strings. Independent approval covers the
complete input and the selected bootstrap authority; protected bytes alone are
not approval. No timestamp, invocation, key, deadline or configuration is made.

Static checks authenticate associations/grammar, not installed image or kernel
state. Rust retains its complete seccomp compiler and live-owner admission.
"""
from __future__ import annotations

import os
import re
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_pilot_scope_authority as scope
from catchplate import native_shadow_constructed_driver as constructed
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_key_contract as key_contract
from catchplate import native_shadow_nitro_originals as originals

p = delivery.p
MAX_INPUT = 1024 * 1024
MAX_CONFIGURATION = 65536
MAX_WINDOW = 32768
INPUT_FIELDS = ("apiVersion", "configurationOriginal", "deliveryConfigurationOriginal", "payloadOriginal")
WINDOW_FIELDS = scope.WINDOW_FIELDS
CONFIGURATION_FIELDS = ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority", "deliveryConfiguration",
    "uid", "gid", "image", "continuation", "lifecycle")


def _seccomp(value):
    """Closed grammar/commitments only; not a second rule-to-BPF compiler."""
    hashes = ("exactInstructionStreamSha256", "rawBpfSha256", "exactArgumentSemanticsSha256",
        "structurallyVerifiedPolicySha256")
    p.fields(value, ("architecture", "defaultAction", "noNewPrivilegesRequired", "installedBeforeUntrustedInput",
        "instructions", "syscallRules") + hashes)
    p.require(value["architecture"] in ("x86-64", "aarch64") and value["defaultAction"] == "kill-process"
        and value["noNewPrivilegesRequired"] is True and value["installedBeforeUntrustedInput"] is True)
    instructions, rules = value["instructions"], value["syscallRules"]
    p.require(type(instructions) is list and 1 <= len(instructions) <= 4096
        and type(rules) is list and 2 <= len(rules) <= 1024)
    raw = bytearray()
    for index, item in enumerate(instructions):
        p.fields(item, ("ordinal", "code", "jumpIfTrue", "jumpIfFalse", "operand"))
        p.require(p.integer(item["ordinal"], minimum=0, maximum=4095) == index)
        p.integer(item["code"], minimum=0, maximum=65535)
        p.integer(item["operand"], minimum=0, maximum=(1 << 32) - 1)
        for field in ("jumpIfTrue", "jumpIfFalse"):
            p.require(index + 1 + p.integer(item[field], minimum=0, maximum=255) <= len(instructions))
        raw.extend(struct.pack("<HBBI", item["code"], item["jumpIfTrue"], item["jumpIfFalse"], item["operand"]))
    p.require(instructions[-1]["code"] & 7 == 6)
    previous = -1
    for rule in rules:
        p.fields(rule, ("syscallNumber", "action", "errno", "argumentRules"))
        number = p.integer(rule["syscallNumber"], minimum=0, maximum=(1 << 32) - 1)
        error = p.integer(rule["errno"], minimum=0, maximum=65535)
        p.require(number > previous and rule["action"] in ("allow", "kill-process", "trap", "errno")
            and (error > 0 if rule["action"] == "errno" else error == 0))
        previous = number
        arguments = rule["argumentRules"]
        p.require(type(arguments) is list and len(arguments) <= 6)
        last = -1
        for argument in arguments:
            p.fields(argument, ("argumentIndex", "operator", "valueHigh", "valueLow", "maskHigh", "maskLow"))
            selected = p.integer(argument["argumentIndex"], minimum=0, maximum=5)
            p.require(selected > last and argument["operator"] in ("equal", "masked-equal", "less-than-or-equal"))
            last = selected
            for field in ("valueHigh", "valueLow", "maskHigh", "maskLow"):
                p.integer(argument[field], minimum=0, maximum=(1 << 32) - 1)
            p.require(argument["operator"] == "masked-equal"
                or argument["maskHigh"] == argument["maskLow"] == (1 << 32) - 1)
    for forbidden in ((59, 322) if value["architecture"] == "x86-64" else (221, 281)):
        matched = [rule for rule in rules if rule["syscallNumber"] == forbidden]
        p.require(len(matched) == 1 and matched[0]["action"] == "kill-process" and not matched[0]["argumentRules"])
    for field in hashes:
        p.digest(value[field])
    instruction_sha = p.framed(b"catchplate.policyShadowCustodySeccompInstructions/v1", (p.canonical(instructions),))
    raw_sha = p.sha(bytes(raw))
    semantics_sha = p.framed(b"catchplate.policyShadowCustodySeccompSemantics/v1", (p.canonical([
        value["architecture"], value["defaultAction"], True, True, rules]),))
    p.require(value["exactInstructionStreamSha256"] == instruction_sha and value["rawBpfSha256"] == raw_sha
        and value["exactArgumentSemanticsSha256"] == semantics_sha
        and value["structurallyVerifiedPolicySha256"] == p.framed(b"catchplate.policyShadowCustodySeccompPolicy/v2",
            (p.canonical([instruction_sha, raw_sha, semantics_sha]),)))


def validate_configuration(configuration_raw: bytes) -> dict:
    """Pure fixed-v4 grammar and associations; no file/process or signing work."""
    config = p.fields(p.document(configuration_raw, MAX_CONFIGURATION), CONFIGURATION_FIELDS)
    p.require(config["apiVersion"] == "catchplate.nativeShadowDriverBootstrapConfiguration/v4")
    driver._key(config["bootstrapAuthority"])
    driver._key(config["phaseTwoAuthority"])
    p.require(config["bootstrapAuthority"]["publicKeyBase64url"] != config["phaseTwoAuthority"]["publicKeyBase64url"])
    delivery._pin(config["deliveryConfiguration"])
    for field in ("uid", "gid"):
        p.integer(config[field], maximum=(1 << 32) - 2)
        p.require(config[field] not in {64988, 64989, 64990, 65534})
    image = p.fields(config["image"], ("imageSha256", "executableSha256", "seccompPolicy", "bootstrapRuntimeSha256",
        "dependencyLockSha256", "buildRecipeSha256", "provenanceSha256"))
    for field in set(image) - {"seccompPolicy"}:
        p.digest(image[field])
    _seccomp(image["seccompPolicy"])
    p.require(image["seccompPolicy"]["architecture"] == "x86-64")
    continuation = p.fields(config["continuation"], ("apiVersion", "keyTransport"))
    p.require(continuation["apiVersion"] == "catchplate.nativeShadowDriverContinuationPreparation/v3")
    transport = key_contract.transport(continuation["keyTransport"])
    p.require(transport["apiVersion"] == "catchplate.nativeShadowKeyKmsTransport/v1")
    policy = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
    p.require(policy["apiVersion"] == "catchplate.nativeShadowDriverLifecyclePolicy/v3")
    p.integer(policy["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
    gate = p.fields(policy["gate"], ("uid", "gid", "executableSha256"))
    p.require(p.integer(gate["uid"]) == p.integer(gate["gid"]) == 65534
        and p.digest(gate["executableSha256"]) != p.sha(b""))
    authority = policy["constructedAdmissionAuthority"]
    constructed.authority(authority)
    p.require(authority["publicKeyBase64url"] not in (config["bootstrapAuthority"]["publicKeyBase64url"],
        config["phaseTwoAuthority"]["publicKeyBase64url"]))
    return config


def validate_delivery(configuration: dict, delivery_configuration_raw: bytes) -> dict:
    """Admit the pinned existing production-bridge C9 original, not credentials."""
    delivery._pin(configuration["deliveryConfiguration"])
    cold = delivery.configuration(delivery_configuration_raw, configuration["deliveryConfiguration"]["sha256"])
    p.require(cold["uid"] == configuration["uid"] and cold["gid"] == configuration["gid"])
    return cold


def validate_window(payload: dict, configuration_raw: bytes, configuration: dict, *, boot: tuple, now: int) -> None:
    """Check supplied current-domain facts; callers must sample their real owner."""
    p.fields(payload, WINDOW_FIELDS)
    p.require(p.canonical(configuration) == configuration_raw)
    p.require(payload["configurationSha256"] == p.sha(configuration_raw)
        and payload["signingKeyId"] == configuration["bootstrapAuthority"]["keyId"])
    p.digest(payload["configurationSha256"]); p.digest(payload["signingKeyId"])
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    for field in ("timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(payload[field], minimum=0, maximum=p.MAX_U64)
    p.require(type(boot) is tuple and len(boot) == 3 and boot == (
        payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]))
    p.integer(now, maximum=p.MAX_U64)
    issued, startup, lifetime = (p.ns(payload[field]) for field in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    reserve = p.integer(configuration["lifecycle"]["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
    p.require(issued <= now < startup <= lifetime and startup - issued <= 30_000_000_000
        and startup < lifetime - reserve)
    invocation = payload["invocationId"]
    p.require(type(invocation) is str and re.fullmatch(r"[0-9a-f]{32}", invocation) and invocation != "0" * 32)


def sign(input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign exactly one unchanged Window/v1 payload; never renew or install it."""
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == "catchplate.nativePilotDriverWindowAuthorityInput/v1")
    configuration_raw, _ = scope._original(value["configurationOriginal"], MAX_CONFIGURATION)
    config = validate_configuration(configuration_raw)
    cold_raw, _ = scope._original(value["deliveryConfigurationOriginal"], MAX_CONFIGURATION)
    validate_delivery(config, cold_raw)
    payload_raw, payload = scope._original(value["payloadOriginal"], MAX_WINDOW)
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = driver._key(config["bootstrapAuthority"])
    p.require(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    owner = os.getpid(), originals._start(), originals._boot()
    before = originals._clock()
    validate_window(payload, configuration_raw, config, boot=owner[2], now=before)
    signature = signing_key.sign(driver.WINDOW_DOMAIN + payload_raw)
    result = p.canonical({"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1",
        "payload": payload, "signatureBase64url": p.encoded(signature)})
    signed = p.fields(p.document(result, MAX_WINDOW), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1"
        and p.canonical(signed["payload"]) == payload_raw)
    public.verify(p.decoded(signed["signatureBase64url"], size=64), driver.WINDOW_DOMAIN + payload_raw)
    after = originals._clock()
    p.require(owner == (os.getpid(), originals._start(), originals._boot()) and before <= after)
    validate_window(signed["payload"], configuration_raw, config, boot=owner[2], now=after)
    return result
