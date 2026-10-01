"""Exact hot12 endpoint source admission, not a live owner or approval source.

Only complete independently approved C9/v2 and signed key/admission originals
are accepted. Existing native grant domains remain unchanged. No fabricated
validator result, baseline, current-key record or refreshed window is used.
"""
from __future__ import annotations

from serverware import native_pilot_adopted_delivery as delivery
from serverware import native_pilot_key_profile as keys
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_profile as p

PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
MAX_AGE = 300_000_000_000


def context(role, *, pair, delivery_input_original, delivery_original, configuration_original,
        configuration_sha256, assignment_payload_original, boot, now_boottime_ns, now_unix_ns):
    p.require(role in keys.ADOPTED_ROLES)
    p.fields(pair, PAIR_FIELDS)
    raw = {}
    for name, value in pair.items():
        maximum = keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT
        p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
        raw[name] = value.encode("ascii")
        p.document(raw[name], maximum)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    authenticated = keys.admitted_adopted_pair(role, *(raw[name] for name in PAIR_FIELDS), **clocks)
    first = keys.input_document(raw["roleKeyInputOriginal"])
    p.require(first["deliveryInputOriginal"].encode("ascii") == delivery_input_original
        and first["deliveryOriginal"].encode("ascii") == delivery_original)
    delivered = delivery.verify_delivery(delivery_input_original, delivery_original, **clocks)
    p.require(delivered["role"] == role and delivered["guest"] == authenticated["expectedScope"]["guest"]
        and p.sha(configuration_original) == p.digest(configuration_sha256))
    configuration = p.document(configuration_original, p.MAX_CONFIG)
    for name in authenticated: p.require(configuration[name] == authenticated[name])
    admitted, authorities = admission.authorization(configuration, now_unix_ns)
    recipe = first["recipeOriginals"]
    assignment = p.document(recipe["assignmentOriginal"].encode("ascii"), 4 * 1024 * 1024)
    p.require(p.canonical(assignment["payload"]) == assignment_payload_original
        and assignment["payloadSha256"] == p.sha(assignment_payload_original) == admitted["assignmentPayloadSha256"])
    trust = p.document(recipe["trustOriginal"].encode("ascii"), 1024 * 1024)
    p.require(p.sha(recipe["trustOriginal"].encode("ascii")) == recipe["trustSha256"]
        and trust["checkpoint"] == configuration["trustCheckpoint"])
    documents = [trust, assignment["payload"], authenticated["authorization"]["payload"],
        authenticated["admissionAuthorization"]["payload"]]
    floors = [value["issuedAtUnixNanos"] for value in documents]
    ceilings = [min(value["expiresAtUnixNanos"], value["issuedAtUnixNanos"] + MAX_AGE + 1) for value in documents]
    records = [trust["assignmentKey"], trust["timeKey"], *(row["key"] for row in trust["roleKeys"])]
    floors.extend(row["notBeforeUnixNanos"] for row in records)
    ceilings.extend(row["notAfterUnixNanos"] for row in records)
    floors.append(trust["checkpoint"]["asOfUnixNanos"])
    ceilings.append(trust["checkpoint"]["asOfUnixNanos"] + MAX_AGE)
    p.require(max(floors) <= now_unix_ns < min(ceilings))
    return {"pair": authenticated, "first": first, "delivery": delivered, "configuration": configuration,
        "admitted": admitted, "keys": authorities, "assignment": assignment["payload"], "trust": trust,
        "deadline": p.ns(delivered["window"]["startupDeadlineBoottimeNs"]),
        "epochFloor": max(floors), "epochLimit": min(ceilings)}


def require_interval(context, issued, expires, *, now_unix_ns):
    p.freshness(issued, expires, now_unix_ns)
    p.require(context["epochFloor"] <= issued < expires <= context["epochLimit"])
    return min(expires, issued + MAX_AGE + 1, context["epochLimit"])


def require_generation_scope(context, scope):
    """Current approved configuration and trust, not merely the same signer."""
    measured, admitted = context["first"]["measured"], context["admitted"]
    p.require(scope["previousConfigurationBindingSha256"] is None
        and scope["assignmentId"] == admitted["assignmentId"]
        and scope["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
        and scope["assignmentRevision"] == admitted["assignmentRevision"]
        and scope["successorConfigurationBindingSha256"] == measured["configurationBindingSha256"]
        and scope["fiveServiceProtocolSetSha256"] == measured["production"]["dispatcherProtocolSetSha256"])
    checkpoint = context["configuration"]["trustCheckpoint"]
    for target, source in (("trustedTimeCheckpointSha256", "checkpointId"),
            ("trustedTimeRevocationGeneration", "revocationGeneration"), ("trustedTimeRevocationRootSha256", "revocationRootSha256")):
        p.require(scope[target] == checkpoint[source])
    key = context["keys"][p.ROLES.index("custody-result-envelope")]
    p.require(scope["envelopeAuthorityKeyId"] == key["keyId"]
        and scope["envelopeAuthorityKeySpkiSha256"] == key["keySpkiSha256"])


def duplicate_originals(context, value, *, generation=False):
    """Exact retained source equality; labels cannot substitute C9 provenance."""
    delivered = context["delivery"]
    mappings = (("cohortConfigurationOriginal", "owner_configuration_raw"),
        ("coordinatorConfigurationOriginal" if generation else "coldConfigurationOriginal", "configuration_raw"),
        ("coordinatorRuntimeOriginal" if generation else "runtimeOriginal", "runtime_raw"))
    for source, field in mappings: p.require(value[source].encode("ascii") == delivered[field])
    original = p.document(value["deliveryInputOriginal"].encode("ascii"), delivery.MAX_INPUT)
    p.require(value["precreationOriginal"] == original["windowOriginal"]
        and value["observationOriginal"] == original["observationOriginal"])
