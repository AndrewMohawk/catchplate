"""Closed fresh-only ordinary runtime recipes; no files or authority actions.

Empty seed lists are explicit independent selections, not recovered history.
Credential descriptions select already provisioned originals; this module
does not read, generate, install or authenticate possession of private keys.
"""
from __future__ import annotations

import re

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_key_authority as authority
from catchplate import native_pilot_ordinary_key_profile as key

p = g.p
API = "catchplate.nativePilotOrdinaryRuntimePolicy/v1"
HELPER_API = "catchplate.nativePilotOrdinaryRuntimePolicy/v2"
MAX_POLICY = g.MAX_BYTES
HISTORY_NAME = "authority-history"
INSPECTION_NAME = "peer-inspection-policy"
RUNTIME_PATHS = {role: "/etc/catchplate/custody-" + role + "-runtime.json" for role in g.ROLES}
INSPECTION_PATHS = {role: "/etc/catchplate/custody-" + role + "-peer-inspection.json" for role in g.ROLES}
RESERVED_PATHS = frozenset((*RUNTIME_PATHS.values(), *INSPECTION_PATHS.values(),
    *initial.INITIAL_CREDENTIAL_PATHS.values()))
HEADER = ("startupTimeoutMillis", "readinessEpoch", "maximumDurabilityWorkerNanos",
    "productionDispatchProtocolSetSha256", "sharedConfigurationSha256",
    "authorityHistoryRootKeyId", "authorityHistoryRootKeySpkiSha256")
PIN = ("endpointVerifyingKeyCredential", "checkpointAuthorityVerifyingKeyCredential", "consumeCursor")
CURSOR = ("sequenceHighWater", "expectedNextSequence", "expectedPredecessorReceiptSha256")
DRS, CLEANUP, RECOVERY, CURRENT, HELPER = g.ROLES
SERVICE = {
    DRS: ("signingKeyCredential", "currentHeadAuthorityVerifyingKeyCredential", "ownershipSeed", "recoveryMaterialSeed"),
    CLEANUP: ("signingKeyCredential", "currentHeadAuthorityVerifyingKeyCredential", "minimumCheckpointSequence",
        "minimumRevocationGeneration", "cleanupAuthority", "genesisPredecessorReceiptSha256"),
    RECOVERY: ("signingKeyCredential", "serviceSigningPin", "maximumRegistrations", "lineageAuthority",
        "lineageAuthorityVerifyingKeyCredential", "durableReapLineageProofs"),
    CURRENT: ("serviceSigningKeyCredential", "serviceSigningPin", "currentSubjects"),
    HELPER: ("signingKeyCredential", "currentHeadAuthorityVerifyingKeyCredential", "helperGeneration"),
}


def digest(value):
    p.require(p.digest(value) != p.sha(b""))
    return value


def name(value):
    p.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value)
        and value not in (HISTORY_NAME, INSPECTION_NAME))
    return value


def cursor(value):
    p.fields(value, CURSOR)
    # This explicit profile starts with no consumed records. The supplied
    # predecessor is independently selected; no receipt is manufactured.
    p.integer(value["sequenceHighWater"], minimum=0, maximum=0)
    p.integer(value["expectedNextSequence"], maximum=1)
    digest(value["expectedPredecessorReceiptSha256"])


def pin(value):
    p.fields(value, PIN)
    for field in PIN[:2]:
        name(value[field])
    cursor(value["consumeCursor"])


def subject(value):
    p.fields(value, ("authority", "identity"))
    p.require(value["authority"] in ("endpoint", "cleanup-authorization-authority"))
    field = "endpoint_role" if value["authority"] == "endpoint" else "authority_role"
    p.fields(value["identity"], (field,))
    p.require(value["identity"][field] in key.ENDPOINT_ROLES)
    return value["identity"][field]


def credentials(value):
    p.require(type(value) is list and 1 <= len(value) <= 62)
    result, paths, total = {}, set(), 0
    for item in value:
        p.fields(item, ("name", "original", "length", "signing"))
        selected = name(item["name"])
        p.require(selected not in result)
        g.c9._pin(item["original"])
        p.require(item["original"]["path"] not in paths
            and item["original"]["path"] not in RESERVED_PATHS)
        paths.add(item["original"]["path"])
        total += p.integer(item["length"], maximum=g.MAX_BYTES)
        if item["signing"] is not None:
            signing = p.fields(item["signing"], ("publicKeyBase64url", "keyId"))
            p.require(p.decoded(signing["publicKeyBase64url"], size=32) != bytes(32)
                and item["length"] == 32)
            digest(signing["keyId"])
        result[selected] = item
    p.require(total <= 16 * 1024 * 1024)
    return result


def shape(fragment):
    p.fields(fragment, ("apiVersion", "services"))
    p.require(fragment["apiVersion"] in (API, HELPER_API))
    helper = fragment["apiVersion"] == HELPER_API
    rows = p.fields(fragment["services"], g.ROLES)
    for role, row in rows.items():
        p.fields(row, ("runtimeHeader", "service", "credentials"))
        header = p.fields(row["runtimeHeader"], HEADER)
        p.integer(header["startupTimeoutMillis"], maximum=30_000)
        key._uint(header["readinessEpoch"])
        p.integer(header["maximumDurabilityWorkerNanos"], maximum=1_000_000_000)
        for field in HEADER[3:]:
            digest(header[field])
        credentials(row["credentials"])
        service = p.fields(row["service"], SERVICE[role] + (("initialEndpointRoles", "initialEndpointPins")
            if helper and role == HELPER else ()))
        for field in SERVICE[role]:
            if field.endswith("Credential"):
                name(service[field])
        if role == DRS:
            p.require(service["ownershipSeed"] == [] and service["recoveryMaterialSeed"] == [])
        elif role == CLEANUP:
            p.integer(service["minimumCheckpointSequence"], maximum=1)
            key._uint(service["minimumRevocationGeneration"])
            selected = p.fields(service["cleanupAuthority"], ("serviceRole", "verifyingKeyCredential"))
            p.require(selected["serviceRole"] in g.ROLES)
            name(selected["verifyingKeyCredential"])
            digest(service["genesisPredecessorReceiptSha256"])
        elif role == HELPER:
            key._uint(service["helperGeneration"])
            if helper:
                p.require(service["initialEndpointRoles"] == list(initial.HELPER_ENDPOINT_ROLES))
                for selected in p.fields(service["initialEndpointPins"], initial.HELPER_ENDPOINT_ROLES).values():
                    pin(selected)
        else:
            pin(service["serviceSigningPin"])
            if role == RECOVERY:
                p.integer(service["maximumRegistrations"], maximum=1024)
                authority._key(service["lineageAuthority"])
                p.require(service["durableReapLineageProofs"] == [])
            else:
                subjects = service["currentSubjects"]
                p.require(type(subjects) is list and 1 <= len(subjects) <= 64)
                seen = set()
                for item in subjects:
                    p.fields(item, ("subject", "serviceRole", "pin"))
                    p.require(item["serviceRole"] in g.ROLES)
                    tag = (item["subject"]["authority"], subject(item["subject"]))
                    p.require(tag not in seen); seen.add(tag)
                    pin(item["pin"])
    p.require(len(g.canonical(fragment)) <= MAX_POLICY)
    return rows


def bind_keys(role, row, authorities, endpoint_roles):
    """Bind every provisioned credential to an approved/authenticated key."""
    service, expected, selected = row["service"], [], authorities[role]
    signing_name = "serviceSigningKeyCredential" if role == CURRENT else "signingKeyCredential"
    expected.append((service[signing_name], selected["service"], True))
    if role in (DRS, CLEANUP, HELPER):
        expected.append((service["currentHeadAuthorityVerifyingKeyCredential"], selected["checkpoint"], False))
    if role == HELPER and "initialEndpointPins" in service:
        for selection in service["initialEndpointPins"].values():
            expected.extend(((selection["endpointVerifyingKeyCredential"], selected["service"], False),
                (selection["checkpointAuthorityVerifyingKeyCredential"], selected["checkpoint"], False)))
    if role == CLEANUP:
        target = service["cleanupAuthority"]
        expected.append((target["verifyingKeyCredential"], authorities[target["serviceRole"]]["service"], False))
    if role in (RECOVERY, CURRENT):
        pins = [(role, service["serviceSigningPin"])]
        if role == RECOVERY:
            lineage = service["lineageAuthority"]
            p.require(lineage["keySpkiSha256"] != selected["service"]["keySpkiSha256"])
            expected.append((service["lineageAuthorityVerifyingKeyCredential"], lineage, False))
        else:
            for item in service["currentSubjects"]:
                allowed = endpoint_roles[item["serviceRole"]]
                p.require(subject(item["subject"]) in (allowed if type(allowed) is tuple else (allowed,)))
                pins.append((item["serviceRole"], item["pin"]))
        for target, selection in pins:
            expected.extend(((selection["endpointVerifyingKeyCredential"], authorities[target]["service"], False),
                (selection["checkpointAuthorityVerifyingKeyCredential"], authorities[target]["checkpoint"], False)))
    supplied = credentials(row["credentials"])
    p.require(set(supplied) == {item[0] for item in expected})
    for credential_name, public, signing in expected:
        public_raw = authority._raw_key(authority._key(public))
        item = supplied[credential_name]
        p.require(item["length"] == 32)
        if signing:
            p.require(item["signing"] == {"publicKeyBase64url": p.encoded(public_raw), "keyId": public["keyId"]})
        else:
            p.require(item["signing"] is None and item["original"]["sha256"] == p.sha(public_raw))


def validate_policy(fragment, *, ordinary_cold_originals, initial_policy):
    rows = shape(fragment)
    p.fields(ordinary_cold_originals, g.ROLES)
    p.fields(initial_policy, ("apiVersion", "services"))
    p.require(initial_policy["apiVersion"] == "catchplate.nativePilotSupervisorOrdinaryInitialPolicy/v1")
    initial = p.fields(initial_policy["services"], g.ROLES)
    authorities = {role: initial[role]["authorities"] for role in g.ROLES}
    roles = {role: initial[role]["endpointRole"] for role in g.ROLES}
    if fragment["apiVersion"] == HELPER_API:
        # The static recipe selects roles, never future signed wrapper bytes.
        from catchplate import native_pilot_ordinary_initial_profile as initial_profile
        p.require(roles[HELPER] in initial_profile.HELPER_ENDPOINT_ROLES)
        roles[HELPER] = initial_profile.HELPER_ENDPOINT_ROLES
    for role, row in rows.items():
        raw = ordinary_cold_originals[role].encode("ascii")
        cold = g.configuration(raw, p.sha(raw), role)
        header, approved = row["runtimeHeader"], initial[role]
        p.require(header["authorityHistoryRootKeyId"] == approved["authorities"]["root"]["keyId"]
            and header["authorityHistoryRootKeySpkiSha256"] == approved["authorities"]["root"]["keySpkiSha256"]
            and header["readinessEpoch"] >= approved["serviceGeneration"])
        bind_keys(role, row, authorities, roles)
        for item in row["credentials"]:
            if item["signing"] is not None:
                p.require(item["signing"]["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
                    and item["signing"]["keyId"] != cold["authority"]["keyId"])
        if role == CLEANUP:
            p.require(row["service"]["minimumRevocationGeneration"] <= approved["revocationGenerationHighWater"])
    return fragment
