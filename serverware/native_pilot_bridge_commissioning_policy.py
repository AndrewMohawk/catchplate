"""Explicit bridge credential metadata and late authorization selections.

Nothing here creates credentials, ciphertext, keys, services or approvals.
Actual independently approved originals must supply every selected value.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_bridge_key_profile as keys
from serverware import native_pilot_bridge_runtime_policy as runtime_policy_profile
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_endpoint_launch_profile as launches
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_contract as contract

p = c9.p
API = "serverware.nativePilotSupervisorBridgeCommissioningPolicy/v1"
ADOPTED_API = "serverware.nativePilotSupervisorBridgeCommissioningPolicy/v2"
MAX_POLICY = 256 * 1024
FIELDS = ("apiVersion", "deliveryCredentials", "keyAuthorization", "launchAuthorizations", "timeBootstrap")
WINDOW_FIELDS = ("issuedAtUnixNanos", "expiresAtUnixNanos")
CIPHERTEXT = "shadow-encrypted-role-inventory"


def validate_policy(fragment, *, bootstrap_configuration, cold_original, runtime_policy=None):
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] in (API, ADOPTED_API) and len(p.canonical(fragment)) <= MAX_POLICY)
    adopted = fragment["apiVersion"] == ADOPTED_API
    cold = delivery.configuration(cold_original, p.sha(cold_original))
    p.require(bootstrap_configuration["deliveryConfiguration"]["sha256"] == p.sha(cold_original)
        and (bootstrap_configuration["uid"], bootstrap_configuration["gid"]) == (cold["uid"], cold["gid"]))
    credentials = fragment["deliveryCredentials"]
    c9._credentials(credentials, cold["authority"])
    p.require(len(credentials) == 20 and all(row["signing"] is None
        and not row["name"].startswith("shadow-key-custody-") for row in credentials))
    rows = {row["name"]: row for row in credentials}
    p.require(CIPHERTEXT in rows and 0 < rows[CIPHERTEXT]["length"] <= 32768)
    continuation = p.fields(bootstrap_configuration["continuation"], ("apiVersion", "keyTransport"))
    p.require(continuation["apiVersion"] == "serverware.nativeShadowDriverContinuationPreparation/v3")
    transport = contract.transport(continuation["keyTransport"])
    p.require(transport["apiVersion"] == "serverware.nativeShadowKeyKmsTransport/v1"
        and rows[CIPHERTEXT]["original"]["sha256"] == transport["encryptedInventorySha256"])
    if runtime_policy is not None:
        selected = runtime_policy_profile.validate_policy(runtime_policy)
        p.require((selected["apiVersion"] == "serverware.nativePilotSupervisorBridgeRuntimePolicy/v3") == adopted)
        names = set(selected["historyCredentials"].values()) | {row["authorityBindingCredential"]
            for row in selected["authorityBindings"].values()} | {CIPHERTEXT}
        p.require(len(names) == 20 and set(rows) == names)
    keys.validate_policy(fragment["keyAuthorization"])
    for operation, row in p.fields(fragment["launchAuthorizations"],
            ("closure", "encryptedDelivery", "verifierTransport")).items():
        p.fields(row, WINDOW_FIELDS + (("parentPort",) if operation == "verifierTransport" else ()))
        p.require(p.integer(row["issuedAtUnixNanos"]) < p.integer(row["expiresAtUnixNanos"]))
        if operation == "verifierTransport":
            p.integer(row["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    clock = p.fields(fragment["timeBootstrap"], launches.CLOCK_FIELDS)
    p.integer(clock["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    p.require(p.ns(clock["maximumBracketNanos"]) <= 1_000_000_000)
    p.integer(clock["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
    p.integer(clock["maximumClockRateErrorPpm"], minimum=0, maximum=10000)
    return copy.deepcopy(fragment)
