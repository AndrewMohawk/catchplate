"""Exact public fresh-helper bootstrap manifest, never initialization evidence.

Actual helper runtime/history admission and the live empty-journal check remain
with the receiving native owner. The manifest describes approved initialization;
only that owner can create its durable installation and seal receipts.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_current_head_profile as head

p = head.p
API = "serverware.policyCustodyCleanupHelperInitialBootstrap/v1"
DOMAIN = API.encode("ascii")
MAX_BYTES = 65536
ROLES = ("settlement-store", "fence-authority", "cgroup-executor", "termination-ledger")
FIELDS = ("apiVersion", "initialization", "operationGeneration", "sharedConfigurationSha256",
    "serviceConfigurationSha256", "initialEndpointHistorySha256", "deadline", "manifestSha256")


def _digest(value):
    p.digest(value)
    p.require(value != "sha256:" + "0" * 64)
    return value


def shape(raw):
    """Closed native framing only, not history, journal or approval admission."""
    value = p.fields(p.document(raw, MAX_BYTES), FIELDS)
    p.require(value["apiVersion"] == API and value["initialization"] == "fresh-helper")
    head.key._uint(value["operationGeneration"])
    for name in ("sharedConfigurationSha256", "serviceConfigurationSha256", "manifestSha256"):
        _digest(value[name])
    for digest in p.fields(value["initialEndpointHistorySha256"], ROLES).values():
        _digest(digest)
    head.key._deadline(value["deadline"])
    framed = p.framed(DOMAIN, (p.canonical([value[name] for name in FIELDS[:-1]]),))
    p.require(value["manifestSha256"] == framed)
    return copy.deepcopy(value)


def build(runtime_original, *, deadline):
    """Derive from literal admitted inputs; caller remains the approval owner."""
    from serverware import native_pilot_ordinary_runtime_profile as ordinary

    runtime = ordinary.validate_runtime(ordinary.HELPER, runtime_original)
    header = runtime["runtime"]
    p.require(header["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v9")
    histories = p.fields(runtime["initialEndpointHistories"], ROLES)
    digests = {}
    for role, original in histories.items():
        p.require(type(original) is str and original.isascii() and bool(original))
        digests[role] = p.sha(original.encode("ascii"))
    value = {"apiVersion": API, "initialization": "fresh-helper",
        "operationGeneration": header["operationGeneration"],
        "sharedConfigurationSha256": header["sharedConfigurationSha256"],
        "serviceConfigurationSha256": p.sha(runtime_original),
        "initialEndpointHistorySha256": digests, "deadline": copy.deepcopy(deadline)}
    value["manifestSha256"] = p.framed(DOMAIN, (p.canonical([value[name] for name in FIELDS[:-1]]),))
    raw = p.canonical(value)
    shape(raw)
    return raw


def require_runtime(raw, runtime_original, *, deadline):
    expected = build(runtime_original, deadline=deadline)
    p.require(shape(raw) == shape(expected))
