"""Closed C9 input projection from retained ordinary originals and activation.

Activation is public data supplied by the actual resource owner. This helper
does not obtain descriptors or turn that data into ownership or approval.
The separate adopted selector never changes a legacy input's interpretation.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_service_authority as authority
from serverware import native_pilot_supervisor_ordinary_deliveries as delivery

p = g.p


def build(role, *, launch_raw, configuration_raw, runtime_raw, payload_raw, activation, adopted=False):
    p.require(role in g.ROLES and type(adopted) is bool)
    value = {"apiVersion": authority.ADOPTED_INPUT_API if adopted else delivery.INPUT_API,
        "operation": "delivery", "serviceRole": role, "launchOriginal": launch_raw.decode("ascii"),
        "configurationOriginal": configuration_raw.decode("ascii"), "configurationSha256": p.sha(configuration_raw),
        "runtimeOriginal": runtime_raw.decode("ascii"), "payloadOriginal": payload_raw.decode("ascii"),
        "activation": copy.deepcopy(activation)}
    # The outer input carries unsigned descriptor metadata, preserving u64.
    raw = g.canonical(value)
    delivery._input(role, raw, adopted=adopted)
    return raw


def checked_result(role, input_raw, result, *, adopted=False):
    return delivery.checked_result(role, input_raw, result, adopted=adopted)
