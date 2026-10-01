"""Independent static selections for the six final commissioning decisions.

Image bytes, Nitro configuration, public assignment trust and provenance still
require independent provisioning. No future observation or decision is input.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_continuation_profile as continuation
from serverware import native_pilot_interactive as interactive
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_proof_cohort_assignment as cohort

p = delivery.p
API = "serverware.nativePilotSupervisorContinuationPolicy/v1"
FIELDS = ("apiVersion", "endpointImages", "constructedAdmission")
INTERACTIVE_API = "serverware.nativePilotSupervisorContinuationPolicy/v2"
MAX_POLICY = 2 * 1024 * 1024


def validate_policy(fragment):
    p.require(type(fragment) is dict)
    selected_interactive = fragment.get("apiVersion") == INTERACTIVE_API
    p.fields(fragment, FIELDS + (("interactive",) if selected_interactive else ()))
    p.require(fragment["apiVersion"] in (API, INTERACTIVE_API) and len(p.canonical(fragment)) <= MAX_POLICY)
    for pin in p.fields(fragment["endpointImages"], cohort.ENDPOINT_ROLES).values():
        delivery._pin(pin)
    selected = copy.deepcopy(fragment)
    selected["constructedAdmission"] = continuation.validate_policy(fragment["constructedAdmission"])
    if selected_interactive:
        selected["interactive"] = interactive.validate_policy(fragment["interactive"])
    return selected
