"""Closed public bundle serialization for the actual phase-two publication job.

These are grammar and literal-byte associations, not signature or installation
proof. The retained release owner authenticates scope and source results; the
phase executor publishes once with its real exclusive PublicPublisher.
"""
from __future__ import annotations

from catchplate import native_pilot_bridge_install as bridge_install
from catchplate import native_pilot_bridge_runtime as runtime
from catchplate import native_pilot_driver_authority as driver_authority
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_publication_profiles as profiles
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_shadow_driver_bootstrap as driver

p = scope.p
API = "catchplate.nativePilotPhaseTwoPublicationInput/v1"
FIELDS = ("apiVersion", "publicBundleOriginal")
PURPOSE = "driver-phase-two-public"
MAX_INPUT = runtime.MAX_BRIDGE_INPUT


def shape(raw, *, adopted=False):
    """Existing version-selected public bundle with all literal source pins."""
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT)
    _, bundle, runtime_raw, operational = driver_authority._phase_bundle(raw.decode("ascii"), adopted=adopted)
    bridge_install.shape("bridge-runtime", runtime_raw)
    delivered_raw, delivered = scope._original(bundle["deliveryOriginal"], 65536)
    profiles.shape("native-delivery-bridge", delivered_raw)
    p.require(delivered["payload"]["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    grants = p.fields(bundle["generationOriginals"], driver.ROLES)
    for role, original in grants.items():
        grant_raw, _ = scope._generation_original(original)
        profiles.shape("ordinary-generation-" + role, grant_raw)
        p.require(operational["generationAdmission"]["grants"][role] == p.sha(grant_raw))
    return bundle


def prepare_input(input_raw, *, adopted=False):
    value = p.fields(p.document(input_raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API)
    raw, _ = scope._original(value["publicBundleOriginal"], MAX_INPUT)
    shape(raw, adopted=adopted)
    return raw


def build(bundle_raw, *, adopted=False):
    shape(bundle_raw, adopted=adopted)
    raw = p.canonical({"apiVersion": API, "publicBundleOriginal": bundle_raw.decode("ascii")})
    p.require(len(raw) <= MAX_INPUT)
    return raw


def checked_result(input_raw, result, *, adopted=False):
    raw = prepare_input(input_raw, adopted=adopted)
    p.fields(result, ("pin",))
    expected = {"pin": {"path": publication.DESTINATIONS[PURPOSE], "sha256": p.sha(raw)}}
    scope._same(result, expected)
    return expected
