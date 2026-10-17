"""Fixed adopted cohort data issuer, never a process or approval capability.

Inputs are independently approved literal originals. Precreation authorizes
bounded preparation only; release signs the existing exact eleven-child wire.
The retained native owner still authenticates every process and actual FD.
"""
from __future__ import annotations

import os
import time

from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_assignment as cohort

p = cohort.p
API = "catchplate.nativePilotCohortAuthorityInput/v2"
MAX_INPUT = 2 * 1024 * 1024
ROLES = cohort.ADOPTED_ENDPOINT_ROLES
FIELDS = ("apiVersion", "operation", "configurationOriginal", "configurationSha256",
          "coldOriginals", "payloadOriginal")
ARGUMENTS = ("retrieval_configuration_raw", "persistence_configuration_raw",
    "trusted_time_configuration_raw", "generation_install_configuration_raw",
    "commit_request_configuration_raw", "ingress_admission_configuration_raw",
    "terminal_append_configuration_raw", "dispatch_barrier_configuration_raw",
    "active_effect_barrier_configuration_raw", "active_effect_commit_configuration_raw",
    "publication_reconciliation_configuration_raw")


def _original(value, maximum):
    p.require(type(value) is str and value.isascii())
    raw = value.encode("ascii")
    p.document(raw, maximum)
    return raw


def prepare_input(operation, raw, *, boot, now_boottime_ns, now_unix_ns):
    """Complete public validation before the caller may read a private key."""
    p.require(operation in ("precreation", "release"))
    extra = ("precreationOriginal", "observationsOriginal") if operation == "release" else ()
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS + extra)
    p.require(value["apiVersion"] == API and value["operation"] == operation)
    configuration_raw = _original(value["configurationOriginal"], cohort.MAX_BYTES)
    config_sha = p.digest(value["configurationSha256"])
    config = cohort.configuration(configuration_raw)
    p.require(config["apiVersion"] == cohort.ADOPTED_CONFIGURATION_API
        and cohort.roles(config) == ROLES and p.sha(configuration_raw) == config_sha)
    cold = p.fields(value["coldOriginals"], ROLES)
    kwargs = {name: _original(cold[role], cohort.delivery.MAX_DELIVERY)
        for role, name in zip(ROLES, ARGUMENTS, strict=True)}
    kwargs.update(configuration_raw=configuration_raw, configuration_sha256=config_sha,
        bridge_configuration_raw=None, payload_raw=_original(value["payloadOriginal"], cohort.MAX_BYTES))
    if operation == "release":
        kwargs.update(precreation_raw=_original(value["precreationOriginal"], cohort.MAX_BYTES),
            observations_raw=_original(value["observationsOriginal"], cohort.MAX_BYTES))
        prepared = cohort.prepare_release(**kwargs, boot=boot, now=now_boottime_ns)
        window = prepared["window"]
    else:
        cohort._configuration_public(configuration_raw, config_sha,
            tuple(kwargs[name] for name in ARGUMENTS[:4]) + (None,),
            *(kwargs[name] for name in ARGUMENTS[4:]))
        window = p.document(kwargs["payload_raw"], cohort.MAX_BYTES)
        cohort._window(window, config, config_sha, boot, now_boottime_ns)
    # The reserve comes from the original signed interval, never this sample.
    deadline = min(p.ns(window["startupDeadlineBoottimeNs"]),
        p.ns(window["lifetimeDeadlineBoottimeNs"]) - 250_000_000)
    p.require(now_boottime_ns < deadline)
    return dict(deadline=deadline, epochLimit=None, window=window, kwargs=kwargs)


def sign(operation, input_original, signing_key):
    """Sign once with an independently provisioned key and real current clocks."""
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    context = prepare_input(operation, input_original, boot=owner[2],
        now_boottime_ns=now, now_unix_ns=wall)
    producer = cohort.sign_precreation if operation == "precreation" else cohort.sign_release
    raw = producer(**context["kwargs"], signing_key=signing_key, boot=owner[2], now=now)
    p.require(owner == (os.getpid(), originals._start(), originals._boot()))
    later, epoch = originals._clock(), time.time_ns()
    p.require(now <= later and wall <= epoch)
    checked = prepare_input(operation, input_original, boot=owner[2],
        now_boottime_ns=later, now_unix_ns=epoch)
    p.require(owner == (os.getpid(), originals._start(), originals._boot()))
    final, final_epoch = originals._clock(), time.time_ns()
    p.require(later <= final < checked["deadline"] and epoch <= final_epoch
        and checked["deadline"] == context["deadline"])
    return raw, checked["deadline"]
