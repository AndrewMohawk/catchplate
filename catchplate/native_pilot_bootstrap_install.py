"""Install one approved driver bootstrap configuration/window/control bundle.

This is the pre-start fixed-file connection, not a window signer, executable
installer, live DriverBootstrap, independent decision engine or launch command.
All original bytes and the complete bundle pin must be independently approved.
The existing cold delivery configuration and static supervisor are retained and
checked; only the three fixed public files are created, with control last.
Partial publications remain on any failure; no adoption, rollback or retry.
"""
from __future__ import annotations

from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_pilot_window_authority as window_authority
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _Original

p = driver.p
MAX_INPUT = 256 * 1024
MAX_SUPERVISOR = 64 * 1024 * 1024
FIELDS = ("apiVersion", "configurationOriginal", "windowOriginal", "controlOriginal")
PURPOSES = ("driver-bootstrap-configuration", "driver-bootstrap-window", "driver-bootstrap-control")
PATHS = (driver.CONFIGURATION, driver.WINDOW, driver.CONTROL)
LIMITS = (65536, 32768, 4096)
_USED = False


def shape(purpose: str, raw: bytes) -> dict:
    """Closed public grammar only; no installed owner, clock or signature verdict."""
    p.require(purpose in PURPOSES)
    if purpose == PURPOSES[0]:
        return window_authority.validate_configuration(raw)
    value = p.document(raw, LIMITS[PURPOSES.index(purpose)])
    if purpose == PURPOSES[1]:
        p.fields(value, ("apiVersion", "payload", "signatureBase64url"))
        p.require(value["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1")
        p.decoded(value["signatureBase64url"], size=64)
        payload = p.fields(value["payload"], scope.WINDOW_FIELDS)
        for field in ("configurationSha256", "signingKeyId"):
            p.digest(payload[field])
        p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
        for field in ("timeNamespaceDevice", "timeNamespaceInode"):
            p.integer(payload[field], maximum=p.MAX_U64)
        issued, startup, lifetime = (p.ns(payload[field]) for field in
            ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
        p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
        publication._invocation(payload["invocationId"])
    else:
        p.fields(value, ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
        p.require(value["apiVersion"] == "catchplate.nativeShadowDriverBootstrapControl/v1")
        for field in ("supervisorExecutableSha256", "configurationSha256", "windowSha256"):
            p.digest(value[field])
    return value


def _static_supervisor(raw):
    # Match DriverBootstrap.start's existing bounded static Linux/amd64 ELF
    # admission, including refusal of both PT_DYNAMIC and PT_INTERP segments.
    p.require(64 <= len(raw) <= MAX_SUPERVISOR and raw[:7] == b"\x7fELF\x02\x01\x01"
        and int.from_bytes(raw[18:20], "little") == 62
        and int.from_bytes(raw[16:18], "little") in (2, 3))
    table, stride, count = (int.from_bytes(raw[start:end], "little") for start, end in
        ((32, 40), (54, 56), (56, 58)))
    p.require(stride == 56 and 1 <= count <= 128 and 64 <= table <= len(raw)
        and table + stride * count <= len(raw)
        and all(int.from_bytes(raw[table + index * stride:table + index * stride + 4], "little")
            not in (2, 3) for index in range(count)))


def install(bundle_original: bytes, *, expected_sha256: str) -> dict:
    """Publish literal approved originals once; return measured pins, not launch."""
    global _USED
    p.require(not _USED)
    _USED = True
    p.require(type(bundle_original) is bytes and 0 < len(bundle_original) <= MAX_INPUT
        and p.sha(bundle_original) == p.digest(expected_sha256))
    value = p.fields(p.document(bundle_original, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == "catchplate.nativePilotBootstrapInstallationInput/v1")
    configuration_raw, _ = scope._original(value["configurationOriginal"], LIMITS[0])
    window_raw, _ = scope._original(value["windowOriginal"], LIMITS[1])
    control_raw, _ = scope._original(value["controlOriginal"], LIMITS[2])
    configuration = shape(PURPOSES[0], configuration_raw)
    signed = shape(PURPOSES[1], window_raw)
    control = shape(PURPOSES[2], control_raw)
    window = signed["payload"]
    p.require(control["configurationSha256"] == p.sha(configuration_raw)
        and control["windowSha256"] == p.sha(window_raw))
    driver._key(configuration["bootstrapAuthority"]).verify(
        p.decoded(signed["signatureBase64url"], size=64), driver.WINDOW_DOMAIN + p.canonical(window))
    boot = originals._boot()
    window_authority.validate_window(window, configuration_raw, configuration,
        boot=boot, now=originals._clock())
    held, publisher = [], None
    try:
        cold_pin = configuration["deliveryConfiguration"]
        cold = _Original(cold_pin["path"], 65536, cold_pin["sha256"], mode=0o400)
        held.append(cold)
        window_authority.validate_delivery(configuration, cold.raw)
        supervisor = _Original(driver.EXECUTABLE, MAX_SUPERVISOR,
            control["supervisorExecutableSha256"], mode=0o555)
        held.append(supervisor)
        _static_supervisor(supervisor.raw)
        p.require(tuple(publication.DESTINATIONS[purpose] for purpose in PURPOSES) == PATHS
            and tuple(publication.LIMITS[purpose] for purpose in PURPOSES) == LIMITS)

        def check(previous=0):
            # _Original checks actual held FD, current path/ancestor identity,
            # ownership, mode and literal bytes, not just the supplied digest.
            for original in held:
                original.check()
            now = originals._clock()
            p.require(now >= previous and originals._boot() == boot)
            window_authority.validate_window(window, configuration_raw, configuration, boot=boot, now=now)
            return now

        previous = check()
        publisher = publication.PublicPublisher.open()
        publisher.require_absent(PURPOSES)
        pins = {}
        for purpose, raw in zip(PURPOSES, (configuration_raw, window_raw, control_raw), strict=True):
            previous = check(previous)
            pins[purpose] = publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
            previous = check(previous)
        publisher.check()
        check(previous)
        return {"apiVersion": "catchplate.nativePilotBootstrapInstallation/v1", "bundleSha256": expected_sha256,
            "configurationSha256": p.sha(configuration_raw), "windowSha256": p.sha(window_raw),
            "supervisorExecutableSha256": control["supervisorExecutableSha256"],
            "invocationId": window["invocationId"], "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"], "pins": pins}
    finally:
        if publisher is not None:
            publisher.close()  # Descriptors only; all complete/partial names remain.
        for original in reversed(held):
            original.close()
