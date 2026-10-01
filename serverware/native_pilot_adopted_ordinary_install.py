"""Selected adopted ordinary public-file installation, never live admission.

The executor first joins the complete input to its real predecessor outputs
and observations. This module independently authenticates all histories and
their exact preparation/resource/runtime bindings, then exclusively publishes
the fifteen fixed public files. It never reads private credentials or repairs
an existing inode. Partial files and descriptors remain owned on failure.
"""
from __future__ import annotations

import copy
import os

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as files
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_genesis_publication as writer
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_install as ordinary
from serverware import native_pilot_ordinary_key_profile as keys
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_service_authority as services
from serverware import native_pilot_window_authority as windows
from serverware import native_shadow_driver_bootstrap as driver

p = g.p
API = "serverware.nativePilotAdoptedOrdinaryInstallationInput/v1"
RESULT_API = "serverware.nativePilotAdoptedOrdinaryInstallation/v1"
FIELDS = ("apiVersion", "launchOriginal", "preparationOriginal", "resourcesOriginal",
    "driverConfigurationOriginal", "driverWindowOriginal", "coldOriginals", "historyOriginals", "runtimeOriginals")
MAX_INPUT = 32 * 1024 * 1024
_CLAIMED = False


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    return raw, g.document(raw, min(maximum, g.MAX_BYTES))


def prepare_input(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Complete public validation; supplied observations are not real owners."""
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API)
    config_raw, _ = _original(value["driverConfigurationOriginal"], 65536)
    config = windows.validate_configuration(config_raw)
    _, signed_window = _original(value["driverWindowOriginal"], 32768)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    windows.validate_window(window, config_raw, config, boot=boot, now=now_boottime_ns)
    launch_raw, _ = _original(value["launchOriginal"], 65536)
    launch, startup, lifetime = services._launch(launch_raw, boot, now_boottime_ns, adopted=True)
    preparation_raw, _ = _original(value["preparationOriginal"], keys.MAX_PREPARATION)
    resources_raw, _ = _original(value["resourcesOriginal"], 65536)
    prepared, resources = keys.preparation(preparation_raw), initial.resources(resources_raw, adopted=True)
    p.require(resources["preparationSha256"] == p.sha(preparation_raw))
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
        p.require(prepared[name] == launch[name] == window[name])
    cold_raws, history_raws, runtime_raws = {}, {}, {}
    for field in FIELDS[-3:]:
        p.fields(value[field], g.ROLES)
    deadline = min(startup, lifetime)
    for role in g.ROLES:
        cold_raw, _ = _original(value["coldOriginals"][role], 65536)
        cold = g.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
        history_raw, wrapper = _original(value["historyOriginals"][role], g.MAX_BYTES)
        runtime_raw, _ = _original(value["runtimeOriginals"][role], g.MAX_BYTES)
        selected = runtime.validate_runtime(role, runtime_raw, adopted=True)
        header = selected["runtime"]
        history = initial.manifest(history_raw, role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"],
            "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}, adopted=True)
        p.fields(wrapper, initial.WRAPPER_FIELDS)
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        state = wrapper["initialState"]
        identity = initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
            launch_raw=launch_raw, configuration=cold, window=window,
            endpoint_role=epoch["endpointProcessIdentity"]["endpointRole"], now=now_boottime_ns, adopted=True)
        p.require(identity == epoch["endpointProcessIdentity"])
        checkpoint = wrapper["initialCheckpoint"]["payload"]
        keys.validate_payload(checkpoint, identity=identity, window=window, now=now_boottime_ns)
        deadline = min(deadline, checkpoint["validUntilBoottime"]["absoluteBoottimeNanos"])
        if role == g.ROLES[-1]:
            helpers = initial.helper_endpoint_histories(history_raw, runtime=selected)
            for item in helpers.values():
                checkpoint = item["checkpoint"]["payload"]
                keys.validate_payload(checkpoint, identity=item["identity"], window=window, now=now_boottime_ns)
                deadline = min(deadline, checkpoint["validUntilBoottime"]["absoluteBoottimeNanos"])
        cold_raws[role], history_raws[role], runtime_raws[role] = cold_raw, history_raw, runtime_raw
    planned = ordinary.plan(runtime_originals=runtime_raws, history_originals=history_raws,
        cold_originals=cold_raws, launch_original=launch_raw, adopted=True)
    p.require(now_boottime_ns < deadline)
    return dict(planned=planned, deadline=deadline, epochLimit=None)


class InstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("adopted ordinary installation refused; partial public files retained")
        self.owner = owner


class Installation(writer.GenesisPublicInstallation):
    """Reuse only the retained exclusive public-file writer, not a cold plan.

    The inherited writer's fixed /etc/serverware ancestor checks, per-write
    original-clock bracket, inode readback, and descriptor retirement are the
    same for these public files. Its cold job planner is never called.
    """
    @classmethod
    def install(cls, *, input_original, expected_sha256, check):
        global _CLAIMED
        p.require(cls is Installation and not _CLAIMED)
        _CLAIMED = True
        owner = cls(writer._TOKEN, check)
        try:
            owner._clock()
            p.require(type(input_original) is bytes and p.sha(input_original) == p.digest(expected_sha256))
            admitted = prepare_input(input_original, boot=owner._boot, now_boottime_ns=owner._last,
                now_unix_ns=owner._wall)
            rows = tuple({name: row[name] for name in ("path", "uid", "gid", "mode", "raw")}
                | {"sha256": p.sha(row["raw"])} for row in admitted["planned"])
            owner._plan = dict(files=rows, launchPin=None, deadline=admitted["deadline"], epochLimit=admitted["epochLimit"])
            owner._input_sha = expected_sha256
            owner._metadata = {}
            for row in admitted["planned"]:
                selected = owner._metadata.setdefault(row["role"], {})
                pin = dict(path=row["path"], sha256=p.sha(row["raw"]))
                if row["kind"] == "runtime":
                    selected["runtimeConfig"] = pin
                else:
                    name = "authority-history" if row["kind"] == "history" else "peer-inspection-policy"
                    selected[row["kind"] + "Credential"] = dict(name=name, original=pin,
                        length=len(row["raw"]), signing=None)
            owner._clock()
            for path in writer.ROOTS:
                with io.owning():
                    parent, leaf = path.rsplit("/", 1)
                    fd = os.open(path, files.FLAGS | os.O_DIRECTORY) if path == "/" else os.open(
                        leaf, files.FLAGS | os.O_DIRECTORY, dir_fd=owner._roots[parent or "/"][0])
                    owner._pending.append(fd)
                    info = os.fstat(fd)
                    owner._roots[path] = fd, files.structural(info)
                    owner._pending.pop()
                owner._protected(info)
            owner.check()
            root = owner._roots[writer.ROOTS[-1]][0]
            for row in rows:
                try:
                    os.stat(row["path"].rsplit("/", 1)[1], dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("adopted ordinary destination exists")
            for row in rows:
                owner._write(row)
            owner.check()
            owner._installed = True
            return owner
        except BaseException as error:
            owner._failed = True
            raise InstallationError(owner) from error

    def result(self):
        p.require(self._installed)
        self.check()
        value = dict(apiVersion=RESULT_API, inputSha256=self._input_sha,
            pins=copy.deepcopy(self._pins), services=copy.deepcopy(self._metadata))
        self._clock()
        return value


def install(*, input_original, expected_sha256, check):
    return Installation.install(input_original=input_original, expected_sha256=expected_sha256, check=check)
