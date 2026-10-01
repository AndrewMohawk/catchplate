"""Observe the actual empty directories of the fixed ordinary effects owner.

This is a retained pre-delivery observation, not a computed genesis, durable
head, authority history, signature or readiness result. All directories already
belong to GenerationInputs/BusinessResources; no resource, lock, journal or
receipt is created here. Their existing cleanup graph remains authoritative.
"""
from __future__ import annotations

import fcntl
import os
import stat
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o

p = g.p
API = "serverware.custodyFiveServiceInitialResources/v1"
ADOPTED_API = "serverware.custodyFiveServiceInitialResources/v2"
FIELDS = ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services")
SERVICE_FIELDS = ("directories",)
DIRECTORY_FIELDS = ("identity", "entryCount")
IDENTITY_FIELDS = ("mountId", "deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode")
DIRECTORIES = {
    g.ROLES[0]: ("journal", "generation-journal", "dispatch-journal", "spool-head-journal"),
    g.ROLES[1]: ("state", "journal", "generation-journal", "active-effect-cleanup-journal"),
    g.ROLES[2]: ("journal", "generation-journal"),
    g.ROLES[3]: ("generation-journal", "dispatch-journal", "spool-current-journal"),
    g.ROLES[4]: ("journal", "generation-journal"),
}
ADOPTED_DIRECTORIES = {role: names + (("publication-journal",) if role in (g.ROLES[0], g.ROLES[3]) else ())
    for role, names in DIRECTORIES.items()}
MAX_BYTES = 65536
_TOKEN = object()


def directories(adoption=False):
    p.require(type(adoption) is bool)
    return ADOPTED_DIRECTORIES if adoption else DIRECTORIES


def _owner(inputs):
    from serverware.custody_generation_business import BusinessResources
    from serverware.custody_generation_inputs import GenerationInputs
    from serverware.custody_generation_launch import FiveServiceLaunch

    p.require(type(inputs) is GenerationInputs and type(inputs._launcher) is FiveServiceLaunch
        and inputs._launcher._input_owner is inputs
        and type(inputs._business_owner) is BusinessResources
        and inputs._business_owner._inputs is inputs
        and inputs._business_owner._launcher is inputs._launcher
        and threading.current_thread() is threading.main_thread())
    inputs.check()
    launch = inputs._launcher
    p.require(inputs._commitment and inputs._spool and inputs._effects and launch._inspected
        and not inputs._closed and not inputs._taken and not inputs._released
        and not launch._attempted and not launch._stop.is_set()
        and tuple(inputs._roles) == g.ROLES and tuple(launch._children) == g.ROLES
        and all(child["phase"] == "parked" and not child["reaped"] for child in launch._children.values())
        and set(inputs._commitments) == {g.ROLES[0], g.ROLES[3]}
        and set(inputs._spools) == {g.ROLES[0], g.ROLES[1], g.ROLES[3]}
        and inputs._adoption == launch._adoption
        and set(inputs._publications) == ({g.ROLES[0], g.ROLES[3]} if inputs._adoption else set()))
    for item in inputs._roles.values():
        p.require(not item["delivery_attempt"] and not item["grant_attempt"]
            and item["delivery"] is None and item["guest"] is None
            and item["grant_raw"] is None and item["launch"] is None)
    p.require(all(not item._attempted for item in (*inputs._commitments.values(), *inputs._spools.values(), *inputs._publications.values())))
    p.require(os.getpid() == launch._pid and o.native._start() == launch._start
        and o.native._boot() == launch._boot and o.clock() < launch._startup)
    return launch


class _InitialResources:
    def __init__(self, token, inputs, preparation):
        p.require(token is _TOKEN and type(preparation) is bytes)
        self.inputs, self.preparation = inputs, preparation
        self.issued = self.previous = o.clock()
        self.raw = self.value = None
        self.failed = False

    def _current(self):
        p.require(not self.failed)
        launch = _owner(self.inputs)
        now = o.clock()
        prepared = g.document(self.preparation, MAX_BYTES)
        p.require(prepared["apiVersion"] == "serverware.custodyFiveServicePreparation/v1"
            and prepared["phase"] == "parked-pre-exec"
            and p.ns(prepared["issuedAtBoottimeNs"]) <= self.issued <= self.previous <= now < launch._startup
            and p.ns(prepared["startupDeadlineBoottimeNs"]) == launch._startup
            and p.ns(prepared["lifetimeDeadlineBoottimeNs"]) == launch._lifetime
            and prepared["invocationId"] == launch._invocation)
        self.previous = now
        return launch

    def _observe(self):
        from serverware.custody_generation_inputs import _persistent

        launch = self._current()
        p.require(launch.preparation_original() == self.preparation)
        services, identities = {}, set()
        selected_directories = ADOPTED_DIRECTORIES if self.inputs._adoption else DIRECTORIES
        for role in g.ROLES:
            self._current()
            item = self.inputs._roles[role]
            cold = item["cold"]
            # Exact source-owned FD layout; never accept a caller census or
            # select fewer directories to make an occupied role look empty.
            expected = g.BUSINESS[role] + ("generation-journal", "generation-grant")
            if role in self.inputs._commitments:
                expected += ("dispatch-journal", "dispatch-grant")
            if role in self.inputs._spools:
                prefix = {g.ROLES[0]: "spool-head", g.ROLES[1]: "active-effect-cleanup",
                    g.ROLES[3]: "spool-current"}[role]
                expected += (prefix + "-journal", prefix + "-grant")
            if role in self.inputs._publications:
                expected += ("publication-journal", "publication-grant")
            descriptors = item["descriptors"]
            p.require(tuple(name for name, _ in descriptors) == expected)
            directories = {}
            for name, fd in descriptors:
                info = os.fstat(fd)
                if name not in selected_directories[role]:
                    p.require(not stat.S_ISDIR(info.st_mode))
                    continue
                p.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_uid == cold["uid"] and info.st_gid == cold["gid"]
                    and not os.get_inheritable(fd)
                    and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
                before = o.identity(info)
                _persistent(fd)
                identity = p.fields(o.directory_identity(fd), IDENTITY_FIELDS)
                p.require(o.names(fd) == () and o.identity(os.fstat(fd)) == before
                    and o.directory_identity(fd) == identity)
                pair = info.st_dev, info.st_ino
                p.require(pair not in identities)
                identities.add(pair)
                directories[name] = {"identity": identity, "entryCount": 0}
                self._current()
            p.require(tuple(directories) == selected_directories[role])
            services[role] = {"directories": directories}
        p.require(len(identities) == (17 if self.inputs._adoption else 15)
            and launch.preparation_original() == self.preparation)
        self._current()
        return {"apiVersion": ADOPTED_API if self.inputs._adoption else API, "preparationSha256": p.sha(self.preparation),
            "issuedAtBoottimeNs": str(self.issued), "services": services}

    def original(self):
        value = self._observe()
        if self.raw is None:
            raw = p.canonical(value)
            p.require(len(raw) <= MAX_BYTES)
            self.value, self.raw = value, raw
        else:
            p.require(value == self.value)
        return self.raw


def initial_resources_original(inputs):
    """One cached actual observation, revisitable only while still pristine."""
    launch = _owner(inputs)
    try:
        if not inputs._initial_state_attempted:
            inputs._initial_state_attempted = True
            preparation = launch.preparation_original()
            inputs._initial_state = _InitialResources(_TOKEN, inputs, preparation)
        p.require(inputs._initial_state is not None)
        return inputs._initial_state.original()
    except BaseException:
        if inputs._initial_state is not None:
            inputs._initial_state.failed = True
        # The existing owner still retains all real resources for cleanup.
        # No failure clears the attempt, adopts a directory or rewrites state.
        raise
