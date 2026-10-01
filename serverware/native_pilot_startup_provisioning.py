"""Actual fixed late startup publication under independent delegation.

This public-only process retains protected source originals and the actual
startup directory. It observes already-created peers, asks the closed profile
to apply the independently supplied delegation, then atomically publishes the
six fixed inputs and admission last. It neither starts children nor reads keys,
seeds current state, renews windows, retries, or removes partial publication.
"""
from __future__ import annotations

import os
import select
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_startup_profile as startup
from serverware import native_pilot_startup_provisioning_profile as profile
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_current_head_state import StartupAtomicPublisher, StateStoreError
from serverware.native_pilot_genesis_authority import _SelfRuntime
from serverware.native_pilot_lifecycle import _Protected

p = startup.p
_TOKEN, _USED, _LIVE = object(), False, None
INPUTS = ("supervisor_inventory", "delegation", "configuration", "recipe", "conductor_inventory", "authority_inventory")
LIMITS = dict(supervisor_inventory=artifacts.MAX_MANIFEST_BYTES, delegation=profile.MAX_DELEGATION,
    configuration=startup.MAX_CONFIGURATION, recipe=startup.SOURCE_LIMITS["recipe"],
    conductor_inventory=artifacts.MAX_MANIFEST_BYTES, authority_inventory=artifacts.MAX_MANIFEST_BYTES)
# Original byte accounting, not a claim about parsed Python heap consumption.
MAX_RETAINED_BYTES = sum(LIMITS.values()) + startup.MAX_OBSERVATION + sum(startup.SOURCE_LIMITS.values()) + startup.MAX_ADMISSION


class StartupProvisionerError(ValueError):
    def __init__(self, owner):
        super().__init__("startup provisioning refused; actual originals and partial publication retained; no retry")
        self.owner = owner


class StartupProvisioner:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._runtime = self._publisher = self._prepared = self._active = None
        self._sources, self._inputs = [], {}
        self._observation = self._result = None
        self._bytes = 0
        self._closed = self._closing = self._failed = self._running = self._used = False
        self.stage, self.published, self.admission_sha256 = "opening", 0, None

    @classmethod
    def open(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256, delegation_fd, delegation_sha256,
             configuration_fd, configuration_sha256, recipe_fd, recipe_sha256,
             conductor_inventory_fd, conductor_inventory_sha256, authority_inventory_fd, authority_inventory_sha256):
        global _USED, _LIVE
        p.require(cls is StartupProvisioner and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            supplied = dict(supervisor_inventory=(supervisor_inventory_fd, supervisor_inventory_sha256),
                delegation=(delegation_fd, delegation_sha256), configuration=(configuration_fd, configuration_sha256),
                recipe=(recipe_fd, recipe_sha256), conductor_inventory=(conductor_inventory_fd, conductor_inventory_sha256),
                authority_inventory=(authority_inventory_fd, authority_inventory_sha256))
            fds = [row[0] for row in supplied.values()]
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in fds) and len(set(fds)) == len(INPUTS))
            for name in INPUTS:
                fd, digest = supplied[name]
                held = _Protected(owner._sources, fd, LIMITS[name], digest)
                owner._inputs[name] = held
                owner._bytes += len(held.raw)
                p.require(owner._bytes <= MAX_RETAINED_BYTES)
            p.require(len({held.identity[:2] for held in owner._inputs.values()}) == len(INPUTS))
            owner._runtime = _SelfRuntime()
            inventory = owner._inputs["supervisor_inventory"]
            owner._runtime.admit(inventory.fd, inventory.digest)
            owner._prepared = profile.prepare(owner._inputs["delegation"].raw,
                **{name + "_original": owner._inputs[name].raw for name in INPUTS if name != "delegation"},
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            setup = startup.configuration(owner._inputs["configuration"].raw, inventory_sha256=inventory.digest,
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            with ownership.owning():
                try:
                    owner._publisher = StartupAtomicPublisher.open(directory=setup["value"]["directory"], check=owner.check)
                except StateStoreError as error:
                    p.require(type(error.owner) is StartupAtomicPublisher)
                    owner._publisher = error.owner
                    raise
            owner._publisher.preflight_inputs()
            owner.check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise StartupProvisionerError(owner) from error

    def _origin(self):
        public_io._process()
        p.require(type(self) is StartupProvisioner and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread())

    def check(self, *, full=False):
        """Publisher callback; retained checks never recursively invoke it."""
        self._origin()
        p.require(not self._failed and not self._closing and self._prepared is not None)
        for held in self._sources: (held.check if full else held.check_identity)()
        self._runtime.check()
        if self._publisher is not None: self._publisher._retained()
        now, wall = originals._clock(), time.time_ns()
        deadline, expiry = self._prepared["deadline"], self._prepared["epochLimit"]
        if self._active is not None:
            deadline, expiry = min(deadline, self._active["deadline"]), min(expiry, self._active["epochLimit"])
        p.require(self._last <= now < deadline and self._wall <= wall < expiry)
        self._last, self._wall = now, wall

    def _clocks(self):
        self.check()
        return dict(boot=self._boot, now_boottime_ns=self._last, now_unix_ns=self._wall)

    def run(self):
        try:
            self.check(full=True); p.require(not self._used and not self._running)
            self._used = self._running = True
            self.stage = "awaiting-actual-startup-observation"
            while startup.OBSERVATION_NAME not in self._publisher.names():
                self._publisher.preflight_inputs(); self.check()
                delay = min(0.01, (self._prepared["deadline"] - self._last) / 1e9,
                    (self._prepared["epochLimit"] - self._wall) / 1e9)
                p.require(delay > 0); select.select([], [], [], delay)
                self.check()
            self._observation = self._publisher.observation_original()
            self._bytes += len(self._observation)
            self._result = profile.compose(self._prepared, self._observation, **self._clocks())
            p.fields(self._result, ("originals", "admissionOriginal", "deadline", "epochLimit"))
            p.fields(self._result["originals"], startup.SOURCE_NAMES)
            self._active = {name: min(self._prepared[name], self._result[name]) for name in ("deadline", "epochLimit")}
            planned = tuple((startup.SOURCE_FILENAMES[name], self._result["originals"][name]) for name in startup.SOURCE_NAMES)
            planned += ((startup.ADMISSION_NAME, self._result["admissionOriginal"]),)
            p.require(all(type(raw) is bytes for _, raw in planned)
                and self._bytes + sum(len(raw) for _, raw in planned) <= MAX_RETAINED_BYTES)
            self.check(full=True); self._publisher.preflight_inputs()
            self.stage = "publishing-delegated-startup-inputs"
            for name, raw in planned:
                self.check(full=True)
                self._publisher.publish(name, raw)
                self._bytes += len(raw); self.published += 1
                self.check(full=True)
            self._runtime.check(installed=True); self.check(full=True)
            self.admission_sha256 = p.sha(self._result["admissionOriginal"])
            self.stage = "seven-startup-originals-published"
        except BaseException as error:
            self._failed = True
            raise StartupProvisionerError(self) from error
        finally:
            self._running = False

    def close(self):
        global _LIVE
        if self._closed: return
        try:
            self._origin(); p.require(not self._running and not self._closing)
            self._closing = True
            # Descriptor retirement only, even after expiration or partial
            # publication. Never retract an admission that another owner saw.
            with ownership.owning():
                if self._publisher is not None: self._publisher.close()
                for held in self._sources: held.close()
                if self._runtime is not None: self._runtime.close()
                self._closed = True; _LIVE = None
        except BaseException as error:
            self._failed = True
            raise StartupProvisionerError(self) from error
