"""Real generation-one registry commit after the exact fifteen-file install.

Only explicit Input2 and its actual successful Installation authorize this
fixed projection. Independent delegation supplies current/active authority;
history signatures do not. State is initialized once under the existing lock,
then public supervisor inventory and worker policy are published policy-last.
No worker, key, decision, retry, repair or replacement is created here.
"""
from __future__ import annotations

import os
import threading
import time

from serverware import native_pilot_adopted_ordinary_install as ordinary
from serverware import native_pilot_current_head_state as state
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_initial_state_profile as profile
from serverware import native_shadow_nitro_originals as originals

p = profile.p
_TOKEN, _CLAIMED = object(), False


class InitialStateInstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("initial state installation refused; actual partial owner retained; no retry")
        self.owner = owner


class InitialStateInstallation:
    def __init__(self, token, check):
        p.require(token is _TOKEN and callable(check))
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._outer, self._installation = check, None
        self._input = self._input_sha = self._prepared = self._store = None
        self._inventory_raw = self._policy_raw = None
        self._committed = self._closed = self._closing = self._failed = False

    @classmethod
    def install(cls, *, installation, input_original, expected_sha256, check):
        global _CLAIMED
        p.require(cls is InitialStateInstallation and not _CLAIMED)
        _CLAIMED = True
        owner = cls(_TOKEN, check)
        try:
            p.require(type(installation) is ordinary.Installation)
            owner._installation = installation
            owner._clock()
            p.require(type(input_original) is bytes and 0 < len(input_original) <= ordinary.MAX_INPUT
                and p.sha(input_original) == p.digest(expected_sha256))
            owner._input, owner._input_sha = input_original, expected_sha256
            value = ordinary.installation_value(p.document(input_original, ordinary.MAX_INPUT))
            p.require(value["apiVersion"] == ordinary.INITIAL_STATE_API)
            # This is the real writer's post-readback result, not caller DTOs.
            actual = p.fields(installation.result(), ("apiVersion", "inputSha256", "pins", "services"))
            p.require(actual["apiVersion"] == ordinary.RESULT_API and actual["inputSha256"] == expected_sha256)
            owner._clock()
            prepared = ordinary.prepare_input(input_original, boot=owner._boot,
                now_boottime_ns=owner._last, now_unix_ns=owner._wall)
            expected = {row["path"]: dict(path=row["path"], sha256=p.sha(row["raw"])) for row in prepared["planned"]}
            p.require(len(expected) == 15 and actual["pins"] == expected
                and len(installation._files) == 15)
            owner._prepared = p.fields(prepared["initialState"],
                ("stateOriginal", "updateOriginal", "workerPolicyOriginal", "deadline", "epochLimit"))
            owner._inventory_raw = value["supervisorInventoryOriginal"].encode("ascii")
            owner._policy_raw = owner._prepared["workerPolicyOriginal"]
            owner._clock()
            with ownership.owning():
                try:
                    owner._store = state.StateStore.open_update(authorization_raw=owner._prepared["updateOriginal"],
                        check=owner._clock)
                except state.StateStoreError as error:
                    owner._store = error.owner
                    raise
            p.require(owner._store.apply_update() == owner._prepared["stateOriginal"])
            owner._clock()
            owner._store.publish_worker_inputs(owner._inventory_raw, owner._policy_raw)
            owner._clock()
            owner._store.release(retain_current=True)
            owner._clock()
            owner._committed = True
            owner.check_retained()
            return owner
        except BaseException as error:
            owner._failed = True
            raise InitialStateInstallationError(owner) from error

    def _origin(self):
        p.require(not self._closed and (self._pid, self._start, self._boot)
            == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == os.getresgid() == (0, 0, 0))

    def _clock(self):
        self._origin(); p.require(not self._failed and not self._closing)
        self._outer()
        if self._installation is not None: self._installation.check_retained()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._prepared is not None:
            p.require(now < self._prepared["deadline"] and wall < self._prepared["epochLimit"])
        self._last, self._wall = now, wall

    def check_retained(self):
        """No original commit callback, old job clock or new admission window."""
        self._origin()
        p.require(self._committed and not self._failed and not self._closing
            and type(self._installation) is ordinary.Installation
            and self._installation._input_sha == self._input_sha)
        self._installation.check_retained()
        self._store.check_retained()
        self._origin()

    def worker_inputs(self):
        self.check_retained()
        result = self._store.worker_inputs()
        p.require(result["supervisor_inventory_sha256"] == p.sha(self._inventory_raw)
            and result["policy_sha256"] == p.sha(self._policy_raw))
        self.check_retained()
        return result

    def result(self):
        """Only provenance of the actual committed, retained public files."""
        self.check_retained()
        state_raw = self._store._files[state.profile.STATE_NAME][2]
        value = state.profile.state(state_raw)
        inputs = self.worker_inputs()
        p.require(state_raw == self._prepared["stateOriginal"] and value["generation"] == 1)
        result = dict(stateSha256=p.sha(state_raw), stateGeneration=value["generation"],
            workerPolicySha256=inputs["policy_sha256"],
            supervisorInventorySha256=inputs["supervisor_inventory_sha256"])
        self.check_retained()
        return result

    def close(self):
        if self._closed: return
        try:
            self._origin(); p.require(not self._closing)
            self._closing = True
            with ownership.owning():
                if self._store is not None: self._store.close()
                self._closed = True
            # The original Installation is borrowed from the executor, which
            # closes it separately after all dependent child owners retire.
        except BaseException as error:
            self._failed = True
            raise InitialStateInstallationError(self) from error
