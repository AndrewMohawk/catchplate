"""Actual four-original publication for the independently approved adopted job.

This uses the executor's existing public-file owners and retains only the real
preprovisioned fresh-store directory. It neither receives nor accesses the cold
core, creates ledger genesis, signs approval, or establishes service readiness.
The executor retains this object before acquisition and closes it only after
its genuine conductor has completed known cleanup.
"""
from __future__ import annotations

import os
import threading

from serverware import native_pilot_adopted_endpoint_plan as plan
from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_genesis_core_profile as core
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_publication as publication
from serverware import native_pilot_public_inputs as public_inputs
from serverware import native_pilot_supervisor_endpoint_inputs as endpoint

p, store = endpoint.p, endpoint.store
_PIN_NAMES = ("peer", "proofScope", "retrievalManifest", "assignment")


class _Publication:
    """Private execution state; public observations cannot construct custody."""

    def __init__(self, publisher, public):
        p.require(type(publisher) is publication.PublicPublisher
            and type(public) is public_inputs.PublicInputs)
        self.publisher, self.public = publisher, public
        self.directory = self.mode = self.cold_directory = None
        self.installation = None
        self.pid = os.getpid()
        self.attempted = self.failed = self.uncertain = False
        self.close_attempted = self.closed = False

    def _origin(self):
        p.require(os.getpid() == self.pid and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def check(self):
        self._origin()
        p.require(not self.closed and not self.close_attempted and not self.failed and not self.uncertain)
        if self.directory is not None and self.mode is not None:
            # _Directory._names uses a short-lived descriptor. Mask its ownership
            # transitions and do not relabel a failed internal close as known.
            with io.owning():
                try:
                    self.directory.check(self.mode)
                except OSError:
                    self.uncertain = True
                    raise
            p.require(self.directory.identity[:2] != self.cold_directory)

    def _read(self, pin, maximum):
        with io.owning():
            try:
                return self.public.read(pin, maximum=maximum)
            except BaseException:
                # The shared reader may fail while retiring constructor-local
                # descriptors. No retry or cleanup proof follows this failure.
                self.uncertain = True
                raise

    def publish(self, value, *, prior, observations, check):
        self.check()
        p.require(not self.attempted and callable(check))
        self.attempted = True
        try:
            check()
            planned = plan.prepare(value, prior=prior, observations=observations)
            p.require(tuple(purpose for purpose, _ in planned) == plan.PURPOSES)
            core_original = observations["endpoint-inputs"]["adoptedCore"]["observationOriginal"]
            p.require(type(core_original) is str and core_original.isascii())
            observed = core.observation(core_original.encode("ascii"))
            self.cold_directory = tuple(observed["directory"][name] for name in ("device", "inode"))
            # All prerequisites and all four absences are checked before chmod
            # or publication. A later race still fails O_EXCL; it never retries.
            self.publisher.require_absent(plan.PURPOSES)
            bootstrap = profile._input(prior, "install-precreation")["nativeColdOriginals"]
            for role, pin in value["coldOriginals"].items():
                check()
                p.require(self._read(pin, p.MAX_CONFIG) == profile._raw(bootstrap[role]))
                check()
            p.require(self._read(value["adoptionAuthorization"], profile.adoption.MAX_AUTHORIZATION)
                == profile._output(prior, "publication-adoption"))
            check()
            self.publisher.require_absent(plan.PURPOSES)
            total = sum(len(raw) for _, raw in planned)
            unread = tuple((purpose, raw) for purpose, raw in planned
                if publication.DESTINATIONS[purpose] not in self.public._entries)
            p.require(len(self.publisher._files) + len(planned) <= publication.MAX_ORIGINALS
                and self.publisher._bytes + total <= publication.MAX_PUBLIC_BYTES
                and len(self.public._entries) + len(unread) <= public_inputs.MAX_ORIGINALS
                and self.public._bytes + sum(len(raw) for _, raw in unread) <= public_inputs.MAX_PUBLIC_BYTES)
            with io.owning():
                self.directory = endpoint._Directory(value["objectDirectory"])
                try:
                    self.directory.open()
                except OSError:
                    self.uncertain = True
                    raise
                self.mode = 0o700
            check()
            self.check()
            manifest = dict(planned)["endpoint-retrieval-manifest"]
            with io.owning():
                try:
                    installed = store.install(target_directory=self.directory.path,
                        manifest_original=manifest, manifest_sha256=p.sha(manifest))
                    self.directory.installed(installed, p.sha(manifest))
                    self.installation, self.mode = installed, 0o555
                except BaseException:
                    # The installer owns transient FDs internally. Keep the
                    # retained directory and fence unknown internal retirement.
                    self.uncertain = True
                    raise
            check()
            for name, (purpose, raw) in zip(_PIN_NAMES, planned, strict=True):
                check()
                with io.owning():
                    try:
                        pin = self.publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
                    except BaseException:
                        self.uncertain = True
                        raise
                p.require(pin == value[name])
                check()
                p.require(self._read(pin, publication.LIMITS[purpose]) == raw)
                check()
            self.check()
            check()
        except BaseException:
            self.failed = True
            raise

    def close(self):
        """Release retained directory FDs only; never undo persistent changes."""
        if self.closed:
            return
        self._origin()
        p.require(not self.close_attempted and not self.uncertain)
        self.close_attempted = True
        with io.owning():
            if self.directory is not None:
                while self.directory.fds:
                    descriptor = self.directory.fds.pop()
                    os.close(descriptor)
            self.closed = True
