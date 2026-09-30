"""Fixed live pilot composition; independent authority remains with its owners.

This is a privileged, same-process operator API, not a JSON launcher or a
readiness command. The returned real owners expose their existing observation,
resource and signing phases. Callers must finish those phases within the
original signed windows; waiting here never extends a deadline.
"""
from __future__ import annotations

import os
import threading

from serverware.custody_generation_business import BusinessResources
from serverware.custody_generation_launch import FiveServiceLaunch
from serverware.native_shadow_driver_bootstrap import DriverBootstrap
from serverware.native_shadow_driver_inputs import OperationalInputs
from serverware.native_shadow_proof_cohort_control import EndpointStartError, ParkedProofCohort

_TOKEN = object()
_LIVE = None


def _require(condition):
    if not condition:
        raise ValueError("native pilot owner or phase does not match")


class NativePilotLaunch:
    """One measured bridge, ten endpoint children and five ordinary services.

    No owner is reconstructed from public observations. An uncertain release or
    cleanup retains this instance and its real descriptors; it cannot be restarted
    or repaired by calling this API again.
    """

    def __init__(self, token):
        _require(token is _TOKEN)
        self._pid = os.getpid()
        self._driver = self._cohort = self._five = None
        self._business = self._generation = self._spool = None
        self._release_attempted = self._cleanup_attempted = self._closed = False
        self._continuation = None
        self._stage = "starting"

    @classmethod
    def start(cls):
        global _LIVE
        _require(cls is NativePilotLaunch and _LIVE is None
                 and threading.current_thread() is threading.main_thread()
                 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            owner._driver = DriverBootstrap.start()
            # Independent cohort precreation binds this just-observed driver.
            # It cannot be prepared from a predicted identity before start().
            owner._stage = "driver"
            return owner
        except BaseException as failure:
            try:
                owner.close()
            except BaseException as cleanup_failure:
                raise BaseExceptionGroup("native pilot preparation and cleanup failed",
                                         [failure, cleanup_failure]) from None
            raise

    def _origin(self):
        _require(_LIVE is self and not self._closed and os.getpid() == self._pid
                 and threading.current_thread() is threading.main_thread()
                 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _preparing(self):
        self._origin()
        _require(self._stage == "resources"
                 and not self._release_attempted and not self._cleanup_attempted)
        self._driver.check()
        self._cohort.check()
        self._five.check()
        self._business.check()
        self._generation.check()
        self._spool.check()

    def start_endpoints(self):
        """Use independently installed originals bound to this actual driver."""
        self._origin()
        _require(self._stage == "driver" and not self._cleanup_attempted)
        self._driver.check()
        self._stage = "endpoint-start-attempted"
        # Both native parents require a single-threaded operator. The ordinary
        # five start creates its lifetime watcher, so it must follow both.
        try:
            self._cohort = ParkedProofCohort.start_for_driver(self._driver)
        except EndpointStartError as failure:
            # Retain the actual partial owner, not public observations. Driver
            # cleanup must happen before shared endpoint resources may close.
            self._cohort = failure.cohort
            raise
        self._five = FiveServiceLaunch.start_effects()
        self._stage = "endpoints"

    def prepare_resources(self):
        """Allocate actual resources before their independent signed delivery."""
        self._origin()
        _require(self._stage == "endpoints" and not self._cleanup_attempted)
        self._driver.check()
        self._cohort.check()
        self._five.check()
        self._stage = "resource-preparation-attempted"
        self._business = BusinessResources.prepare_commitment(self._five)
        self._generation = self._business.commitment_inputs()
        self._spool = self._cohort.prepare_spool_inputs()
        self._stage = "resources"
        self._preparing()

    @property
    def driver(self):
        self._origin()
        return self._driver

    @property
    def cohort(self):
        self._origin()
        return self._cohort

    @property
    def ordinary_services(self):
        self._origin()
        return self._five

    @property
    def business_resources(self):
        self._origin()
        return self._business

    @property
    def generation_inputs(self):
        self._origin()
        return self._generation

    @property
    def spool_inputs(self):
        self._origin()
        return self._spool

    def release(self, *, operational_inputs, endpoint_release_original,
                endpoint_transfers, phase_two_scope_original,
                phase_two_public_originals):
        """Consume real prepared owners once; construction is not readiness.

All independent grants/deliveries, actual gate binding and resource originals
must already exist. Existing owners verify them; this method neither signs nor
recreates them. No user callback or arbitrary executable runs between releases.
        """
        self._preparing()
        _require(type(operational_inputs) is OperationalInputs
                 and operational_inputs._driver is self._driver
                 and type(endpoint_release_original) is bytes
                 and type(endpoint_transfers) is dict
                 and type(phase_two_scope_original) is bytes
                 and type(phase_two_public_originals) is bytes)
        operational_inputs.check()
        self._release_attempted = True
        transfer = self._generation.transfer()
        self._five.release(transfer)
        self._five.release_endpoint_cohort(
            self._cohort, driver=self._driver, inputs=operational_inputs,
            release_original=endpoint_release_original, transfers=endpoint_transfers)
        self._continuation = self._cohort.continue_driver(
            inputs=operational_inputs, signed_scope_original=phase_two_scope_original,
            public_originals=phase_two_public_originals)
        return dict(self._continuation)

    def close(self):
        """Retire each actual owner without crediting unknown cleanup.

The driver subtree retires first. If it is uncertain, stop the locally owned
endpoints and ordinary children, but retain all shared business originals and
resources. There is no cleanup retry or deadline renewal in this wrapper.
        """
        global _LIVE
        if self._closed:
            return
        self._origin()
        _require(not self._cleanup_attempted)
        self._cleanup_attempted = True
        failures = []
        if self._driver is not None:
            try:
                self._driver.close()
            except BaseException as error:
                failures.append(error)
        if self._cohort is not None:
            try:
                if failures:
                    self._cohort.stop_endpoints()
                else:
                    self._cohort.close()
            except BaseException as error:
                failures.append(error)
        if self._five is not None:
            try:
                # This reaps real ordinary children without discarding the
                # separate generation/business descriptors on unknown cleanup.
                self._five.close()
            except BaseException as error:
                failures.append(error)
        if not failures:
            try:
                if self._generation is not None:
                    self._generation.close()
                elif self._business is not None:
                    self._business.close()
            except BaseException as error:
                failures.append(error)
        if failures:
            # _LIVE retains the complete object graph on every unknown result.
            raise BaseExceptionGroup("native pilot cleanup remains incomplete", failures)
        self._closed = True
        _LIVE = None

    def __enter__(self):
        self._origin()
        _require(self._stage == "driver" and not self._cleanup_attempted)
        self._driver.check()
        return self

    def __exit__(self, *_):
        self.close()
