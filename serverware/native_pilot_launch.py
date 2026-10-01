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
from serverware.custody_generation_launch import FiveServiceLaunch, FiveServiceStartError
from serverware.native_shadow_driver_bootstrap import DriverBootstrap, DriverBootstrapStartError
from serverware.native_shadow_driver_inputs import OperationalInputs
from serverware.native_shadow_driver_outgoing import OutgoingResources
from serverware.native_shadow_driver_resources import BridgeResources
from serverware.native_shadow_proof_cohort_control import EndpointStartError, ParkedProofCohort

_TOKEN = object()
_LIVE = None


def _require(condition):
    if not condition:
        raise ValueError("native pilot owner or phase does not match")


class PilotStartError(ValueError):
    """The actual partial pilot remains owned; cleanup is not retryable."""

    def __init__(self, pilot, failure):
        super().__init__("native pilot start failed; cleanup uncertain; owner retained")
        self.pilot, self.failure = pilot, failure


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
        self._commit_request = self._generation_install = self._bridge = self._outgoing = None
        self._operation = None
        self._endpoint_inputs = None
        self._service_inputs_attempted = False
        self._five_cleanup_failure = None
        self._connections_attempted = self._operation_attempted = False
        self._release_attempted = self._cleanup_attempted = self._closed = False
        self._continuation = None
        self._origin_attempted = self._interactive_attempted = self._interactive_failed = False
        self._origin_handoff = self._interactive_result = None
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
        except DriverBootstrapStartError as failure:
            owner._driver = failure.driver
            owner._cleanup_attempted = True  # Driver already attempted cleanup once.
            raise PilotStartError(owner, failure) from failure
        except BaseException as failure:
            try:
                owner.close()
            except BaseException as cleanup_failure:
                combined = BaseExceptionGroup("native pilot preparation and cleanup failed",
                                              [failure, cleanup_failure])
                raise PilotStartError(owner, combined) from None
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
        self._commit_request.check()
        self._generation_install.check()
        self._bridge.check()
        if self._outgoing is not None:
            self._outgoing.check()
        if self._endpoint_inputs is not None:
            self._endpoint_inputs.check()

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
        try:
            self._five = FiveServiceLaunch.start_effects()
        except FiveServiceStartError as failure:
            self._five = failure.launch
            self._five_cleanup_failure = failure.cleanup_error
            raise
        self._stage = "endpoints"

    def prepare_resources(self):
        """Allocate actual resources before their independent signed delivery."""
        self._origin()
        _require(self._stage == "endpoints" and not self._cleanup_attempted)
        self._driver.check()
        self._cohort.check()
        self._five.check()
        _require(self._driver._gate_binding is not None)
        self._stage = "resource-preparation-attempted"
        self._business = BusinessResources.prepare_commitment(self._five)
        self._generation = self._business.commitment_inputs()
        self._spool = self._cohort.prepare_spool_inputs()
        self._commit_request = self._cohort.prepare_commit_request_inputs()
        self._generation_install = self._cohort.prepare_generation_install_inputs()
        self._bridge = BridgeResources.prepare(self._driver)
        self._stage = "resources"
        self._preparing()

    def prepare_bridge_connections(self):
        """Allocate the exact live clients after all endpoint paths exist.

        The protected outgoing runtime must bind the already allocated journal
        and actual measured peers. These still-unconnected sockets become C9
        observations; allocation is not authentication or permission to send.
        """
        self._preparing()
        _require(not self._connections_attempted and not self._operation_attempted)
        self._connections_attempted = True
        self._outgoing = OutgoingResources.prepare(self._driver)
        self._bridge.prepare_native_peers(outgoing=self._outgoing, spool=self._spool)
        self._preparing()

    def bridge_activation(self):
        """Actual complete C9 FD6+ metadata for the independent delivery signer."""
        self._preparing()
        _require(self._connections_attempted and self._outgoing is not None)
        records = self._bridge.activation_originals() + self._outgoing.activation_originals()
        _require(len(records) == 41 and len({entry["name"] for entry in records}) == 41)
        return [dict(entry, fd=target) for target, entry
                in enumerate(sorted(records, key=lambda item: item["name"]), 6)]

    def prepare_operational_inputs(self, *, launch_pin, production):
        """Join independent launch originals to these exact retained resources."""
        self._preparing()
        _require(self._connections_attempted and not self._operation_attempted)
        self._operation_attempted = True
        self._operation = OperationalInputs.prepare_pilot(self._driver, outgoing=self._outgoing,
            resources=self._bridge, launch_pin=launch_pin, production=production)
        self._preparing()
        return self._operation

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

    @property
    def commit_request_inputs(self):
        self._origin()
        return self._commit_request

    @property
    def generation_install_inputs(self):
        self._origin()
        return self._generation_install

    @property
    def bridge_resources(self):
        self._origin()
        return self._bridge

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
        _require(self._operation_attempted and operational_inputs is self._operation)
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

    def check_running(self):
        """Check retained live owners, never reopen their preparation phases."""
        self._origin()
        _require(self._release_attempted and self._continuation is not None
            and not self._cleanup_attempted and not self._interactive_failed
            and self._driver._constructed and self._operation is self._driver._operational_inputs)
        self._driver.check()
        self._cohort.check_running()
        self._five.check()
        _require(self._five._attempted and self._five._thread is not None
            and self._five._thread.is_alive() and not self._five._stop.is_set()
            and all(item["phase"] == "constructed" for item in self._five._children.values()))
        self._generation.check()
        self._spool.check(preparation=False)

    def running_deadline_boottime_ns(self):
        """The original three lifetimes minus the original maximum reserve."""
        self.check_running()
        from serverware import native_shadow_nitro_profile as p
        from serverware.native_pilot_interactive import COHORT_REAP_RESERVE_NS
        production = p.document(self._operation._operation, 65536)["production"]
        reserve = max(self._driver._config["lifecycle"]["cleanupReserveNanos"], production["cleanupReserveNanos"])
        return min(min(self._driver._lifetime, self._cohort._lifetime, self._five._lifetime) - reserve,
            self._cohort._lifetime - COHORT_REAP_RESERVE_NS)

    def running_pidfds(self):
        """Borrow only PIDFDs already retained by this actual owner graph."""
        self.check_running()
        _require(self._driver._driver_pidfd is not None and self._driver._gate_pidfd is not None)
        return (self._driver._pidfd, self._driver._driver_pidfd, self._driver._gate_pidfd,
            self._cohort._pidfd, *(item[0] for item in self._cohort._parked),
            *(item["pidfd"] for item in self._five._children.values()))

    def deliver_generation_origin(self, *, deadline_boottime_ns):
        """Retain only the actual existing relay's one returned handoff."""
        from serverware import native_pilot_interactive as interactive
        self._origin()
        _require(self._release_attempted and self._continuation is not None
            and not self._cleanup_attempted and not self._origin_attempted)
        self._origin_attempted = True
        handoff = self._cohort.deliver_generation_origin(deadline_boottime_ns=deadline_boottime_ns)
        self._origin_handoff = interactive._handoff(handoff)
        return handoff

    def run_interactive(self, action, *, origin_handoff, deadline_boottime_ns):
        from serverware import native_pilot_interactive as interactive
        return interactive.run(self, action, origin_handoff=origin_handoff,
            deadline_boottime_ns=deadline_boottime_ns)

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
                if self._five_cleanup_failure is not None:
                    raise self._five_cleanup_failure  # No second cleanup attempt.
                self._five.close()
            except BaseException as error:
                failures.append(error)
        if not failures:
            try:
                if self._generation is not None:
                    self._generation.close()
                elif self._business is not None:
                    self._business.close()
                if self._endpoint_inputs is not None:
                    self._endpoint_inputs.close()
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
