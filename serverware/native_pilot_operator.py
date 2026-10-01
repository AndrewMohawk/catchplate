"""Fixed live pilot conductor; every signature comes from an independent owner.

Eleven machine exchanges join the existing real resource/launch owners. Public
observations are not capabilities. No authority key, arbitrary command, user
callback, supplied numeric descriptor or readiness override is accepted here.
This module does not implement the independently operated authority coordinator.
"""
from __future__ import annotations

import os

from serverware import custody_generation_grants as generation
from serverware import custody_generation_originals as originals
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import native_pilot_interactive as interactive
from serverware.native_pilot_endpoint_inputs import PilotEndpointInputs
from serverware.native_pilot_launch import NativePilotLaunch, PilotStartError
from serverware.native_pilot_operator_channel import Channel, STAGES
from serverware.native_pilot_public_inputs import PublicInputs
from serverware.native_pilot_service_inputs import ENDPOINT_INPUT_ROLES, SPOOL_LISTENER_ROLES, admit_services

_TOKEN = object()
_LIVE = None
_USED = False


def _text(raw):
    p.require(type(raw) is bytes)
    return raw.decode("ascii")


class Operator:
    """One actual attempt, retained even when startup or cleanup is uncertain."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid = os.getpid()
        self._pilot = self._channel = self._public = None
        self._production = None
        self._transfers = None
        self._bridge_preparation = None
        self._phase = "open"
        self._cleanup_attempted = self._closed = self._finished = False
        self._failure = self._cleanup_failure = None
        self._interactive_result = None

    @classmethod
    def claim(cls):
        global _LIVE, _USED
        p.require(cls is Operator and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN)
        _LIVE = owner  # Before the first pipe, original or live process is acquired.
        return owner

    def _deadline(self, *, live=False):
        pilot = self._pilot
        pilot._origin()
        owners = tuple(owner for owner in (pilot._driver, pilot._cohort, pilot._five) if owner is not None)
        p.require(bool(owners))
        deadline = min(owner._lifetime if live else owner._startup for owner in owners)
        if live:
            p.require(self._production is not None)
            reserve = max(pilot._driver._config["lifecycle"]["cleanupReserveNanos"],
                          self._production["cleanupReserveNanos"])
            deadline -= reserve
        p.require(originals.clock() < deadline)
        return deadline

    def _exchange(self, phase, payload, fields, *, live=False):
        p.require(phase in STAGES and not self._cleanup_attempted and os.getpid() == self._pid)
        self._phase = phase
        self._public.check()
        if self._bridge_preparation is not None and not self._bridge_preparation._consumed:
            self._bridge_preparation.check()
        reply = self._channel.exchange(phase, payload, deadline_boottime_ns=self._deadline(live=live))
        if phase == "shutdown" and reply.get("action") == "run-interactive":
            interactive.validate_action(reply, origin_handoff=payload["originHandoff"])
        else:
            p.fields(reply, fields)
        self._public.check()
        if self._bridge_preparation is not None and not self._bridge_preparation._consumed:
            self._bridge_preparation.check()
        return reply

    def _resource_observations(self):
        pilot = self._pilot
        pilot._preparing()
        native = {"generationInstall": pilot.generation_install_inputs.activation(),
                  "commitRequest": pilot.commit_request_inputs.activation()}
        for role in SPOOL_LISTENER_ROLES:
            native[role] = [originals.activation(name, target, fd) for target, (name, fd)
                in enumerate(pilot.spool_inputs.additions(role), 6)]
        return {
            "cohortObservationOriginal": _text(pilot.cohort.original_bytes()),
            "ordinaryParked": pilot.ordinary_services.parked_originals(),
            "ordinaryActivations": {role: pilot.generation_inputs.activation(role) for role in generation.ROLES},
            "ordinaryDirectories": {role: pilot.generation_inputs.directory_identities(role) for role in generation.ROLES},
            "nativeActivations": native,
            "bridgeJournal": pilot.bridge_resources.journal_identity(),
        }

    def _prepare_endpoints(self, inputs):
        p.fields(inputs["coldOriginals"], ("retrieval", "persistence", "trustedTime"))
        cold = {role: self._public.read(pin, maximum=p.MAX_CONFIG)
                for role, pin in inputs["coldOriginals"].items()}
        peer = self._public.read(inputs["peer"], maximum=16384)
        scope = self._public.read(inputs["proofScope"], maximum=16384)
        manifest = self._public.read(inputs["retrievalManifest"], maximum=retrieval.MAX_MANIFEST)
        assignment = self._public.read(inputs["assignment"], maximum=4 * 1024 * 1024)
        # Existing deterministic recipe validates the exact nine production
        # fields. Its measured values are not an assignment/grant approval.
        recipe = self._pilot.driver.generation_manifest(assignment_original=assignment,
                                                       production=inputs["production"])
        self._production = dict(inputs["production"])
        path = inputs["objectDirectory"]
        p.require(type(path) is str and len(path) <= 4096 and "\0" not in path)
        directory = originals.directory(path)
        try:
            endpoints = PilotEndpointInputs.prepare(self._pilot, cold_originals=cold,
                peer_original=peer, peer_sha256=inputs["peer"]["sha256"],
                proof_scope_original=scope, proof_scope_sha256=inputs["proofScope"]["sha256"],
                retrieval_manifest_original=manifest, retrieval_manifest_sha256=inputs["retrievalManifest"]["sha256"],
                object_directory_fd=directory, assignment_original=assignment)
        finally:
            # The composite claims/duplicates the genuine directory before any
            # resource side effects. Only this caller's extra FD closes here.
            os.close(directory)
        return endpoints, recipe

    def run(self):
        """Start once and leave owners held until explicit close, including errors."""
        p.require(_LIVE is self and self._phase == "open" and not self._cleanup_attempted)
        self._phase = "starting"
        self._channel = Channel.open()
        self._public = PublicInputs.open()
        try:
            self._pilot = NativePilotLaunch.start()
        except PilotStartError as failure:
            self._pilot = failure.pilot
            raise
        pilot = self._pilot
        driver = pilot.driver
        p.require(driver._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
            and driver._config["lifecycle"]["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")

        bootstrap = self._exchange("bootstrap-admission", {
            "bootstrapObservationOriginal": _text(driver.observation_original()),
            "admissionPayloadOriginal": _text(driver.prepare_bootstrap_driver_admission()),
        }, ("bootstrapAdmission",))
        admitted = driver.accept_bootstrap_driver_admission(
            self._public.read(bootstrap["bootstrapAdmission"], maximum=8192))
        gate = driver.await_gate_binding()
        self._exchange("endpoint-precreation", {
            "bootstrapObservationOriginal": _text(driver.observation_original()),
            "bootstrapAdmissionOriginal": _text(admitted), "gateBindingOriginal": _text(gate),
        }, ())
        pilot.start_endpoints()
        pilot.prepare_resources()

        inputs = self._exchange("endpoint-inputs", self._resource_observations(),
            ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production"))
        endpoints, recipe = self._prepare_endpoints(inputs)
        observations = self._resource_observations()
        observations["nativeActivations"].update(endpoints.activations())
        observations["driverGenerationRecipe"] = recipe
        endpoint_reply = self._exchange("endpoint-deliveries", observations, ("endpointDeliveries",))
        endpoint_pins = p.fields(endpoint_reply["endpointDeliveries"], ENDPOINT_INPUT_ROLES)
        endpoint_result = endpoints.admit_deliveries(originals={role: self._public.read(
            endpoint_pins[role], maximum=delivery.MAX_DELIVERY) for role in ENDPOINT_INPUT_ROLES})
        # The real retained owner has now fsynced/read back its empty store.
        # Only this actual result is presented for later Retrieval/v3 or the
        # explicitly selected fresh-ledger/v4 signing;
        # no predicted genesis, second intake, or renewed startup is supplied.
        observations = self._resource_observations()
        observations["nativeActivations"].update(endpoints.activations())
        observations["driverGenerationRecipe"] = recipe
        observations["endpointDeliveries"] = endpoint_pins
        observations["endpointDeliveryResult"] = endpoint_result
        # Actual retained PIDFD/target-executable measurements. The ordinary
        # children are still parked before exec; this is not a running-service
        # identity or independently signed current-key authorization.
        observations["ordinaryPreparationOriginal"] = _text(pilot.ordinary_services.preparation_original())
        observations["ordinaryInitialResourcesOriginal"] = _text(pilot.generation_inputs.initial_resources_original())
        from serverware.native_pilot_service_inputs import FIELDS
        service_inputs = self._exchange("service-originals", observations, FIELDS)
        self._transfers = admit_services(pilot, endpoints=endpoints, originals=self._public, inputs=service_inputs)

        # Configuration and nested credential descriptors retain their existing
        # fixed-path loaders; no private bytes are copied to the pipe channel.
        from serverware.native_pilot_bridge_preparation import BridgePreparation
        self._bridge_preparation = BridgePreparation.claim(pilot)
        preparation_raw = self._bridge_preparation.prepare()
        self._exchange("bridge-runtime", {
            "bridgePreparationOriginal": _text(preparation_raw),
            "ordinaryGenerationGrants": pilot.generation_inputs.grant_sha256s(),
            "endpointLaunches": service_inputs["endpointLaunches"],
            "nativeGrantSha256s": {role: p.sha(transfer.signed_originals()[1] if role == "persistence"
                else transfer._grant_bytes) for role, transfer in self._transfers.items()},
            "bridgeJournal": pilot.bridge_resources.journal_identity(),
            "cohortObservationOriginal": _text(pilot.cohort.original_bytes()),
            "ordinaryParked": pilot.ordinary_services.parked_originals(),
        }, ())
        pilot.prepare_bridge_connections()
        bridge = self._exchange("bridge-delivery", {"activation": pilot.bridge_activation()}, ("launch",))
        self._public.read(bridge["launch"], maximum=32768)
        operation = pilot.prepare_operational_inputs(launch_pin=bridge["launch"], production=self._production)
        release = self._exchange("release", {"operationOriginal": _text(operation.operation_original())},
            ("endpointRelease", "phaseTwoScope", "phaseTwoPublic"))
        from serverware import native_pilot_bridge_runtime as bridge_runtime
        public_maximum = (bridge_runtime.MAX_BRIDGE_INPUT if bridge_runtime.runtime_version(operation._runtime_raw) in (10, 11, 12)
            else 1024 * 1024)
        self._bridge_preparation.consume()
        continuation = pilot.release(operational_inputs=operation,
            endpoint_release_original=self._public.read(release["endpointRelease"], maximum=32768),
            endpoint_transfers=self._transfers,
            phase_two_scope_original=self._public.read(release["phaseTwoScope"], maximum=32768),
            phase_two_public_originals=self._public.read(release["phaseTwoPublic"], maximum=public_maximum))

        exported = driver.prepare_constructed_driver_admission()
        constructed = self._exchange("constructed-admission", {key: _text(raw) for key, raw in exported.items()},
                                     ("constructedAdmission",))
        admission = driver.accept_constructed_driver_admission(
            self._public.read(constructed["constructedAdmission"], maximum=16384))
        origin = self._exchange("generation-origin", {"constructedObservation": continuation,
            "constructedAdmissionSha256": p.sha(admission)}, ("action",), live=True)
        p.require(origin["action"] == "observe-installed-generation")
        # The reply requests an observation, not a supplied installed verdict.
        # Only the existing actual management/independent issuer relay can
        # establish the origin handoff. It gets no new lifetime or cleanup time.
        handoff = pilot.deliver_generation_origin(deadline_boottime_ns=self._deadline(live=True))
        stop = self._exchange("shutdown", {"originHandoff": handoff}, ("action",), live=True)
        if stop["action"] == "run-interactive":
            self._interactive_result = pilot.run_interactive(stop, origin_handoff=handoff,
                deadline_boottime_ns=min(self._deadline(live=True), pilot.running_deadline_boottime_ns()))
        else:
            p.require(stop["action"] == "stop")
        self._finished = True

    def close(self):
        """One cleanup; unknown outcomes retain this entire real object graph."""
        global _LIVE
        if self._closed:
            return
        p.require(_LIVE is self and os.getpid() == self._pid and not self._cleanup_attempted)
        self._cleanup_attempted = True
        try:
            if self._pilot is not None:
                # A startup exception may have already consumed cleanup. Never
                # invoke it again or confuse retained ownership with retirement.
                if self._pilot._cleanup_attempted and not self._pilot._closed:
                    raise ValueError("native pilot cleanup previously attempted")
                self._pilot.close()
            if self._bridge_preparation is not None:
                self._bridge_preparation.close()
            if self._public is not None:
                self._public.close()
            if self._channel is not None:
                self._channel.close()
        except BaseException as failure:
            self._cleanup_failure = failure
            raise
        self._closed = True
        _LIVE = None
