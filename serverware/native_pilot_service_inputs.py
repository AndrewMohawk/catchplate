"""One fixed service-originals phase on genuine retained pilot resources.

All authority originals are independently supplied public pins. This module
only invokes existing signature receivers, journal writers and transfer owners
in their required order. It does not sign, release children, manufacture a
grant, reconstruct an owner, or return an admission/readiness verdict.
"""
from __future__ import annotations

from serverware import custody_commitment_inputs as commitment
from serverware import custody_generation_grants as generation
from serverware import custody_spool_inputs as spool
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_proof_cohort_assignment as cohort_profile
from serverware.native_pilot_public_inputs import PublicInputs
from serverware.native_shadow_generation_install_inputs import MAX_RECORD, MAX_RECORDS

FIELDS = (
    "ordinaryDeliveries", "ordinaryGrants", "dispatchGrants", "dispatchNativeGrant",
    "spoolGrants", "nativeSpoolGrants", "endpointDeliveries", "endpointLaunches",
    "persistence", "generationJournal",
)
ENDPOINT_INPUT_ROLES = ("retrieval", "persistence", "trustedTime")
SPOOL_LISTENER_ROLES = (
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit",
)
MAX_SIGNED_ORIGINAL = 65536
MAX_LAUNCH_ORIGINAL = 32768


def _pin(value):
    p.fields(value, ("path", "sha256"))
    delivery._pin(value)


def _pins(value, roles):
    p.fields(value, roles)
    for pin in value.values():
        _pin(pin)


def admit_services(pilot, *, endpoints, originals: PublicInputs, inputs: dict):
    """Consume one closed reply and return the exact ten real endpoint owners.

    A failure leaves the pilot attempt fenced and all actual partial owners
    retained for its cleanup. In particular, the endpoint composite retains
    a PersistenceTransfer even if failure precedes cohort registration. Public
    input descriptors must remain alive until the caller's genuine cleanup.
    """
    from serverware.native_pilot_endpoint_inputs import PilotEndpointInputs
    from serverware.native_pilot_launch import NativePilotLaunch

    p.require(type(pilot) is NativePilotLaunch)
    pilot._origin()
    p.require(pilot._service_inputs_attempted is False)
    pilot._service_inputs_attempted = True  # Before any original read or partial writer.
    p.require(type(originals) is PublicInputs and type(endpoints) is PilotEndpointInputs
        and pilot._endpoint_inputs is endpoints and endpoints._pilot is pilot
        and endpoints._cohort is pilot.cohort)
    pilot._preparing()
    endpoints.check()
    originals.check()
    cohort = pilot.cohort
    p.require(cohort.endpoint_driver_selected() and cohort.effects_selected()
        and tuple(cohort._roles) == cohort_profile.ENDPOINT_ROLES)

    p.fields(inputs, FIELDS)
    _pins(inputs["ordinaryDeliveries"], generation.ROLES)
    _pins(inputs["ordinaryGrants"], generation.ROLES)
    _pins(inputs["dispatchGrants"], commitment.ROLES)
    _pin(inputs["dispatchNativeGrant"])
    _pins(inputs["spoolGrants"], spool.EFFECT_ROLES)
    _pins(inputs["nativeSpoolGrants"], spool.EFFECT_NATIVE)
    _pins(inputs["endpointDeliveries"], ENDPOINT_INPUT_ROLES)
    _pins(inputs["endpointLaunches"], cohort._roles)
    _pins(inputs["persistence"], ("configuration", "genesis", "journal"))
    journal = p.fields(inputs["generationJournal"], ("genesis", "records"))
    _pin(journal["genesis"])
    p.require(type(journal["records"]) is list and len(journal["records"]) <= MAX_RECORDS)
    for pin in journal["records"]:
        _pin(pin)

    ordinary = pilot.generation_inputs
    for role in generation.ROLES:
        ordinary.admit_delivery(role, signed_delivery_original=originals.read(
            inputs["ordinaryDeliveries"][role], maximum=delivery.MAX_DELIVERY))
    for role in generation.ROLES:
        ordinary.admit_grant(role, signed_grant_original=originals.read(
            inputs["ordinaryGrants"][role], maximum=MAX_SIGNED_ORIGINAL))

    # The composite admits these actual C9 originals and initializes the real
    # empty spool-store binding itself. Its returned observation is not used
    # to reconstruct resources or synthesize another grant/genesis.
    endpoints.admit_deliveries(originals={role: originals.read(
        inputs["endpointDeliveries"][role], maximum=delivery.MAX_DELIVERY)
        for role in ENDPOINT_INPUT_ROLES})

    dispatch_native = originals.read(inputs["dispatchNativeGrant"], maximum=MAX_SIGNED_ORIGINAL)
    for role in commitment.ROLES:
        ordinary.seal_dispatch_grant(role, approved_grant_original=originals.read(
            inputs["dispatchGrants"][role], maximum=MAX_SIGNED_ORIGINAL),
            native_grant_original=dispatch_native)
    native_spool = {name: originals.read(pin, maximum=MAX_SIGNED_ORIGINAL)
        for name, pin in inputs["nativeSpoolGrants"].items()}
    # Source-fixed insertion/order: Head(DRS), Cleanup, Current(CSA). All three
    # retain the same seven original bytes, not caller-generated projections.
    for role in spool.EFFECT_ROLES:
        ordinary.seal_spool_grant(role, approved_grant_original=originals.read(
            inputs["spoolGrants"][role], maximum=MAX_SIGNED_ORIGINAL if role == generation.ROLES[0] else 131072),
            native_originals=native_spool)

    launch_pins = inputs["endpointLaunches"]
    for role in cohort._roles:
        # Pins selected by the reply must pass the restricted public reader,
        # even though the purpose owners also open/check the retained launch.
        originals.read(launch_pins[role], maximum=MAX_LAUNCH_ORIGINAL)
    coordinator = pilot.generation_install_inputs
    coordinator.initialize_journal(launch_pin=launch_pins["generationInstall"],
        genesis_original=originals.read(journal["genesis"], maximum=MAX_RECORD),
        record_originals=tuple(originals.read(pin, maximum=MAX_RECORD) for pin in journal["records"]))
    transfers = {"generationInstall": coordinator.retain(launch_pin=launch_pins["generationInstall"])}
    transfers["commitRequest"] = pilot.commit_request_inputs.transfer(launch_pin=launch_pins["commitRequest"])

    persistence = inputs["persistence"]
    transfers.update(endpoints.retain(
        launch_pins={role: launch_pins[role] for role in ENDPOINT_INPUT_ROLES},
        persistence_configuration_original=originals.read(persistence["configuration"], maximum=p.MAX_CONFIG),
        persistence_configuration_sha256=persistence["configuration"]["sha256"],
        genesis_original=originals.read(persistence["genesis"], maximum=16384),
        genesis_sha256=persistence["genesis"]["sha256"],
        journal_original=originals.read(persistence["journal"], maximum=1024),
        journal_sha256=persistence["journal"]["sha256"]))
    for role in SPOOL_LISTENER_ROLES:
        additions = pilot.spool_inputs.additions(role)
        transfers[role] = cohort.retain_activation_fds(role=role, launch_pin=launch_pins[role],
            descriptors=tuple((target, fd) for target, (_, fd) in enumerate(additions, 6)))

    # Do not compare dispatch_native to the outer commitRequest endpoint grant:
    # that endpoint serves LedgerSpool/v2 and pins a distinct CommitRequest
    # companion original. The mandatory existing _require_endpoint_release
    # compares all seven actual transfer grant originals, opens that companion
    # pin, and joins both dispatch owners before the one cohort send. It also
    # verifies the actual later OperationalInputs bridge scope/FDs; that full
    # join cannot be substituted or claimed complete at this earlier phase.
    p.fields(transfers, cohort._roles)
    pilot._preparing()
    endpoints.check()
    originals.check()
    return {role: transfers[role] for role in cohort._roles}
