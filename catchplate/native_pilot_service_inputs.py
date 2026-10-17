"""One fixed service-originals phase on genuine retained pilot resources.

All authority originals are independently supplied public pins. This module
only invokes existing signature receivers, journal writers and transfer owners
in their required order. It does not sign, release children, manufacture a
grant, reconstruct an owner, or return an admission/readiness verdict.
"""
from __future__ import annotations

from catchplate import custody_commitment_inputs as commitment
from catchplate import custody_generation_grants as generation
from catchplate import custody_spool_inputs as spool
from catchplate import custody_publication_inputs as publication
from catchplate import native_pilot_adopted_service_authority as adopted_authority
from catchplate import native_pilot_native_service_authority as native_authority
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_nitro_profile as p
from catchplate import native_shadow_proof_cohort_assignment as cohort_profile
from catchplate.native_pilot_public_inputs import PublicInputs
from catchplate.native_shadow_generation_install_inputs import MAX_RECORD, MAX_RECORDS

FIELDS = (
    "ordinaryDeliveries", "ordinaryGrants", "dispatchGrants", "dispatchNativeGrant",
    "spoolGrants", "nativeSpoolGrants", "endpointLaunches",
    "persistence", "generationJournal",
)
ENDPOINT_INPUT_ROLES = ("retrieval", "persistence", "trustedTime")
ADOPTED_ENDPOINT_INPUT_ROLES = ENDPOINT_INPUT_ROLES + ("publicationReconciliation",)
ADOPTED_FIELDS = FIELDS + ("publicationGrants", "nativePublicationGrant", "persistenceServiceInput")
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


def input_shape(inputs, *, adopted=False):
    """Closed public reply pins, not signatures or live owner admission."""
    p.require(type(adopted) is bool)
    roles = cohort_profile.ADOPTED_ENDPOINT_ROLES if adopted else cohort_profile.ENDPOINT_ROLES
    p.fields(inputs, ADOPTED_FIELDS if adopted else FIELDS)
    _pins(inputs["ordinaryDeliveries"], generation.ROLES)
    _pins(inputs["ordinaryGrants"], generation.ROLES)
    _pins(inputs["dispatchGrants"], commitment.ROLES)
    _pin(inputs["dispatchNativeGrant"])
    _pins(inputs["spoolGrants"], spool.EFFECT_ROLES)
    _pins(inputs["nativeSpoolGrants"], spool.EFFECT_NATIVE)
    _pins(inputs["endpointLaunches"], roles)
    _pins(inputs["persistence"], ("configuration", "genesis", "journal"))
    journal = p.fields(inputs["generationJournal"], ("genesis", "records"))
    _pin(journal["genesis"])
    p.require(type(journal["records"]) is list and len(journal["records"]) <= MAX_RECORDS)
    for pin in journal["records"]:
        _pin(pin)
    if adopted:
        _pins(inputs["publicationGrants"], publication.ROLES)
        _pin(inputs["nativePublicationGrant"])
        _pin(inputs["persistenceServiceInput"])
    return inputs


def admit_services(pilot, *, endpoints, originals: PublicInputs, inputs: dict):
    """Consume the legacy closed reply; never infer an adopted lane from data."""
    return _admit_services(pilot, endpoints=endpoints, originals=originals, inputs=inputs, adopted=False)


def admit_adopted_services(pilot, *, endpoints, originals: PublicInputs, inputs: dict):
    """Seal adopted publications and return all eleven genuine endpoint owners."""
    return _admit_services(pilot, endpoints=endpoints, originals=originals, inputs=inputs, adopted=True)


def _admit_services(pilot, *, endpoints, originals, inputs, adopted):
    """Consume one closed reply on the explicitly selected actual owner lane.

    A failure leaves the pilot attempt fenced and all actual partial owners
    retained for its cleanup. In particular, the endpoint composite retains
    a PersistenceTransfer even if failure precedes cohort registration. Public
    input descriptors must remain alive until the caller's genuine cleanup.
    """
    from catchplate.native_pilot_endpoint_inputs import PilotEndpointInputs
    from catchplate.native_pilot_launch import NativePilotLaunch

    p.require(type(pilot) is NativePilotLaunch)
    pilot._origin()
    p.require(pilot._service_inputs_attempted is False)
    pilot._service_inputs_attempted = True  # Before any original read or partial writer.
    p.require(type(originals) is PublicInputs and type(endpoints) is PilotEndpointInputs
        and pilot._endpoint_inputs is endpoints and endpoints._pilot is pilot
        and endpoints._cohort is pilot.cohort)
    pilot._preparing()
    endpoints.check()
    # The previous endpoint-deliveries phase has already consumed its one
    # intake and physically initialized the actual spool. Never re-admit here
    # or accept a caller's observation in place of that retained owner state.
    p.require(endpoints._delivery_attempted and not endpoints._retain_attempted)
    endpoint_roles = ADOPTED_ENDPOINT_INPUT_ROLES if adopted else ENDPOINT_INPUT_ROLES
    p.require(endpoints._adopted == adopted and endpoints._roles == endpoint_roles)
    p.fields(endpoints._deliveries, endpoint_roles)
    p.fields(endpoints._guests, endpoint_roles)
    p.fields(endpoints._spool_journal, ("genesisSha256", "sequence", "headSha256"))
    originals.check()
    cohort = pilot.cohort
    p.require(cohort.endpoint_driver_selected() and cohort.effects_selected()
        and cohort.adoption_selected() == adopted
        and tuple(cohort._roles) == (cohort_profile.ADOPTED_ENDPOINT_ROLES if adopted else cohort_profile.ENDPOINT_ROLES)
        and pilot.generation_inputs._adoption == adopted
        and (pilot._received_core is not None) == adopted)

    input_shape(inputs, adopted=adopted)
    journal = inputs["generationJournal"]

    ordinary = pilot.generation_inputs
    for role in generation.ROLES:
        ordinary.admit_delivery(role, signed_delivery_original=originals.read(
            inputs["ordinaryDeliveries"][role], maximum=delivery.MAX_DELIVERY))
    for role in generation.ROLES:
        ordinary.admit_grant(role, signed_grant_original=originals.read(
            inputs["ordinaryGrants"][role], maximum=MAX_SIGNED_ORIGINAL))

    dispatch_native = originals.read(inputs["dispatchNativeGrant"], maximum=native_authority.MAX_OUTPUT)
    native_authority.grant_original("commitRequest", dispatch_native)
    for role in commitment.ROLES:
        ordinary.seal_dispatch_grant(role, approved_grant_original=originals.read(
            inputs["dispatchGrants"][role], maximum=MAX_SIGNED_ORIGINAL),
            native_grant_original=dispatch_native)
    native_spool = {name: originals.read(pin, maximum=adopted_authority.PROFILES["retrieval"][3]
        if adopted and name == "retrieval" else native_authority.MAX_OUTPUT)
        for name, pin in inputs["nativeSpoolGrants"].items()}
    for name, raw in native_spool.items():
        native_authority.grant_original(name, raw)
    # Source-fixed insertion/order: Head(DRS), Cleanup, Current(CSA). All three
    # retain the same seven original bytes, not caller-generated projections.
    for role in spool.EFFECT_ROLES:
        ordinary.seal_spool_grant(role, approved_grant_original=originals.read(
            inputs["spoolGrants"][role], maximum=MAX_SIGNED_ORIGINAL if role == generation.ROLES[0] else 131072),
            native_originals=native_spool)

    if adopted:
        native_publication = originals.read(inputs["nativePublicationGrant"],
            maximum=adopted_authority.PROFILES["publication"][3])
        adopted_authority.grant_original("publication", native_publication)
        # DRS must be sealed first: CSA's genuine receiver joins its retained
        # durable predecessor, literal native/retrieval grants and original caps.
        for role in publication.ROLES:
            pilot.seal_publication_grant(role, approved_grant_original=originals.read(
                inputs["publicationGrants"][role], maximum=publication.MAX_GRANT),
                native_original=native_publication, retrieval_original=native_spool["retrieval"])
        publication.release_current(ordinary)

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
        launch_pins={role: launch_pins[role] for role in endpoint_roles},
        persistence_configuration_original=originals.read(persistence["configuration"], maximum=p.MAX_CONFIG),
        persistence_configuration_sha256=persistence["configuration"]["sha256"],
        genesis_original=originals.read(persistence["genesis"], maximum=16384),
        genesis_sha256=persistence["genesis"]["sha256"],
        journal_original=originals.read(persistence["journal"], maximum=1024),
        journal_sha256=persistence["journal"]["sha256"],
        **({"persistence_service_input_original": originals.read(inputs["persistenceServiceInput"],
            maximum=adopted_authority.MAX_INPUT)} if adopted else {})))
    if adopted:
        p.require(transfers["publicationReconciliation"]._grant_bytes == native_publication)
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
