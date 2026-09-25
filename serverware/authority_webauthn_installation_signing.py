"""Fixed original installation evidence under its explicit admitted purpose.

The independent installer owner must admit the actual physical installation
and durable readback, committed stage/fence/witness ancestry, exact pending
publication and predecessor high-water rows, and original observation time.
It also supplies genuine root-admitted configuration/generation/runtime
cohort and its separately admitted evidence private key and signer identity.
This mapper checks their consistency; dictionaries or key possession do not
establish those admissions, fsync, activation or committed-stage authority.

All mutable input/configuration graphs and original references are held before
native configuration/key callbacks. Only the explicit installation purpose
selects the public key, identity, SPKI, target and lifetime. There is no role-key
fallback, per-request policy override, clock, filesystem, SQL, socket, public
route, new signer process, retry or replacement work allowance. The real
producer verifies original-byte semantics and signs; the actual input codec
retains the same original time and full independently admitted stage graph.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_configuration as read_configuration
from serverware import authority_webauthn_evidence_policy as policy
from serverware import authority_webauthn_installation_production as production


authority, evidence, completion = production.authority, production.evidence, production.completion


class WebAuthnInstallationSigningError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, evidence_private_key, evidence_signer_identity,
        installed_bundle_bytes, installed_state_bytes, publication_row,
        high_water_row, expected_committed_stage, observed_at, work):
    """Return signed envelope, completion arguments, evidence request and inputs.

    These ordinary outputs retain original installation provenance supplied by
    the owning caller; they do not create it or grant custody/execution rights.
    No claims, successful proof DTO, installer public key, target, identity
    override, lifetime override or alternate purpose is accepted.
    """
    ledger = evidence.capture._SharedLedger(work)
    originals = installed_bundle_bytes, installed_state_bytes
    for raw, maximum in zip(originals, (completion.bundle_core.MAX_INSTALLATION_BYTES,
            completion.bundle_core.MAX_STATE_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnInstallationSigningError("installation signing requires bounded original bytes")
    signer, instant, digest = evidence_private_key, observed_at, configuration_digest
    if not isinstance(signer, evidence.keys.Ed25519PrivateKey):
        raise WebAuthnInstallationSigningError("independent installation evidence signer must be Ed25519")
    evidence.plan.contract._digest(digest)
    completion._now(instant)
    owned_inputs = evidence.capture._JSONCapture(ledger).visit({
        "publication": publication_row, "highWater": high_water_row,
        "stage": expected_committed_stage, "signerIdentity": evidence_signer_identity})
    owned_configuration = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    evidence._identity(owned_inputs["signerIdentity"])
    # All caller graphs and exact scalar/key references are now private or
    # immutable. Genuine mapper callbacks cannot reopen caller containers.
    captured, launch = configuration._capture_configuration_on_work(
        payload=owned_configuration, configuration_digest=digest,
        generation=owned_generation, work=work)
    configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=owned_runtime, owned_payload=captured,
        configuration_digest=digest, launch=launch, work=work)
    roles = captured["roles"]
    if type(roles) is not dict or type(roles.get("planner")) is not dict:
        raise WebAuthnInstallationSigningError("installation signing requires its enabled planner policy")
    evidence.plan.contract._literal(roles["planner"]["processMode"], "policy-authority-planner")
    read_configuration._require_enabled_operation(
        roles["planner"], "webauthn.trust.installation.admit", work)
    if policy.FIELD not in captured:
        raise WebAuthnInstallationSigningError("installation evidence signing has no explicit purpose policy")
    purposes, public_keys = policy._validate_policy_on_work(
        captured[policy.FIELD], webauthn=captured["webauthn"], work=work)
    selected = purposes["installation"]
    if selected is None:
        raise WebAuthnInstallationSigningError("installation evidence signing is disabled")
    # These are the independently configured installation-purpose pins, not
    # the runtime cohort's generic verifier/planner keys or an inferred target.
    expected_identity = selected["signerIdentity"]
    public_key, signer_spki = public_keys["installation"], selected["signingSpkiDigest"]
    target, maximum_age_ns = selected["installationTargetDigest"], selected["maximumAgeNs"]
    completion._same(owned_inputs["signerIdentity"], expected_identity,
        work, "independent installer identity differs from its admitted evidence purpose")
    evidence.keys._pair_on_work(signer, public_key, work)
    original, arguments = production._produce_on_work(
        installed_bundle_bytes=originals[0], installed_state_bytes=originals[1],
        publication_row=owned_inputs["publication"], high_water_row=owned_inputs["highWater"],
        expected_committed_stage=owned_inputs["stage"], installation_target_digest=target,
        observed_at=instant, private_key=signer, public_key=public_key,
        signer_identity=expected_identity, signer_spki_digest=signer_spki,
        maximum_age_ns=maximum_age_ns, work=work)
    final_arguments = evidence.capture._JSONCapture(ledger).visit(arguments)

    # Use the actual codec and typed-request commitment assembler. The full
    # stage graph remains an upstream-admitted input, not inferred history.
    from serverware import authority_webauthn_evidence_invocation as invocation

    request, inputs_bytes = invocation._installation_on_work(
        installation_envelope_bytes=original, installed_bundle_bytes=originals[0],
        installed_state_bytes=originals[1], observed_at=instant,
        expected_committed_stage=owned_inputs["stage"],
        publication_row=owned_inputs["publication"], work=work)
    return original, final_arguments, request, inputs_bytes
