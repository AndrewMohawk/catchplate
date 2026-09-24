"""Original signed installation evidence from the real completion checks.

The caller must own the physical installation and readback, independently admit
the committed aggregate-stage/root ancestry and exact current publication /
high-water rows, and supply its configured target, signing pins and observation
time. This worker does not install, read files, fsync, activate a runtime, prove
those admissions, or acquire permission from supplied bytes. It performs the
same original-byte semantic checks as the actual completion consumer before
deriving and signing its fixed v2 claims. No claims or successful-proof DTO is
accepted as input.

The original evidence and final completion arguments are ordinary outputs, not
durable custody, publication permission or an execution receipt. The owner
must still retain/admit the exact v2 evidence row and execute the genuine
four-effect completion transition with common capacity and root proofs. There
is no database, filesystem, clock, configuration lookup, retry or registry
activation here. All source-visible work uses the supplied allowance; native
parser/crypto internals retain their existing explicit resource exclusions.
"""
from __future__ import annotations

from serverware import authority_transition_webauthn_completion as completion


authority, core, evidence = completion.authority, completion.core, completion.evidence


class WebAuthnInstallationProductionError(ValueError):
    pass


def _prepare_result(claims, arguments, identity, signer_pin, observed_ns, expires_ns, work):
    """Reserve the real post-sign identity hash using only fixed-width sizing.

    No placeholder is verified, retained or returned. The actual business-intent
    normalizer runs before signing; only its fixed-width evidence-digest leaf
    and the matching top-level leaf are replaced with the original's real ID.
    Completion arguments do not duplicate the original envelope in base64.
    """
    placeholder = {"schema": evidence.SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": "trust-installation", "signerIdentity": identity,
        "signerSpkiDigest": signer_pin, "issuedAtEpochNs": observed_ns,
        "expiresAtEpochNs": expires_ns, "claims": claims, "signatureBase64Url": "A" * 86}
    evidence._shape(placeholder)
    size, nodes = work.measure(placeholder)
    if size > evidence.MAX_EVIDENCE_BYTES or nodes > evidence.MAX_EVIDENCE_NODES:
        raise WebAuthnInstallationProductionError("installation evidence exceeds its source output bounds")
    work.charge(input_bytes=71)
    arguments["verification_evidence_digest"] = "sha256:" + "0" * 64
    arguments["businessIntent"] = authority._synthesize_business_intent(completion.OPERATION, arguments, work=work)
    completion._object(arguments, completion._ARGUMENT_FIELDS, "produced completion arguments")
    completion._text(arguments["publication_id"], "produced publication ID")
    core.require_digest(arguments["verification_evidence_digest"], "prepared evidence identity")
    final_size, _ = work.measure(arguments)
    if final_size > authority.MAX_REQUEST_BYTES:
        raise WebAuthnInstallationProductionError("completion arguments exceed the existing request bound")
    # Exact existing framed-digest recipe: actual domain encoding, delimiter,
    # one BE64 frame length and all original bytes. Reserve before the signer.
    work.prepare_utf8(evidence.IDENTITY_DOMAIN)
    work.charge(hashes=1, input_bytes=9 + size)
    return size


def _produce_on_work(*, installed_bundle_bytes, installed_state_bytes,
        publication_row, high_water_row, expected_committed_stage,
        installation_target_digest, observed_at, private_key, public_key,
        signer_identity, signer_spki_digest, maximum_age_ns, work):
    """Return (actual signed installation original, final complete arguments)."""
    ledger = evidence.capture._SharedLedger(work)
    observed_ns = completion._now(observed_at)
    evidence.plan.contract._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    expires_ns = observed_ns + maximum_age_ns
    completion._integer(expires_ns, "installation evidence expiry", 1)
    evidence.plan.contract._digest(signer_spki_digest)
    identity = evidence.capture._JSONCapture(ledger).visit(signer_identity)
    evidence._identity(identity)
    claims, publication, _, _, _, _ = completion._installation_claims_on_work(
        installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
        publication_row=publication_row, high_water_row=high_water_row,
        expected_committed_stage=expected_committed_stage, installation_target_digest=installation_target_digest,
        observed_at=observed_at, work=work)
    arguments = {"publication_id": publication["id"]}
    size = _prepare_result(claims, arguments, identity, signer_spki_digest, observed_ns, expires_ns, work)
    original = evidence._produce_on_work(purpose="trust-installation", claims=claims,
        private_key=private_key, public_key=public_key, signer_identity=identity,
        signer_spki_digest=signer_spki_digest, issued_at_epoch_ns=observed_ns,
        expires_at_epoch_ns=expires_ns, work=work)
    if type(original) is not bytes or len(original) != size:
        raise WebAuthnInstallationProductionError("installation evidence differs from its prepared source shape")
    # This genuine original-byte hash was prepaid above. The shared signer
    # already performs its actual signature codec; there is no second encoding.
    digest = core.framed_digest(evidence.IDENTITY_DOMAIN, original)
    arguments["verification_evidence_digest"] = digest
    arguments["businessIntent"]["arguments"]["verification_evidence_digest"] = digest
    return original, arguments
