"""Original signed trust-bundle admission for the private stage composer.

The public-key DER, measured schema and verification instant are independently
admitted inputs. A real signature/schema/certificate computation happens here;
no caller-provided verification result or root policy is accepted. Returned
arguments and classifier roots are ordinary observations, not a transferable
proof, authenticated request, current database root, or permission to stage.

Original bundle bytes may differ from their canonical envelope (for example,
the core's pretty installation format). The canonical decoded signed envelope,
not a replacement encoding of the original transport, is joined to the staged
argument graph. All source-visible work uses the original meter. Bounded native
JSON/schema/X509/Ed25519 internals retain the core's separate native boundary.
No clock, database, filesystem, configuration lookup or registry is introduced.
"""
from __future__ import annotations

from datetime import datetime, timezone

from catchplate import authority_transition_webauthn_trust_stage as stage
from catchplate import webauthn_trust_core as bundle_core


class WebAuthnTrustCandidateError(ValueError):
    pass


def _require_valid_at_on_work(*, arguments, verified_at, work):
    """Recheck supplied joined metadata at a later independently admitted time.

    This deliberately does not verify a signature or accept a proof token.
    The owning path must first derive these owned arguments with _admit_on_work.
    Preserve the core's inclusive validUntil boundary; do not retime metadata.
    """
    stage.capture._SharedLedger(work)
    if (type(arguments) is not dict or type(arguments.get("bundle")) is not dict
            or type(verified_at) is not datetime or verified_at.tzinfo is not timezone.utc):
        raise WebAuthnTrustCandidateError("candidate validity needs exact owned arguments and UTC time")
    metadata = arguments["bundle"].get("metadata")
    if type(metadata) is not dict:
        raise WebAuthnTrustCandidateError("candidate validity metadata is not an exact object")
    valid_from = bundle_core._time(metadata.get("validFrom"), "validFrom", _work=work)
    valid_until = (bundle_core._time(metadata["validUntil"], "validUntil", _work=work)
        if "validUntil" in metadata else None)
    if verified_at < valid_from or valid_until is not None and verified_at > valid_until:
        raise WebAuthnTrustCandidateError("candidate bundle is not valid at the independently admitted cutoff")


def _root_policy(root, bundle_digest, sequence, work):
    """Derive a deterministic classifier descriptor from the actual result."""
    # The real verifier owns this immutable root and already bounds its exact
    # frozenset. Reserve the variable list copy before materializing it; sorting
    # preserves literal case/spelling and changes no set-membership semantics.
    work.charge(input_bytes=2 + max(0, len(root.aaguids) - 1), json_nodes=1)
    aaguids = []
    for value in root.aaguids:
        work.prepare_copy(value)
        aaguids.append(value)
    work.prepare_copy(aaguids)
    work.prepare_copy(aaguids)
    ordered = tuple(sorted(aaguids))
    # RootTrustPolicy actually validates/encodes each text field. Its ordinary
    # constructor supplies no cryptographic or selected-row authority.
    for value in (root.id, root.certificate_sha256, root.authenticator_class, bundle_digest):
        work.prepare_utf8(value)
    for value in ordered:
        work.prepare_utf8(value)
    return stage.classifier.RootTrustPolicy(root.id, root.certificate_sha256,
        root.authenticator_class, ordered, bundle_digest, sequence)


def _admit_on_work(*, arguments, bundle_bytes, verification_context,
        expected_signing_key_id, work):
    """Return owned staged arguments and roots derived by genuine verification."""
    ledger = stage.capture._SharedLedger(work)
    if (type(bundle_bytes) is not bytes or not 1 <= len(bundle_bytes) <= bundle_core.MAX_INPUT_BYTES
            or type(verification_context) is not bundle_core.TrustVerificationContext):
        raise WebAuthnTrustCandidateError("candidate admission needs original bytes and an exact core context")
    # Hold all context members before any native/key callback. The original
    # frozen dataclass can still be deliberately rebound by its caller.
    public_key_der = verification_context.public_key_der
    schema_bytes = verification_context.schema_bytes
    verified_at = verification_context.verified_at
    if (type(public_key_der) is not bytes or not 1 <= len(public_key_der) <= bundle_core.MAX_PUBLIC_KEY_BYTES
            or type(schema_bytes) is not bytes or not 1 <= len(schema_bytes) <= bundle_core.MAX_SCHEMA_BYTES
            or type(verified_at) is not datetime or verified_at.tzinfo is not timezone.utc):
        raise WebAuthnTrustCandidateError("candidate context members are not bounded immutable inputs")
    bundle_core._digest(expected_signing_key_id, "independent candidate signing key")
    owned = stage.capture._JSONCapture(ledger,
        maximum_bytes=stage.authority.MAX_REQUEST_BYTES).visit(arguments)
    stage._arguments(owned, work)
    # Bind the actual independent DER before native key parsing or verification.
    observed_key_id = bundle_core.sha256_prefixed(public_key_der, _work=work)
    stage._same(observed_key_id, expected_signing_key_id, work,
        "candidate key DER differs from the independent signing-key pin")
    context = bundle_core.TrustVerificationContext(public_key_der, schema_bytes, verified_at, _work=work)
    verified = bundle_core.verify_bundle(bundle_bytes, context, _work=work)
    # This extra actual decode is charged. It exposes no successful result DTO
    # input, and never reconstructs the original transport before verification.
    decoded = verified.bundle_dict(_work=work)
    stage._same(decoded, owned["bundle"], work,
        "staged bundle differs from the genuinely verified canonical envelope")
    for actual, expected in ((verified.bundle_digest, owned["bundle_digest"]),
            (verified.sequence, owned["sequence"]), (verified.rollback_epoch, owned["rollback_epoch"]),
            (verified.signing_key_id, owned["signing_key_id"]),
            (verified.signing_key_id, expected_signing_key_id)):
        if type(actual) is not type(expected):
            raise WebAuthnTrustCandidateError("candidate verified metadata scalar type changed")
        stage._same(actual, expected, work, "candidate verified metadata differs from staged arguments")
    work.charge(input_bytes=2 + max(0, len(verified.roots) - 1), json_nodes=1)
    roots = tuple(_root_policy(root, verified.bundle_digest, verified.sequence, work)
        for root in verified.roots)
    return owned, roots
