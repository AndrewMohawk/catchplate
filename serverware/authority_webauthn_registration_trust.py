"""Recover the complete attestation context from admitted committed trust rows.

The publication and high-water rows MUST already be independently admitted
state, including the stage's genuine original bundle signature/schema check
and the committed publication transition. This reader does not prove row
membership, pending-publication absence, currentness, or that prior admission.
Without the independent publication signer it cannot repeat that signature
verification, and it neither accepts nor constructs a successful VerifiedBundle.

It rejoins the actual stored canonical bundle and stage-payload commitments,
the high-water counters/digests, and the original evaluation interval. Every
root is recovered from the stored certificate material using the real trust
core, then placed in the actual attestation core types. No caller-selected
root inventory, inferred signing key, filesystem, database, clock, policy
override or replacement work allowance is accepted. Certificate chain/time
and registration evidence verification remain the downstream core's work.
"""
from __future__ import annotations

import re

from serverware import authority_transition_webauthn_completion as completion
from serverware import authority_transition_webauthn_registration as registration
from serverware import webauthn_attestation_core as attestation
from serverware import webauthn_trust_core as bundle_core


evidence, trust = completion.evidence, completion.trust
_BUNDLE_FIELDS = frozenset({"apiVersion", "kind", "metadata", "roots"})
_METADATA_FIELDS = frozenset({"id", "sequence", "rollbackEpoch", "validFrom",
    "signingKeyId", "signature"})
_ROOT_FIELDS = frozenset({"id", "authenticatorClass", "certificatePem"})
_ROOT_OPTIONAL = frozenset({"aaguids", "certificateSha256"})
_AAGUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


class WebAuthnRegistrationTrustError(ValueError):
    pass


def _stored_on_work(value, work):
    """Own the bounded original row JSON; stage writes this exact encoding."""
    if type(value) is not str or not 2 <= len(value) <= bundle_core.MAX_CANONICAL_BYTES:
        raise WebAuthnRegistrationTrustError("committed trust JSON exceeds its source bound")
    work.prepare_utf8(value)
    original = value.encode("utf-8")
    if len(original) > bundle_core.MAX_CANONICAL_BYTES:
        raise WebAuthnRegistrationTrustError("committed trust JSON exceeds its byte bound")
    decoded = completion._decode(original, work, bundle_core.MAX_CANONICAL_BYTES)
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=bundle_core.MAX_CANONICAL_BYTES).visit(decoded)
    canonical = bundle_core._canonical(owned, _work=work)
    work.charge(input_bytes=len(original) + len(canonical))
    if canonical != original:
        raise WebAuthnRegistrationTrustError("committed trust JSON is not its canonical original")
    return original, owned


def _root_fields_on_work(bundle, work):
    """Hold the closed source extraction inventory, not a second verifier."""
    completion._object(bundle, _BUNDLE_FIELDS, "committed trust bundle")
    registration._same((bundle["apiVersion"], bundle["kind"]),
        ("serverware.webauthnTrust/v1", "WebAuthnTrustBundle"), work,
        "committed trust bundle format")
    metadata = bundle["metadata"]
    if (type(metadata) is not dict or not _METADATA_FIELDS <= metadata.keys()
            or metadata.keys() - _METADATA_FIELDS not in (set(), {"validUntil"})):
        raise WebAuthnRegistrationTrustError("committed trust metadata is not source closed")
    registration._text(metadata["id"], "committed bundle ID", bundle_core.MAX_CANONICAL_BYTES, work)
    bundle_core._positive_counter(metadata["sequence"], "sequence")
    bundle_core._positive_counter(metadata["rollbackEpoch"], "rollback epoch")
    bundle_core._digest(metadata["signingKeyId"], "committed signing key")
    # Retain the previously authenticated signature verbatim. Its presence is
    # not a claim that this extraction has independently verified the signer.
    signature = metadata["signature"]
    registration._text(signature, "committed bundle signature", bundle_core.MAX_CANONICAL_BYTES, work)
    if not signature.startswith("ed25519:") or not signature[8:]:
        raise WebAuthnRegistrationTrustError("committed trust signature format changed")
    roots = bundle["roots"]
    if type(roots) is not list or len(roots) > bundle_core.MAX_TRUST_ROOTS:
        raise WebAuthnRegistrationTrustError("committed trust root inventory exceeds its source bound")
    held = []
    for item in roots:
        if (type(item) is not dict or not _ROOT_FIELDS <= item.keys()
                or item.keys() - _ROOT_FIELDS - _ROOT_OPTIONAL):
            raise WebAuthnRegistrationTrustError("committed trust root is not source closed")
        identifier, root_class, pem = item["id"], item["authenticatorClass"], item["certificatePem"]
        registration._text(identifier, "committed root ID", bundle_core.MAX_CANONICAL_BYTES, work)
        registration._text(pem, "committed root certificate", bundle_core.MAX_CANONICAL_BYTES, work)
        if type(root_class) is not str or root_class not in ("yubikey", "hardware", "platform"):
            raise WebAuthnRegistrationTrustError("committed trust root class changed")
        declared_digest = item.get("certificateSha256")
        if "certificateSha256" in item:
            bundle_core._digest(declared_digest, "declared root certificate")
        aaguids = item.get("aaguids", [])
        if type(aaguids) is not list or len(aaguids) > bundle_core.MAX_ROOT_AAGUIDS:
            raise WebAuthnRegistrationTrustError("committed root AAGUID inventory exceeds its source bound")
        work.prepare_scan(aaguids)
        if any(type(value) is not str or re.fullmatch(_AAGUID, value) is None for value in aaguids):
            raise WebAuthnRegistrationTrustError("committed root AAGUID is not source-shaped")
        work.prepare_copy(aaguids)
        frozen_aaguids = frozenset(aaguids)
        if len(frozen_aaguids) != len(aaguids):
            raise WebAuthnRegistrationTrustError("committed root AAGUID inventory repeats an entry")
        held.append((identifier, root_class, pem, declared_digest, frozen_aaguids))
    work.charge(json_nodes=len(held) + 1)
    return tuple(held)


def _context_on_work(*, published_row, high_water_row, rp_id, origin, verified_at, work):
    """Derive actual full-root context from upstream-admitted committed rows.

    The RP, origin and exact original UTC evaluation time are independently
    configured/held inputs. The return is a genuine VerificationContext, not
    evidence of row, publication-signature or current-root admission.
    """
    ledger = evidence.capture._SharedLedger(work)
    evaluation_ns = registration._now(verified_at)
    held_time = verified_at
    owned = evidence.capture._JSONCapture(ledger).visit({"published": published_row,
        "high": high_water_row, "rpId": rp_id, "origin": origin})
    published, high = owned["published"], owned["high"]
    completion._object(published, completion._PUBLICATION_FIELDS, "admitted published trust row")
    completion._object(high, completion._HIGH_WATER_FIELDS, "admitted trust high-water row")
    held_rp, held_origin = owned["rpId"], owned["origin"]
    registration._text(held_rp, "configured RP ID", 4096, work)
    registration._text(held_origin, "configured origin", 8192, work)
    registration._text(published["id"], "published trust row ID", 1024, work)
    registration._same((published["scope"], published["status"], high["authority_scope"]),
        ("global", "published", trust.AUTHORITY_SCOPE), work, "published trust row scope")
    trust.high_water_document(rollback_epoch=high["rollback_epoch"],
        sequence=high["publication_sequence"], publication_digest=high["publication_digest"],
        metadata_blob_digest=high["metadata_blob_digest"], revocation_set_digest=high["revocation_set_digest"],
        witness_receipt_digest=high["witness_receipt_digest"], witness_sequence=high["witness_sequence"])
    for name in ("bundle_digest", "payload_digest", "signing_key_id"):
        bundle_core._digest(published[name], "published " + name)
    if published["previous_bundle_digest"] is not None:
        bundle_core._digest(published["previous_bundle_digest"], "published predecessor")
    sequence = bundle_core._positive_counter(published["sequence"], "published sequence")
    rollback = bundle_core._positive_counter(published["rollback_epoch"], "published rollback epoch")
    registration._integer(high["updated_at_epoch_ns"], "published high-water time", 1)
    registration._same((published["bundle_digest"], published["payload_digest"], sequence, rollback),
        (high["publication_digest"], high["metadata_blob_digest"],
         high["publication_sequence"], high["rollback_epoch"]), work, "published high-water binding")
    # All caller-owned graphs and original JSON/time/configuration references
    # are detached before the first parser, certificate or encoding callback.
    bundle_original, bundle = _stored_on_work(published["bundle_json"], work)
    _, withdrawn = _stored_on_work(published["withdrawn_credential_ids_json"], work)
    _, event = _stored_on_work(published["audit_event_json"], work)
    root_fields = _root_fields_on_work(bundle, work)
    metadata = bundle["metadata"]
    registration._same((metadata["sequence"], metadata["rollbackEpoch"], metadata["signingKeyId"]),
        (sequence, rollback, published["signing_key_id"]), work, "committed bundle metadata")
    created = bundle_core._time(published["created_at"], "publication creation", _work=work)
    completed = bundle_core._time(published["published_at"], "publication completion", _work=work)
    if (created > completed or completed > held_time
            or registration._now(completed) != high["updated_at_epoch_ns"]
            or high["updated_at_epoch_ns"] > evaluation_ns):
        raise WebAuthnRegistrationTrustError("published trust row times differ from admitted high-water")
    valid_from = bundle_core._time(metadata["validFrom"], "validFrom", _work=work)
    valid_until = (bundle_core._time(metadata["validUntil"], "validUntil", _work=work)
        if "validUntil" in metadata else None)
    if held_time < valid_from or valid_until is not None and held_time > valid_until:
        raise WebAuthnRegistrationTrustError("committed trust bundle is not valid at original evaluation time")
    work.prepare_copy(bundle)
    work.prepare_copy(metadata)
    unsigned = {**bundle, "metadata": {key: value for key, value in metadata.items() if key != "signature"}}
    actual_bundle_digest = bundle_core.sha256_prefixed(
        bundle_core._canonical(unsigned, _work=work), _work=work)
    registration._same(actual_bundle_digest, published["bundle_digest"], work,
        "committed original unsigned bundle digest")
    if type(withdrawn) is not list or len(withdrawn) > completion.MAX_STAGED_WITHDRAWAL_IDS:
        raise WebAuthnRegistrationTrustError("committed withdrawal inventory exceeds its source bound")
    previous = None
    for identifier in withdrawn:
        registration._text(identifier, "committed withdrawn credential ID", 1024, work)
        if previous is not None and previous >= identifier:
            raise WebAuthnRegistrationTrustError("committed withdrawal inventory is not sorted and unique")
        previous = identifier
    registration._same(completion._frame("serverware.webauthnRevocationSet/v1", withdrawn, work),
        high["revocation_set_digest"], work, "committed high-water withdrawal digest")
    if type(event) is not dict or "reason" not in event:
        raise WebAuthnRegistrationTrustError("committed stage audit has no original reason")
    reason = event["reason"]
    if reason is not None:
        registration._text(reason, "committed stage reason", 16_384, work)

    roots, root_digests, total = [], [], 0
    for identifier, root_class, pem, declared_digest, aaguids in root_fields:
        work.prepare_utf8(pem)
        certificate = bundle_core._certificate(pem.encode("utf-8"), _work=work)
        der = bundle_core._native(work,
            lambda: certificate.public_bytes(bundle_core.serialization.Encoding.DER))
        bundle_core._bounded_bytes(der, "root certificate", bundle_core.MAX_ROOT_CERTIFICATE_BYTES)
        certificate_digest = bundle_core.sha256_prefixed(der, _work=work)
        if declared_digest is not None:
            registration._same(certificate_digest, declared_digest, work, "committed root certificate digest")
        work.charge(input_bytes=2 + max(0, len(aaguids) - 1), json_nodes=1)
        for value in aaguids:
            work.prepare_copy(value)
        ordered_aaguids = sorted(aaguids)
        descriptor = {"id": identifier, "certificateSha256": certificate_digest,
            "authenticatorClass": root_class, "aaguids": ordered_aaguids,
            "bundleDigest": actual_bundle_digest, "bundleSequence": sequence,
            "bundleRollbackEpoch": rollback}
        total += len(der) + len(bundle_core._canonical(descriptor, _work=work))
        if total > bundle_core.MAX_TRUST_SNAPSHOT_BYTES:
            raise WebAuthnRegistrationTrustError("committed full trust snapshot exceeds its source bound")
        roots.append(attestation.TrustRootSnapshot(der, certificate_digest, root_class,
            aaguids, actual_bundle_digest, sequence, rollback, _work=work))
        root_digests.append(certificate_digest)
    work.prepare_copy(root_digests)
    root_digests.sort()
    mutation_payload = {"bundle_digest": actual_bundle_digest, "sequence": sequence,
        "rollback_epoch": rollback, "current_bundle_digest": published["previous_bundle_digest"],
        "root_certificate_sha256": root_digests, "withdrawn_credential_record_ids": withdrawn,
        "reason": reason}
    registration._same(bundle_core.sha256_prefixed(
        bundle_core._canonical(mutation_payload, _work=work), _work=work),
        published["payload_digest"], work, "committed stage mutation payload digest")
    # Preserve exact stored material through native extraction; the caller's
    # rows were never consulted after their initial complete ownership.
    evidence.capability._canonical(bundle_original, bundle, ledger,
        bundle_core.MAX_CANONICAL_BYTES, evidence.plan.contract.MAX_JSON_NODES)
    work.charge(input_bytes=total, json_nodes=len(roots) + 1)
    return attestation.VerificationContext(held_rp, held_origin, held_time,
        tuple(roots), _work=work)
