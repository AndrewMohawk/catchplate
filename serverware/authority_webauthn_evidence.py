"""Original-byte signatures for successor WebAuthn evidence claims.

These private mechanics authenticate the two fixed evidence purposes against
independently supplied key, identity, claim and time expectations. They do not
admit those expectations, authorize a registration or installation, or register
a transition. In particular, signing an arbitrary claims object does not prove
that installation or attestation occurred. Actual purpose-specific composers
must derive the claims from their real operations before calling the signer.

The complete original envelope has an acyclic identity: neither its signature
nor its resulting evidence digest occurs in the signed claims. Callers must
preserve that property in their purpose-specific schemas. Verification returns
no authority token. All work uses the original allowance; no clock, database,
key lookup, registry bypass, or legacy receipt interpretation is introduced.
The v2 custody projection uses the existing table's seventeen columns; only an
independently admitted persistence/root owner may install it. Consumption is a
returned row effect, never a database write or a substitute for proof admission.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_contract as authority
from serverware import authority_revocation_writer_acknowledgment as keys


plan, capability, production = keys.plan, keys.capability, keys.production
capture, wire = keys.capture, keys.wire
SCHEMA = "serverware.policyAuthorityWebAuthnEvidence/v1"
SIGNATURE_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceSignature/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceIdentity/v1"
STATEMENT_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceStatement/v2"
DETACHED_SIGNATURE_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceDetachedSignature/v2"
BINDING_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceBinding/v2"
EVIDENCE_TABLE = "policy_authority_external_evidence_receipts"
MAX_EVIDENCE_BYTES = authority.MAX_REQUEST_BYTES
MAX_EVIDENCE_NODES = 4096
MAX_EVIDENCE_DEPTH = 16
_CLAIM_SCHEMAS = {
    "registration-attestation": "serverware.policyAuthorityWebAuthnRegistrationAttestation/v2",
    "trust-installation": "serverware.policyAuthorityWebAuthnTrustInstallation/v2",
}
_IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "signerIdentity", "signerSpkiDigest",
    "issuedAtEpochNs", "expiresAtEpochNs", "claims", "signatureBase64Url"})
_CUSTODY_PURPOSES = {
    "registration-attestation": ("webauthn-registration-attestation/v2", "webauthn.registration.finalize"),
    "trust-installation": ("webauthn-trust-installation/v2", "webauthn.trust.complete"),
}
# Exact existing SQL layout: seventeen columns, without a new proof/status DTO.
EVIDENCE_ROW_FIELDS = frozenset({"evidence_digest", "evidence_type", "statement_json", "statement_digest",
    "verifier_identity_digest", "verifier_measurement_digest", "verifier_attestation_receipt_digest",
    "signature_algorithm", "signature_base64url", "signature_digest", "binding_digest", "status",
    "verified_at_epoch_ns", "expires_at_epoch_ns", "consumed_operation_id", "consumed_at_epoch_ns",
    "source_revision"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class WebAuthnEvidenceError(ValueError):
    pass


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_EVIDENCE_DEPTH or self.nodes >= MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence exceeds its local structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence exceeds its node bound")
        return result


def _identity(value):
    plan.contract._object(value, _IDENTITY_FIELDS, "WebAuthn evidence signer identity")
    for field in _IDENTITY_FIELDS:
        plan.contract._digest(value[field])


def _claims(value, purpose):
    if type(purpose) is not str or purpose not in _CLAIM_SCHEMAS:
        raise WebAuthnEvidenceError("WebAuthn evidence purpose is not supported")
    if type(value) is not dict:
        raise WebAuthnEvidenceError("WebAuthn evidence claims are not an exact object")
    plan.contract._literal(value.get("schema"), _CLAIM_SCHEMAS[purpose])
    # The fixed consumer owns the complete purpose-specific field set. This
    # shared layer checks the domain and whole-graph equality, not semantics.


def _shape(envelope):
    plan.contract._object(envelope, _FIELDS, "WebAuthn evidence envelope")
    plan.contract._literal(envelope["schema"], SCHEMA)
    plan.contract._literal(envelope["sourceRevision"], authority.SOURCE_REVISION)
    _claims(envelope["claims"], envelope["purpose"])
    _identity(envelope["signerIdentity"])
    plan.contract._digest(envelope["signerSpkiDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        plan.contract._integer(envelope[field], minimum=1)
    lifetime = envelope["expiresAtEpochNs"] - envelope["issuedAtEpochNs"]
    if not 0 < lifetime <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnEvidenceError("WebAuthn evidence validity interval is outside source bounds")
    plan.contract._base64url(envelope["signatureBase64Url"], signature=True)


def _fresh(envelope, now_epoch_ns, maximum_age_ns, maximum_clock_skew_ns):
    plan.contract._integer(now_epoch_ns, minimum=1)
    plan.contract._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    plan.contract._integer(maximum_clock_skew_ns, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    issued, expires = envelope["issuedAtEpochNs"], envelope["expiresAtEpochNs"]
    if (issued > now_epoch_ns + maximum_clock_skew_ns
            or now_epoch_ns - issued > maximum_age_ns or now_epoch_ns >= expires
            or expires - issued > maximum_age_ns):
        raise WebAuthnEvidenceError("WebAuthn evidence is outside independently configured freshness")


def _decode_on_work(envelope_bytes, work):
    """Decode canonical original data only; this is not authentication."""
    ledger = capture._SharedLedger(work)
    envelope = wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=MAX_EVIDENCE_BYTES, maximum_nodes=MAX_EVIDENCE_NODES,
        maximum_depth=MAX_EVIDENCE_DEPTH)
    _shape(envelope)
    capability._canonical(envelope_bytes, envelope, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
    return envelope


def _evidence_digest_on_work(envelope_bytes, work):
    """Commit original bytes without granting their claims any authority."""
    capture._SharedLedger(work)
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= MAX_EVIDENCE_BYTES:
        raise WebAuthnEvidenceError("WebAuthn evidence identity requires bounded original bytes")
    return plan._frame(IDENTITY_DOMAIN, (envelope_bytes,), work)


def _produce_on_work(*, purpose, claims, private_key, public_key, signer_identity,
        signer_spki_digest, issued_at_epoch_ns, expires_at_epoch_ns, work):
    """Sign owned claims; semantic production and signer admission are external."""
    try:
        ledger = capture._SharedLedger(work)
        _claims(claims, purpose)
        _identity(signer_identity)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise WebAuthnEvidenceError("WebAuthn evidence signer is not Ed25519")
        unsigned = _Capture(ledger, maximum_bytes=MAX_EVIDENCE_BYTES).visit({
            "schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "purpose": purpose,
            "signerIdentity": signer_identity, "signerSpkiDigest": signer_spki_digest,
            "issuedAtEpochNs": issued_at_epoch_ns, "expiresAtEpochNs": expires_at_epoch_ns,
            "claims": claims})
        placeholder = {**unsigned, "signatureBase64Url": "A" * 86}
        _shape(placeholder)
        keys._public_binding(public_key, signer_spki_digest, work)
        keys._pair_on_work(private_key, public_key, work)
        unsigned_bytes = capability._wire(unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned_bytes,), work), work)
        final_size, final_nodes = work.measure(placeholder)
        if final_size > MAX_EVIDENCE_BYTES or final_nodes > MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence signed output exceeds its bound")
        unsigned_size, unsigned_nodes = work.measure(unsigned)
        # Reserve the actual post-callback encoder/comparison and final output
        # before signing. Native Ed25519 internals keep their existing exclusion.
        work.charge(input_bytes=3 * unsigned_size + final_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=unsigned_nodes + final_nodes)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if plan.core.canonical_bytes(unsigned) != unsigned_bytes:
            raise WebAuthnEvidenceError("WebAuthn evidence claims changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        plan.contract._base64url(encoded, signature=True)
        original = plan.core.canonical_bytes({**unsigned, "signatureBase64Url": encoded})
        if len(original) != final_size:
            raise WebAuthnEvidenceError("WebAuthn evidence final output changed")
        return original
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("WebAuthn evidence signing failed") from exc


def _verify_on_work(*, envelope_bytes, purpose, expected_claims, public_key,
        expected_signer_identity, expected_signer_spki_digest, now_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Actually verify original bytes and complete independent claims; no token."""
    try:
        ledger = capture._SharedLedger(work)
        _claims(expected_claims, purpose)
        _identity(expected_signer_identity)
        plan.contract._digest(expected_signer_spki_digest)
        expected = _Capture(ledger, maximum_bytes=MAX_EVIDENCE_BYTES).visit({
            "claims": expected_claims, "signerIdentity": expected_signer_identity})
        envelope = _decode_on_work(envelope_bytes, work)
        _fresh(envelope, now_epoch_ns, maximum_age_ns, maximum_clock_skew_ns)
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        encoded_signature = unsigned.pop("signatureBase64Url")
        unsigned_bytes = capability._wire(unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        keys._public_binding(public_key, expected_signer_spki_digest, work)
        capability._signature(public_key, encoded_signature, SIGNATURE_DOMAIN, unsigned_bytes, ledger)
        capability._canonical(unsigned_bytes, unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        capability._canonical(envelope_bytes, envelope, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        plan._same((unsigned["purpose"], unsigned["signerSpkiDigest"], unsigned["signerIdentity"], unsigned["claims"]),
            (purpose, expected_signer_spki_digest, expected["signerIdentity"], expected["claims"]), work,
            "WebAuthn evidence differs from independently pinned purpose, signer or claims")
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("WebAuthn evidence verification failed") from exc


def _custody_purpose(purpose):
    if type(purpose) is not str or len(purpose) > 64 or purpose not in _CUSTODY_PURPOSES:
        raise WebAuthnEvidenceError("WebAuthn custody purpose has no source consumer")
    return _CUSTODY_PURPOSES[purpose]


def _verified_row_on_work(*, envelope_bytes, purpose, expected_claims, public_key,
        expected_signer_identity, expected_signer_spki_digest, now_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Reverify originals and derive the existing table's exact v2 row.

    This ordinary projection neither writes the row nor admits a measured
    producer, selected-row proof, signer configuration or current root. A real
    persistence owner must establish all of those independently. V1 generic
    evidence semantics must never interpret these purpose-specific v2 rows.

    ``statement_json`` is the complete original canonical signed envelope, not
    a claims-only reconstruction. The existing ``verified_at_epoch_ns`` column
    stores its signed issuance instant for this version, not the varying time
    of a later signature check. Thus every fresh verification of identical
    originals derives the same immutable verified-row material. Consumption
    separately requires actual supplied time at or after that signed instant.
    """
    try:
        ledger = capture._SharedLedger(work)
        evidence_type, operation = _custody_purpose(purpose)
        _verify_on_work(envelope_bytes=envelope_bytes, purpose=purpose, expected_claims=expected_claims,
            public_key=public_key, expected_signer_identity=expected_signer_identity,
            expected_signer_spki_digest=expected_signer_spki_digest, now_epoch_ns=now_epoch_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
        # Reparse the same immutable original for the row projection; no prior
        # verification DTO or mutable caller claims are accepted as authority.
        # This genuine extra canonical decode is charged, not a cache discount.
        envelope = _decode_on_work(envelope_bytes, work)
        identity = envelope["signerIdentity"]
        claims_bytes = capability._wire(envelope["claims"], ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        signature = envelope["signatureBase64Url"]
        statement_digest = plan._frame(STATEMENT_DOMAIN, (envelope_bytes,), work)
        signature_digest = plan._frame(DETACHED_SIGNATURE_DOMAIN,
            (plan._ascii("Ed25519", work), plan._ascii(signature, work)), work)
        binding_digest = plan._frame(BINDING_DOMAIN,
            (plan._ascii(authority.SOURCE_REVISION, work), plan._ascii(purpose, work),
             plan._ascii(operation, work), claims_bytes), work)
        evidence_digest = _evidence_digest_on_work(envelope_bytes, work)
        work.charge(input_bytes=len(envelope_bytes))
        statement_json = envelope_bytes.decode("ascii")
        row = {"evidence_digest": evidence_digest, "evidence_type": evidence_type,
            "statement_json": statement_json, "statement_digest": statement_digest,
            "verifier_identity_digest": identity["sessionIdentityDigest"],
            "verifier_measurement_digest": identity["measurementDigest"],
            "verifier_attestation_receipt_digest": identity["attestationReceiptDigest"],
            "signature_algorithm": "Ed25519", "signature_base64url": signature,
            "signature_digest": signature_digest, "binding_digest": binding_digest,
            "status": "verified", "verified_at_epoch_ns": envelope["issuedAtEpochNs"],
            "expires_at_epoch_ns": envelope["expiresAtEpochNs"], "consumed_operation_id": None,
            "consumed_at_epoch_ns": None, "source_revision": authority.SOURCE_REVISION}
        plan.contract._object(row, EVIDENCE_ROW_FIELDS, "v2 WebAuthn evidence row")
        return row
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("v2 WebAuthn evidence row projection failed") from exc


def _admission_effect_on_work(selected, verified_row, work):
    """Compare an exact custody PK and return ordinary insertion/no-op data.

    This helper performs no signature, purpose-semantic or root verification.
    Fixed purpose composers must themselves run the genuine semantic worker
    and _verified_row_on_work before calling it; no entry point accepts this
    result as a proof token. A supplied absence is not an authenticated absence.
    The future operation owner must prove the selection and atomically render
    the INSERT under its own explicit source template and root authority.

    None means only that the whole unused verified row already matches. It is
    not execution replay, completion, permission to reset consumption or a
    durable receipt. No UPDATE is proposed for any existing row.
    """
    ledger = capture._SharedLedger(work)
    owned = capture._JSONCapture(ledger).visit({"selected": selected, "row": verified_row})
    selected, row = owned["selected"], owned["row"]
    plan.contract._object(selected, capture._SELECTED_FIELDS, "WebAuthn admission selection")
    plan.contract._object(row, EVIDENCE_ROW_FIELDS, "WebAuthn admission row")
    for field in ("evidence_digest", "statement_digest", "verifier_identity_digest",
            "verifier_measurement_digest", "verifier_attestation_receipt_digest",
            "signature_digest", "binding_digest"):
        plan.contract._digest(row[field])
    if (type(row["evidence_type"]) is not str
            or row["evidence_type"] not in tuple(item[0] for item in _CUSTODY_PURPOSES.values())):
        raise WebAuthnEvidenceError("WebAuthn admission row is not a supported v2 purpose")
    plan.contract._literal(row["source_revision"], authority.SOURCE_REVISION)
    plan.contract._literal(row["signature_algorithm"], "Ed25519")
    plan.contract._literal(row["status"], "verified")
    plan.contract._base64url(row["signature_base64url"], signature=True)
    if row["consumed_operation_id"] is not None or row["consumed_at_epoch_ns"] is not None:
        raise WebAuthnEvidenceError("WebAuthn admission cannot restore consumed evidence")
    for field in ("verified_at_epoch_ns", "expires_at_epoch_ns"):
        plan.contract._integer(row[field], minimum=1)
    if not 0 < row["expires_at_epoch_ns"] - row["verified_at_epoch_ns"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnEvidenceError("WebAuthn admission row has an invalid signed interval")
    statement = row["statement_json"]
    if type(statement) is not str or not 2 <= len(statement) <= MAX_EVIDENCE_BYTES:
        raise WebAuthnEvidenceError("WebAuthn admission requires the bounded original statement")
    work.prepare_scan(statement)
    if not statement.isascii():
        raise WebAuthnEvidenceError("WebAuthn admission statement is not original canonical ASCII")
    if (type(selected["present"]) is not bool or selected["contractSelector"] is not None
            or selected["present"] and type(selected["row"]) is not dict
            or not selected["present"] and selected["row"] is not None):
        raise WebAuthnEvidenceError("WebAuthn admission selection is not exact PK presence/absence")
    expected_key = {"evidence_digest": row["evidence_digest"]}
    key_bytes = capability._wire(expected_key, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
    key_digest = plan._frame("serverware.policyAuthorityBusinessKey/v1",
        (plan._ascii(EVIDENCE_TABLE, work), key_bytes), work)
    plan._same((selected["table"], selected["key"], selected["keyDigest"]),
        (EVIDENCE_TABLE, expected_key, key_digest), work,
        "WebAuthn admission selection differs from the original evidence primary key")
    if selected["present"]:
        plan.contract._object(selected["row"], EVIDENCE_ROW_FIELDS, "retained WebAuthn admission row")
        plan._same(selected["row"], row, work,
            "WebAuthn admission conflicts with retained or already consumed evidence")
        return selected, None
    return selected, row


def _consume_on_work(context, *, envelope_bytes, purpose, expected_claims, public_key,
        expected_signer_identity, expected_signer_spki_digest, now_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Return one owned selected/after pair; no write or authority token.

    Every call genuinely verifies the signature, independent pins and complete
    expected claims. The exact authenticated selected row must equal the v2
    projection in its unused verified state. Consumed/revoked/v1 or partially
    matching rows fail; operation execution replay is not a second consumption.
    The caller must atomically include this effect with the business effects
    and independently admit its selected rows, request and evaluation instant.
    """
    try:
        ledger = capture._SharedLedger(work)
        evidence_type, operation = _custody_purpose(purpose)
        if (type(context) is not plan.core.KernelContext or type(context.operation) is not str
                or context.operation != operation or type(context.selected_rows) is not tuple
                or len(context.selected_rows) > authority.operation_spec(operation)["maximumQueryRows"]
                or any(type(selected) is not dict for selected in context.selected_rows)):
            raise WebAuthnEvidenceError("v2 WebAuthn consumption has no exact supported context")
        spec = authority.operation_spec(operation)
        if ("external-evidence-receipt" not in spec["proofPrimitives"]
                or evidence_type not in spec["externalEvidenceTypes"]
                or EVIDENCE_TABLE not in spec["businessReadBeforeWrite"]
                or EVIDENCE_TABLE not in spec["businessWrites"]):
            raise WebAuthnEvidenceError("v2 WebAuthn consumption is not declared by the actual operation")
        request_digest = context.request_digest
        plan.contract._digest(request_digest)
        database_now = context.database_now
        if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
            raise WebAuthnEvidenceError("v2 WebAuthn consumption requires its independently held UTC instant")
        plan.contract._integer(now_epoch_ns, minimum=1)
        elapsed = database_now - _EPOCH
        context_now = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000
        plan.contract._integer(context_now, minimum=1)
        if now_epoch_ns != context_now:
            raise WebAuthnEvidenceError("v2 WebAuthn consumption instant differs from its held context")
        # Own the actual selected inventory before any key export/verification
        # callback. JSON capture requires a real prepaid tuple-to-list copy.
        work.prepare_copy(context.selected_rows)
        owned = capture._JSONCapture(ledger).visit(list(context.selected_rows))
        for selected in owned:
            plan.contract._object(selected, capture._SELECTED_FIELDS, "v2 WebAuthn selected row")
            if (type(selected["present"]) is not bool or type(selected["key"]) is not dict
                    or (selected["present"] and type(selected["row"]) is not dict)
                    or (not selected["present"] and selected["row"] is not None)):
                raise WebAuthnEvidenceError("v2 WebAuthn selected row has no exact presence/row shape")
        work.prepare_copy(owned)
        held_context = plan.core.KernelContext(operation, {}, tuple(owned), database_now, request_digest)
        evidence_digest = _evidence_digest_on_work(envelope_bytes, work)
        selected = held_context._exact(EVIDENCE_TABLE, {"evidence_digest": evidence_digest}, work=work)
        if selected["present"] is not True:
            raise WebAuthnEvidenceError("v2 WebAuthn evidence has no retained verified row")
        plan.contract._object(selected["row"], EVIDENCE_ROW_FIELDS, "retained v2 WebAuthn evidence row")
        row = _verified_row_on_work(envelope_bytes=envelope_bytes, purpose=purpose,
            expected_claims=expected_claims, public_key=public_key,
            expected_signer_identity=expected_signer_identity,
            expected_signer_spki_digest=expected_signer_spki_digest, now_epoch_ns=now_epoch_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
        plan._same(selected["row"], row, work,
            "retained v2 WebAuthn evidence differs from exact verified original projection")
        if not row["verified_at_epoch_ns"] <= now_epoch_ns < row["expires_at_epoch_ns"]:
            raise WebAuthnEvidenceError("v2 WebAuthn evidence is not yet consumable or has expired")
        operation_id = plan._frame("serverware.policyAuthorityOperation/v2",
            (plan._ascii(operation, work), plan._ascii(request_digest, work)), work)
        work.prepare_copy(row)
        consumed = {**row, "status": "consumed", "consumed_operation_id": operation_id,
            "consumed_at_epoch_ns": now_epoch_ns}
        return selected, consumed
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("v2 WebAuthn evidence consumption failed") from exc
