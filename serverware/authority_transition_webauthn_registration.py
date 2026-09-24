"""Successor registration semantics, deliberately not a registered v1 kernel.

The private transition re-verifies original v2 evidence against independent
key/identity/RP/time pins and derives ordinary row effects. Its caller must
actually authenticate primary rows and every complete query in the recipe.
Neither a bare KernelContext nor the returned effects prove that admission.
The existing v1 manifest/complete-query dispatcher cannot admit this recipe:
activation requires an explicit successor adapter, not a keyless registry stub.

Evidence signs an acyclic semantic intent and derived attestation result, not
the final request digest, future credential UUID, evidence ID or signature.
The original challenge is the one-use barrier; no v1 receipt is fabricated.
No database, clock, legacy finalizer, signer or replacement work budget is used.
"""
from __future__ import annotations

from datetime import datetime, timezone

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as capture
from serverware import authority_contract as authority
from serverware import authority_index_projection as projection
from serverware import authority_revocation_invocation as invocation
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as support
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_trust as trust


OPERATION = "webauthn.registration.finalize"
PROFILE = "serverware.policyAuthorityWebAuthnRegistrationTransition/v2"
INTENT_SCHEMA = "serverware.policyAuthorityWebAuthnRegistrationIntent/v2"
CLAIMS_SCHEMA = "serverware.policyAuthorityWebAuthnRegistrationAttestation/v2"
INTENT_DOMAIN = "serverware.policyAuthorityWebAuthnRegistrationIntent/v2"
MAX_SIBLINGS = 32
_I64_MAX = 2**63 - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ARGUMENT_FIELDS = frozenset({"semantic_intent", "credential", "challenge",
    "verified_at_epoch_ns", "attestation_envelope_base64url", "attestation_evidence_digest",
    "oidc_session_id", "sibling_challenge_ids", "businessIntent"})
_INTENT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "profile",
    "challengeId", "challengeRowDigest", "userId", "label", "authorizationDigest",
    "authorizationMode", "rpId", "origin", "clientDataDigest", "attestationObjectDigest",
    "trustHighWaterDigest"})
_CREDENTIAL_FIELDS = frozenset({"credential_id", "user_id", "label", "public_key_cose",
    "sign_count", "aaguid", "authenticator_class", "attestation_fmt", "attestation_trusted",
    "attestation_trust_path", "attestation_leaf_sha256", "attestation_root_sha256",
    "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence",
    "attestation_verified_at", "transports", "user_verified"})
_CHALLENGE_FIELDS = frozenset({"id", "challenge", "challenge_type", "user_id",
    "approval_request_id", "payload_json", "scope_key", "expires_at", "used_at", "created_at"})
_MODES = frozenset({"bootstrap-token", "development-bootstrap", "existing-webauthn",
    "oidc-session-first-enrollment"})


def _fail(message):
    raise core.TransitionKernelError(message)


def _closed(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str for key in value) or set(value) != fields):
        _fail(f"registration {label} is not source closed")


def _text(value, label, maximum, work, *, empty=False):
    if type(value) is not str or (not value and not empty) or len(value) > maximum:
        _fail(f"registration {label} is not bounded exact text")
    work.prepare_utf8(value)
    if len(value.encode("utf-8")) > maximum or "\x00" in value:
        _fail(f"registration {label} exceeds its UTF-8 bound")
    return value


def _integer(value, label, minimum=0, maximum=_I64_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"registration {label} is not a bounded exact integer")
    return value


def _digest(value):
    evidence.plan.contract._digest(value)
    return value


def _same(actual, expected, work, label):
    work.prepare_comparison(actual, expected)
    if actual != expected:
        _fail(f"registration {label} differs")


def _wire(value, work):
    work.prepare_encoding(value)
    return core.canonical_bytes(value)


def _framed(domain, value, work):
    return evidence.plan._frame(domain, (_wire(value, work),), work)


def _encoded_original(value, maximum, work, *, minimum=2):
    if type(value) is not str or not 2 <= len(value) <= (4 * maximum + 2) // 3:
        _fail("registration original-byte encoding is outside its bound")
    # Unpadded canonical base64 determines its byte count without decoding.
    count = len(value) * 3 // 4
    if not minimum <= count <= maximum:
        _fail("registration original byte count is outside its bound")
    if count == 1:
        # Registration credential IDs permit one byte; invocation's document
        # codec deliberately requires two. Use the actual canonical challenge
        # codec for this bounded case, not an invented two-byte minimum.
        raw = support._challenge_bytes(value, work=work)
        if len(raw) != 1:
            _fail("registration one-byte original changed")
        return raw
    return invocation._decode(value, count, maximum, work)


def _utc(value, label, work):
    _text(value, label, 64, work)
    parsed = support._utc(value, label, work=work)
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        _fail(f"registration {label} is not UTC")
    return parsed


def _now(value):
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        _fail("registration evaluation time is not an exact UTC datetime")
    delta = value - _EPOCH
    return _integer((delta.days * 86400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000, "evaluation instant", 1)


def _arguments(owned, work):
    _closed(owned, _ARGUMENT_FIELDS, "arguments")
    intent, credential = owned["semantic_intent"], owned["credential"]
    _closed(intent, _INTENT_FIELDS, "semantic intent")
    _closed(credential, _CREDENTIAL_FIELDS, "derived credential")
    for field, wanted in (("schema", INTENT_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
                          ("operation", OPERATION), ("profile", PROFILE)):
        _same(intent[field], wanted, work, field)
    for field in ("challengeRowDigest", "authorizationDigest", "clientDataDigest",
                  "attestationObjectDigest", "trustHighWaterDigest"):
        _digest(intent[field])
    for field, maximum in (("challengeId", 4096), ("userId", 4096), ("rpId", 4096), ("origin", 8192)):
        _text(intent[field], field, maximum, work)
    _text(intent["label"], "label", 4096, work, empty=True)
    if type(intent["authorizationMode"]) is not str or intent["authorizationMode"] not in _MODES:
        _fail("registration authorization mode is not supported")
    for field, maximum in (("credential_id", 1366), ("user_id", 4096),
                          ("authenticator_class", 128), ("attestation_fmt", 256 * 1024), ("aaguid", 128)):
        _text(credential[field], field, maximum, work)
    _text(credential["label"], "label", 4096, work, empty=True)
    _encoded_original(credential["credential_id"], 1024, work, minimum=1)
    _encoded_original(credential["public_key_cose"], 4096, work, minimum=1)
    _integer(credential["sign_count"], "sign counter", 0, 2**32 - 1)
    for field in ("attestation_trusted", "user_verified"):
        if type(credential[field]) is not bool:
            _fail("registration attestation flags are not exact booleans")
    for field in ("attestation_leaf_sha256", "attestation_root_sha256", "attestation_trust_bundle_digest"):
        if credential[field] is not None:
            _digest(credential[field])
    if credential["attestation_trust_bundle_sequence"] is not None:
        _integer(credential["attestation_trust_bundle_sequence"], "trust sequence", 1)
    # Five supplied certificates plus a separately admitted root may appear.
    for field, maximum in (("attestation_trust_path", 6), ("transports", 16)):
        values = credential[field]
        if type(values) is not list or len(values) > maximum:
            _fail("registration credential list exceeds its source bound")
        for item in values:
            if field == "attestation_trust_path":
                _digest(item)
            else:
                _text(item, "transport", 2048, work, empty=True)
    if credential["attestation_verified_at"] is not None:
        _utc(credential["attestation_verified_at"], "attestation time", work)
    if credential["attestation_trusted"] and any(credential[field] is None for field in (
            "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence", "attestation_verified_at")):
        _fail("trusted registration result has no complete trust binding")
    _same((intent["userId"], intent["label"]), (credential["user_id"], credential["label"]), work,
        "intent credential scope")
    _text(owned["challenge"], "challenge", 4096, work)
    _integer(owned["verified_at_epoch_ns"], "verification instant", 1)
    if credential["attestation_verified_at"] is not None:
        _same(_now(_utc(credential["attestation_verified_at"], "attestation time", work)),
            owned["verified_at_epoch_ns"], work, "derived verification instant")
    _digest(owned["attestation_evidence_digest"])
    siblings = owned["sibling_challenge_ids"]
    if type(siblings) is not list or len(siblings) > MAX_SIBLINGS:
        _fail("registration sibling inventory exceeds its source bound")
    for item in siblings:
        _text(item, "sibling challenge ID", 4096, work)
    work.prepare_copy(siblings)
    ordered = sorted(siblings)
    work.prepare_copy(siblings)
    if len(set(siblings)) != len(siblings):
        _fail("registration sibling inventory is duplicated")
    _same(siblings, ordered, work, "sibling ordering")
    work.prepare_scan(siblings)
    if intent["challengeId"] in siblings:
        _fail("registration selected challenge cannot also be a sibling")
    oidc = intent["authorizationMode"] == "oidc-session-first-enrollment"
    if oidc:
        _text(owned["oidc_session_id"], "OIDC session ID", 4096, work)
    elif owned["oidc_session_id"] is not None or siblings:
        _fail("ordinary registration cannot consume OIDC sibling scope")
    work.prepare_copy(owned)
    semantic = {name: value for name, value in owned.items() if name != "businessIntent"}
    expected = authority._synthesize_business_intent(OPERATION, semantic, work=work)
    _same(owned["businessIntent"], expected, work, "final business intent")
    return owned


def _identity(request_digest, purpose, work):
    return core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
        purpose=purpose, work=work)


def _query_recipe_on_work(*, arguments, database_now, request_digest, work):
    """Ordinary source declarations; not accepted v1 QueryProgram objects.

    Complete declarations require authenticated full ranges and primary joins,
    not merely an SQL page or the supplied sibling hints. The common framework
    must separately append and prove the one shared audit-capacity query.
    """
    ledger = capture._SharedLedger(work)
    values = _arguments(capture._JSONCapture(ledger).visit(arguments), work)
    _digest(request_digest)
    _now(database_now)
    cutoff = complete.cutoff_microseconds(database_now)
    intent, credential = values["semantic_intent"], values["credential"]
    result = []

    def exact(name, table, key):
        result.append({"kind": "primary-key-row", "queryId": core.query_program_id(OPERATION, name, table),
            "table": table, "key": key, "maximumRows": 1})

    def full(name, index_id, selector, maximum):
        work.prepare_copy(selector)
        complete._prepare_constructor_work(index_id, tuple(selector.items()), work)
        profile = projection.profile_for(index_id)
        work.prepare_encoding(selector, shallow_copies=1)
        projection.snapshot_selector(index_id, selector)
        result.append({"kind": complete.PROOF_PRIMITIVE,
            "queryId": core.query_program_id(OPERATION, name, profile.table),
            "table": profile.table, "indexId": index_id,
            "projectionDigest": profile.projection_digest, "selector": selector,
            "maximumRows": maximum, "overflowDisposition": "fail-closed"})

    exact("registration_challenge", "webauthn_challenges", {"id": intent["challengeId"]})
    exact("new_credential", "webauthn_credentials", {"id": _identity(request_digest, "credential-record", work)})
    exact("registration_audit", "metadata_audit_outbox", {"id": _identity(request_digest, "registration-audit", work)})
    exact("trust_high_water", trust.HIGH_WATER_TABLE, {"authority_scope": trust.AUTHORITY_SCOPE})
    full("credential_id_history", "webauthn_credential_id", {"credential_id": credential["credential_id"]}, 1)
    full("pending_trust_publications", "webauthn_publication_status", {"status": "pending"}, 1)
    result.append({"kind": "selected-row-field-join", "queryId": core.query_program_id(OPERATION,
        "trust_publication", trust.PUBLICATION_TABLE), "table": trust.PUBLICATION_TABLE,
        "maximumRows": 1, "sourceTable": trust.HIGH_WATER_TABLE,
        "sourceKey": {"authority_scope": trust.AUTHORITY_SCOPE},
        "fixedPredicates": {"scope": "global", "status": "published"},
        "fieldJoins": {"bundle_digest": "publication_digest", "payload_digest": "metadata_blob_digest",
            "rollback_epoch": "rollback_epoch", "sequence": "publication_sequence"}})
    if values["oidc_session_id"] is not None:
        exact("pending_oidc_session", "oidc_browser_sessions", {"id": values["oidc_session_id"]})
        full("user_credential_history", "webauthn_credential_user_history", {"user_id": credential["user_id"]}, 1)
        full("user_registration_challenges", "webauthn_registration_unused_user",
            {"user_id": credential["user_id"], "expires_after_us": cutoff}, 1 + len(values["sibling_challenge_ids"]))
    work.prepare_copy(result)
    return tuple(result)


def _present(context, table, work):
    work.prepare_copy(context.selected_rows)
    return tuple(selected for selected in context.selected_rows
        if selected["table"] == table and selected["present"] is True)


def _stored_json(raw, work):
    value = support._stored_json(raw, work=work)
    # Database JSON text is already original row data. Retain legacy JSON
    # interpretation rather than imposing a new whitespace serialization rule.
    return value


def _trust_binding(context, intent, credential, work):
    selected = context._exact(trust.HIGH_WATER_TABLE, {"authority_scope": trust.AUTHORITY_SCOPE}, work=work)
    high = support._row(selected, work=work)
    document = trust.high_water_document(rollback_epoch=high.get("rollback_epoch"),
        sequence=high.get("publication_sequence"), publication_digest=high.get("publication_digest"),
        metadata_blob_digest=high.get("metadata_blob_digest"), revocation_set_digest=high.get("revocation_set_digest"),
        witness_receipt_digest=high.get("witness_receipt_digest"), witness_sequence=high.get("witness_sequence"))
    _same(high.get("authority_scope"), trust.AUTHORITY_SCOPE, work, "trust authority scope")
    _same(intent["trustHighWaterDigest"], trust.high_water_digest(document, work=work), work, "trust predecessor")
    publications = _present(context, trust.PUBLICATION_TABLE, work)
    if len(publications) != 1:
        _fail("registration requires one published trust predecessor and no pending publication")
    published = support._row(publications[0], work=work)
    for actual, expected in ((published.get("scope"), "global"), (published.get("status"), "published"),
            (published.get("bundle_digest"), high["publication_digest"]),
            (published.get("payload_digest"), high["metadata_blob_digest"]),
            (published.get("rollback_epoch"), high["rollback_epoch"]),
            (published.get("sequence"), high["publication_sequence"])):
        if type(actual) is not type(expected):
            _fail("registration trust predecessor scalar type changed")
        _same(actual, expected, work, "published trust predecessor")
    if credential["attestation_trusted"]:
        _same((credential["attestation_trust_bundle_digest"], credential["attestation_trust_bundle_sequence"]),
            (high["publication_digest"], high["publication_sequence"]), work, "trusted attestation generation")


def _transition_on_work(context, *, evidence_public_key, expected_signer_identity,
        expected_signer_spki_digest, expected_rp_id, expected_origin,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Return (ordinary selected/after row pairs, legacy-shaped result).

    Required independent pins are not read from the request or an evidence
    DTO. The actual original signature is checked in this call. The upstream
    successor must admit the context/time, complete query recipe and signer
    provenance; this private business worker cannot replace those admissions.
    """
    ledger = capture._SharedLedger(work)
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or context.operation != OPERATION
            or type(context.selected_rows) is not tuple or len(context.selected_rows) > 112):
        _fail("registration context is not a bounded exact source input")
    now_ns = _now(context.database_now)
    _integer(maximum_age_ns, "independent maximum age", 1, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    _integer(maximum_clock_skew_ns, "independent clock skew", 0, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    request_digest = _digest(context.request_digest)
    work.prepare_copy(context.selected_rows)
    owned = capture._JSONCapture(ledger).visit({"arguments": context.arguments,
        "selected": list(context.selected_rows), "signerIdentity": expected_signer_identity})
    values = _arguments(owned["arguments"], work)
    identity = owned["signerIdentity"]
    evidence._identity(identity)
    _digest(expected_signer_spki_digest)
    _text(expected_rp_id, "independent RP ID", 4096, work)
    _text(expected_origin, "independent origin", 8192, work)
    selected_rows = owned["selected"]
    for selected in selected_rows:
        _closed(selected, capture._SELECTED_FIELDS, "selected row")
        if type(selected["present"]) is not bool or type(selected["key"]) is not dict:
            _fail("registration selected row shape changed")
        if selected["present"] and type(selected["row"]) is not dict:
            _fail("registration present row has no exact object")
        if not selected["present"] and selected["row"] is not None:
            _fail("registration absent row contains data")
    work.prepare_copy(selected_rows)
    current = core.KernelContext(OPERATION, values, tuple(selected_rows), context.database_now, request_digest)
    intent, credential = values["semantic_intent"], values["credential"]
    _same((intent["rpId"], intent["origin"]), (expected_rp_id, expected_origin), work, "independent RP/origin")
    challenge_selected = current._exact("webauthn_challenges", {"id": intent["challengeId"]}, work=work)
    challenge = support._row(challenge_selected, work=work)
    _closed(challenge, _CHALLENGE_FIELDS, "challenge row")
    _same((challenge["id"], challenge["challenge"], challenge["challenge_type"], challenge["user_id"],
           challenge["approval_request_id"], challenge["used_at"]),
        (intent["challengeId"], values["challenge"], "registration", intent["userId"], None, None), work, "live challenge scope")
    if _utc(challenge["expires_at"], "challenge expiry", work) <= current.database_now:
        _fail("registration challenge is expired")
    _same(intent["challengeRowDigest"], _framed("serverware.policyAuthorityWebAuthnChallengeRow/v1", challenge, work),
        work, "whole challenge row commitment")
    payload = _stored_json(challenge["payload_json"], work)
    if type(payload) is not dict:
        _fail("registration challenge payload is not an object")
    _same((payload.get("type"), payload.get("user_id"), payload.get("label")),
        ("registration", intent["userId"], intent["label"]), work, "challenge payload scope")
    authorization = payload.get("authorization")
    if type(authorization) is not dict:
        _fail("registration requires the original enrollment authorization")
    _same(authorization.get("mode"), intent["authorizationMode"], work, "enrollment mode")
    _digest(authorization.get("payload_digest"))
    _same(intent["authorizationDigest"], _framed("serverware.policyAuthorityWebAuthnRegistrationAuthorization/v2",
        authorization, work), work, "full enrollment authorization")
    _trust_binding(current, intent, credential, work)
    credentials = _present(current, "webauthn_credentials", work)
    for selected in credentials:
        row = selected["row"]
        if row.get("credential_id") == credential["credential_id"]:
            _fail("registration credential ID has already existed, including revoked history")
    if values["oidc_session_id"] is not None:
        _closed(authorization, frozenset({"mode", "session_id", "user_id", "pending_expires_at",
            "payload_digest", "existing_credential_count"}), "OIDC enrollment authorization")
        _integer(authorization["existing_credential_count"], "OIDC historical credential count", 0, 0)
        _same((authorization["session_id"], authorization["user_id"]),
            (values["oidc_session_id"], intent["userId"]), work, "OIDC authorization scope")
        session = support._row(current._exact("oidc_browser_sessions", {"id": values["oidc_session_id"]}, work=work), work=work)
        _same((session.get("id"), session.get("user_id"), session.get("status"), session.get("pending_expires_at")),
            (values["oidc_session_id"], intent["userId"], "pending_webauthn", authorization["pending_expires_at"]), work,
            "pending OIDC session")
        if any(_utc(session.get(field), "OIDC expiry", work) <= current.database_now
               for field in ("expires_at", "pending_expires_at")):
            _fail("registration pending OIDC session is expired")
        for selected in credentials:
            if selected["row"].get("user_id") == intent["userId"]:
                _fail("OIDC first enrollment requires zero all-status credential history")
    raw = _encoded_original(values["attestation_envelope_base64url"], evidence.MAX_EVIDENCE_BYTES, work)
    _same(values["attestation_evidence_digest"], evidence._evidence_digest_on_work(raw, work), work, "original evidence identity")
    claims = {"schema": CLAIMS_SCHEMA, "intentDigest": _framed(INTENT_DOMAIN, intent, work),
        "credential": credential, "trustHighWaterDigest": intent["trustHighWaterDigest"],
        "verifiedAtEpochNs": values["verified_at_epoch_ns"],
        "verifierMeasurementDigest": identity["measurementDigest"],
        "verifierAttestationReceiptDigest": identity["attestationReceiptDigest"]}
    if (values["verified_at_epoch_ns"] > now_ns + maximum_clock_skew_ns
            or now_ns - values["verified_at_epoch_ns"] > maximum_age_ns):
        _fail("registration cryptographic verification is stale")
    evidence._verify_on_work(envelope_bytes=raw, purpose="registration-attestation", expected_claims=claims,
        public_key=evidence_public_key, expected_signer_identity=identity,
        expected_signer_spki_digest=expected_signer_spki_digest, now_epoch_ns=now_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    record_id = _identity(request_digest, "credential-record", work)
    new_selected = current._exact("webauthn_credentials", {"id": record_id}, work=work)
    audit_id = _identity(request_digest, "registration-audit", work)
    audit_selected = current._exact("metadata_audit_outbox", {"id": audit_id}, work=work)
    if new_selected["present"] or audit_selected["present"]:
        _fail("registration deterministic credential or audit identity was already used")
    now_iso = current.database_now.isoformat()
    work.prepare_copy(credential)
    row = {field: value for field, value in credential.items() if field != "user_verified"}
    row.update({"id": record_id, "attestation_trusted": int(credential["attestation_trusted"]),
        "attestation_trust_path": _wire(credential["attestation_trust_path"], work).decode("ascii"),
        "transports": _wire(credential["transports"], work).decode("ascii"),
        "dev_private_key_pem": None, "created_at": now_iso, "updated_at": now_iso, "last_used_at": None,
        "revoked_at": None, "revoked_by": None, "revocation_reason": None, "revocation_source": None})
    work.prepare_copy(challenge)
    consumed = {**challenge, "used_at": now_iso}
    effects = [(new_selected, row), (challenge_selected, consumed)]
    siblings = []
    if values["oidc_session_id"] is not None:
        for selected in _present(current, "webauthn_challenges", work):
            candidate = selected["row"]
            if (candidate.get("user_id") == intent["userId"] and candidate.get("challenge_type") == "registration"
                    and candidate.get("used_at") is None
                    and _utc(candidate.get("expires_at"), "sibling expiry", work) > current.database_now
                    and candidate.get("id") != intent["challengeId"]):
                # Deliberately no approval_request_id filter.
                siblings.append(selected)
        work.prepare_copy(siblings)
        actual_ids = sorted(item["row"]["id"] for item in siblings)
        _same(actual_ids, values["sibling_challenge_ids"], work, "complete live sibling population")
        for selected in siblings:
            work.prepare_copy(selected["row"])
            effects.append((selected, {**selected["row"], "used_at": now_iso}))
    event = {"user_id": intent["userId"], "credential_id": credential["credential_id"],
        "authenticator_class": credential["authenticator_class"], "aaguid": credential["aaguid"],
        "attestation_fmt": credential["attestation_fmt"], "attestation_trusted": credential["attestation_trusted"],
        "attestation_root_sha256": credential["attestation_root_sha256"], "registration_authorization": authorization}
    if values["oidc_session_id"] is not None:
        event["invalidated_sibling_registration_challenge_count"] = len(siblings)
    event_raw = _wire(event, work)
    work.charge(input_bytes=len(event_raw))
    audit = {"id": audit_id, "event_type": "webauthn.credential_registered", "actor_type": "admin",
        "actor_id": intent["userId"], "event_json": event_raw.decode("ascii"),
        "event_digest": evidence.plan._frame("serverware.metadataAuditOutboxEvent/v1", (event_raw,), work),
        "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": now_iso}
    effects.append((audit_selected, audit))
    work.prepare_copy(row)
    returned_credential = {**row, "attestation_trusted": credential["attestation_trusted"],
        "attestation_trust_path": credential["attestation_trust_path"], "transports": credential["transports"]}
    work.prepare_copy(consumed)
    returned_challenge = {field: value for field, value in consumed.items() if field != "payload_json"}
    returned_challenge["payload"] = payload
    result = {"challenge": returned_challenge, "credential": returned_credential}
    if values["oidc_session_id"] is not None:
        result["invalidated_sibling_registration_challenge_count"] = len(siblings)
    if len(effects) > MAX_SIBLINGS + 3:
        _fail("registration effects exceed the source mutation bound")
    work.prepare_copy(effects)
    work.prepare_encoding(result)
    return tuple(effects), result
