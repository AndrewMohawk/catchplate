"""One real scope-bound claim per material and one contact per exact token."""
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_retirement_succession_records as rows
from serverware import authority_oauth_retirement_succession_contacts as contacts
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared


def material_list(scope):
    inventory = rows.stored(scope["inventory_original_json"])
    p.require(set(inventory) == {"snapshotBindings", "materialOriginals", "priorContacts", "analysisSha256"})
    p.digest(inventory["analysisSha256"])
    p.require(type(inventory["materialOriginals"]) is list and len(inventory["materialOriginals"]) <= p.MAX_MATERIALS)
    return inventory, inventory["materialOriginals"]


def observed(context, grant):
    claims, attempts = [], []
    for pin in grant["materials"]:
        claim_id = p.material_claim_id(grant["authorizationId"], pin["materialId"])
        selected = context.exact(p.MATERIAL_TABLE, {"id": claim_id})
        if selected["present"]:
            claim = shared._row(selected, "actual material decryption claim"); rows.material_original(claim)
            p.require(claim["scope_id"] == grant["authorizationId"] and claim["material_id"] == pin["materialId"])
            claims.append(claim)
        for purpose in pin["tokenPurposes"]:
            selected = context.exact(p.ATTEMPT_TABLE, {"id": p.attempt_id(claim_id, purpose)})
            if selected["present"]:
                attempt = shared._row(selected, "actual material contact"); rows.attempt_original(attempt)
                p.require(attempt["material_claim_id"] == claim_id and attempt["scope_id"] == grant["authorizationId"])
                attempts.append(attempt)
    return claims, attempts


def _same_owner(values, original):
    p.require(values["assignment_original"] == original["assignment_original"]
        and values["enrollment_original"] == original["enrollment_original"]
        and values["authorization_original"] == original["authorization_original"]
        and values["credential_policy"] == original["credential_policy"])
    now, then = values["native_evidence"]["statement"], original["native_evidence"]["statement"]
    for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "instanceId", "policyHash",
            "dataPlaneBinarySha256", "enrollmentSha256", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
        p.require(now[name] == then[name], "material effect owner changed")


def transition(context, values, grant, scope):
    operation, request = context.operation, values["request"]
    p.require(operation in p.MATERIAL_OPERATIONS | {p.OP_RECOVER})
    inventory, materials = material_list(scope)
    claims, attempts = observed(context, grant)
    if operation == p.OP_RECOVER and request["materialId"] is None:
        return (), claims, attempts, {"contactDisposition": "observation-only"}
    identifier = request["materialId"]
    found = [item for item in materials if item["pin"]["materialId"] == identifier]
    p.require(len(found) == 1)
    material = found[0]; pin = next(pin for pin in grant["materials"] if pin["materialId"] == identifier)
    p.require(material["pin"] == pin and material["providerId"] == grant["providerId"])
    raw_enrollment = p.activation.enrollment_bytes(values["enrollment_original"])
    p.require(p.sha256(raw_enrollment) == pin["enrollmentSha256"])
    if material["enrollmentOriginal"] is not None:
        p.require(material["enrollmentOriginal"] == raw_enrollment.decode("ascii"))
    else:
        from serverware import authority_oauth_activation_policy as enrollment
        original = rows.stored(material["sourceOriginals"]["credentialOriginal"], 512 * 1024)
        p.require(rows.stored(original["metadata"], 32768)["oauth_application_owner"] == enrollment.association(raw_enrollment))
    claim_id = p.material_claim_id(grant["authorizationId"], identifier)
    claim_selected = context.exact(p.MATERIAL_TABLE, {"id": claim_id})
    claim = next((row for row in claims if row["id"] == claim_id), None)
    if operation in {p.OP_INSPECT, p.OP_RECOVER}:
        return (), claims, attempts, {"contactDisposition": "observation-only", "materialOriginal": p.canonical(material).decode("ascii")}
    now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
    p.require(grant["issuedAtEpochNs"] <= now < grant["retentionExpiresAtEpochNs"])
    if operation == p.OP_MATERIAL:
        p.require(now < grant["contactExpiresAtEpochNs"] and not claim_selected["present"] and claim is None
            and request["materialOriginalSha256"] == p.sha256(p.canonical(material))
            and not any(row["material_claim_id"] == claim_id for row in attempts))
        claim = {"id": claim_id, "material_id": identifier, "scope_id": grant["authorizationId"], "provider_id": grant["providerId"],
            "scope_json": p.canonical(grant["scope"]).decode("ascii"), "authorization_sha256": scope["authorization_sha256"],
            "material_original_json": p.canonical(material).decode("ascii"), "claim_arguments_json": p.canonical(values).decode("ascii"),
            "claim_request_digest": context.request_digest, "owner_nonce_sha256": request["ownerNonceSha256"], "status": "claimed", "created_at": stamp, "updated_at": stamp}
        rows.material_original(claim)
        return (core.mutation(operation=operation, selected=claim_selected, row=claim),), claims + [claim], attempts, {"contactDisposition": "not-contact-authority"}
    p.require(claim is not None and claim["material_original_json"] == p.canonical(material).decode("ascii")
        and claim["authorization_sha256"] == scope["authorization_sha256"]
        and claim["owner_nonce_sha256"] == p.sha256(p.decoded(request["ownerNonce"], 32, 32)))
    claimed = p.arguments(p.OP_MATERIAL, rows.stored(claim["claim_arguments_json"], p.MAX_ARGUMENT_BYTES))
    _same_owner(values, claimed)
    purpose = request["tokenPurpose"]; attempt_id = p.attempt_id(claim_id, purpose)
    selected = context.exact(p.ATTEMPT_TABLE, {"id": attempt_id})
    if operation == p.OP_CONTACT:
        p.require(now < grant["contactExpiresAtEpochNs"] and not selected["present"]
            and request["materialRowSha256"] == p.sha256(rows.material_original(claim))
            and all(row["status"] in {"accepted", "accepted-existing"} for row in attempts),
            "one consumed uncertain/rejected contact blocks continuation; there is no loop retry")
        prior = contacts.prior_match(inventory["priorContacts"], request["contactRequestSha256"])
        for previous in sorted(attempts, key=lambda row: row["id"]):
            if previous["contact_request_sha256"] != request["contactRequestSha256"]:
                continue
            previous_claim = next(row for row in claims if row["id"] == previous["material_claim_id"])
            prior = rows.stored(previous["prior_contact_json"], 512 * 1024) if previous["status"] == "accepted-existing" else {
                "profile": "succession", "attemptOriginal": rows.attempt_original(previous).decode("ascii"),
                "sourceOriginal": rows.material_original(previous_claim).decode("ascii")}
            contacts.reference(records=prior, request_sha256=request["contactRequestSha256"])
            break
        attempt = {"id": attempt_id, "material_id": identifier, "material_claim_id": claim_id, "scope_id": grant["authorizationId"],
            "token_purpose": purpose, "contact_request_sha256": request["contactRequestSha256"], "contact_arguments_json": p.canonical(values).decode("ascii"),
            "contact_request_digest": context.request_digest, "finish_arguments_json": None, "finish_request_digest": None, "transport_original": None,
            "prior_contact_json": None if prior is None else p.canonical(prior).decode("ascii"),
            "status": "contact-claimed" if prior is None else "accepted-existing", "created_at": stamp, "updated_at": stamp}
        disposition = attempt["status"]
    else:
        p.require(operation == p.OP_FINISH and selected["present"])
        before = shared._row(selected, "actual one-use contact claim"); rows.attempt_original(before)
        p.require(request["attemptRowSha256"] == p.sha256(rows.attempt_original(before)) and before["status"] == "contact-claimed"
            and before["material_claim_id"] == claim_id and before["token_purpose"] == purpose)
        contacted = p.arguments(p.OP_CONTACT, rows.stored(before["contact_arguments_json"], p.MAX_ARGUMENT_BYTES))
        _same_owner(values, contacted)
        raw = p.decoded(request["transportOriginal"], p.MAX_TRANSPORT_BYTES)
        outcome = p.transport(raw, before["contact_request_sha256"])
        report = p.document(raw, p.MAX_TRANSPORT_BYTES)
        p.require(shared._database_epoch_ns(p.issuance.legacy.timestamp(before["created_at"])) <= report["receivedAtEpochNs"] <= now
            and report["receivedAtEpochNs"] < grant["contactExpiresAtEpochNs"])
        attempt = {**before, "status": outcome, "finish_arguments_json": p.canonical(values).decode("ascii"),
            "finish_request_digest": context.request_digest, "transport_original": raw.decode("ascii"), "updated_at": stamp}
        disposition = "observed-" + outcome
    rows.attempt_original(attempt)
    returned = [row for row in attempts if row["id"] != attempt_id] + [attempt]
    return (core.mutation(operation=operation, selected=selected, row=attempt),), claims, returned, {"contactDisposition": disposition}
