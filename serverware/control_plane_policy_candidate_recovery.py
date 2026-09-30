"""Warm native receipt readback into the existing claimed publication CAS.

Only the fixed authenticated lookup route is contacted, once. The original
claim's deadline and protected predecessor remain authoritative. No install,
handoff worker, new claim, signature, or absence-to-noncommit conversion exists
here; pre-retention acknowledgement loss and process loss remain unresolved.
"""
import http.client
import urllib.error
import urllib.request

from fastapi import HTTPException
from serverware import authority_policy_candidate as profile
from serverware import db, http_client

MANAGEMENT_PATH = "/v1/policy-shadow/generations/lookup"
LOOKUP_SCHEMA = "serverware.policyShadowGenerationLookup/v1"


def _read_native(owner, claim):
    from serverware import app
    owner.check()
    profile.require(not owner.contacted and claim["publication_envelope_digest"] is None
        and owner.claim_original == profile.row_original(claim).decode("ascii"))
    management = profile.management_original(claim["management_request_json"])
    body = profile.canonical({"apiVersion": LOOKUP_SCHEMA, "requestId": management["requestId"],
        "replayId": management["replayId"], "managementHandoffId": management["managementHandoffId"],
        "requestSha256": claim["payload_digest"]})
    profile.require(0 < len(body) <= 4096
        and profile.sha256(claim["management_request_json"].encode("ascii")) == claim["payload_digest"])
    if not app.DATA_PLANE_MANAGEMENT_TOKEN or len(app.DATA_PLANE_MANAGEMENT_TOKEN.encode("utf-8")) > 4096:
        raise HTTPException(status_code=503, detail="decision-gate management authentication is unavailable")
    request = urllib.request.Request(app._policy_shadow_generation_url(MANAGEMENT_PATH), data=body, method="POST",
        headers={"Accept": "application/json", "Accept-Encoding": "identity", "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": app.DATA_PLANE_MANAGEMENT_TOKEN})
    owner.check()
    # Mark before contact, retain the same clipped absolute deadline, and never
    # fall back to the mutating /generations endpoint on any response or error.
    owner.contacted = True
    try:
        response = http_client.request_json_bytes(request, timeout=app.DECISION_GATE_TIMEOUT_SECONDS,
            deadline=http_client.HttpDeadline(owner.deadline / 1_000_000_000), max_bytes=8 * 1024 * 1024,
            require_https=False, expected_statuses=(200,), expected_content_types=("application/json",))
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        raise HTTPException(status_code=503 if status >= 500 else 409,
            detail="exact native publication is not available for readback; outcome remains unresolved") from exc
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, http_client.HttpClientError) as exc:
        raise HTTPException(status_code=503,
            detail="native publication readback unavailable; do not repeat publication") from exc
    owner.check()
    profile.require(type(response.value) is dict)
    return app._policy_shadow_publication_stage_record(response,
        management_request_json=claim["management_request_json"], actor_id=owner.identity.user_id)


def _stored(claim):
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM policy_shadow_generation_publications WHERE generation_publication_envelope_digest = ?",
            (claim["publication_envelope_digest"],)).fetchone()
    profile.require(row is not None and row["request_id"] == claim["request_id"]
        and row["management_request_json"] == claim["management_request_json"]
        and row["generation_publication_envelope_digest"] == claim["publication_envelope_digest"])
    return dict(row)


def recover(owner, value):
    from serverware import app
    from serverware import control_plane_policy_candidate as intake
    profile.require(type(owner) is intake._Owner and owner.request.url.path == intake.PREFIX + "/recover"
        and set(value) == {"apiVersion", "requestId"} and value["apiVersion"] == profile.HTTP_SCHEMA)
    owner.check()
    claim = intake._claim(value["requestId"])
    profile.require(claim is not None and claim["actor_id"] == owner.identity.user_id
        and claim["configuration_digest"] == owner.configuration and claim["issued_at_epoch_ns"] <= owner.epoch)
    # A new HTTP request is not a renewal. Even known-result recovery uses the
    # original <=30-second window; historical inspection remains /lookup only.
    owner.clip(claim["expires_at_epoch_ns"])
    owner.claim_original = profile.row_original(claim).decode("ascii")
    if claim["publication_envelope_digest"] is not None:
        publication = _stored(claim)
    else:
        record = _read_native(owner, claim)
        profile.require(intake._claim(value["requestId"]) == claim)
        arguments = {"actor_id": owner.identity.user_id, "control_plane_configuration_digest": owner.configuration,
            "request": {"claimOriginal": owner.claim_original, "record": record,
                "verificationInputs": intake._verification_inputs(record)}}
        # This is the original controlled writer, not recovery-specific DML.
        # It reverifies original signatures/current trust and CASes the exact
        # consumed claim + current predecessors in one audited transaction.
        result = owner.dispatch(profile.OP_PUBLISH, arguments)
        retained = intake._claim(value["requestId"])
        profile.require(retained is not None and retained == {
            **claim, "publication_envelope_digest": result["publication"]["generation_publication_envelope_digest"]})
        publication = _stored(retained)
        profile.require(publication == result["publication"])
    owner.check()
    return {"apiVersion": "serverware.policyCandidateGenerationResult/v1", "automaticRetryAllowed": False,
        "requestId": claim["request_id"], "publication": app._policy_shadow_publication_result(publication, recovered=True)}
