"""One challenged native observation, owned by an actual post-bind Setup read."""
import base64
import secrets
import urllib.error
import urllib.request

from serverware import authority_setup_policy as profile
from serverware import authority_oauth_setup as codec
from serverware import authority_policy_candidate as candidate
from serverware import control_plane_credential_currentness as currentness
from serverware import control_plane_native_loaded_trust as native
from serverware import http_client

PATH = "/v1/native-loaded-policy"
MAX_RESPONSE = 524288
MAX_OBSERVATION = 262144
MAX_EVIDENCE = 131072


def _credential(owner):
    rows = currentness._rows(owner.continuation["credential_id"], owner.continuation["credential_version"])
    profile.require(rows[2]["status"] == "open")
    return profile.canonical(rows)


def observe(owner):
    # Runtime import avoids app initialization cycles and consumes the actual
    # fixed management URL/token owner. Neither value comes from the browser.
    from serverware import app
    owner.check()
    trust = native.Trust(owner)
    owner.current_original = profile.canonical(owner.current())
    credential_original = _credential(owner)
    management = candidate.management_original(owner.claim["management_request_json"])
    assignment, digest = profile.reviewed_assignment(owner.session, management)
    profile.require(digest == owner.continuation["assignment_digest"]
        and assignment["routePolicyDigest"] == owner.continuation["route_policy_digest"])
    policy_raw = profile.canonical(management["candidatePolicyBundle"])
    context = {"continuationSha256": profile.sha256(owner.continuation_original),
        "currentCredentialStateSha256": profile.sha256(credential_original), "assignment": assignment}
    request = {"apiVersion": "serverware.nativeLoadedPolicyRequest/v1",
        "challenge": base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii"),
        "contextSha256": profile.sha256(profile.canonical(context)), "policyHash": assignment["policyHash"],
        "principalId": assignment["principalId"], "routeId": assignment["routeId"], "credentialId": assignment["credentialId"],
        "issuedAtEpochNs": owner.started_epoch, "expiresAtEpochNs": owner.expires}
    original = profile.canonical(request)
    profile.require(0 < len(original) <= 4096 and request["expiresAtEpochNs"] - request["issuedAtEpochNs"] <= 30_000_000_000)
    url, token = app._policy_shadow_generation_url(PATH), app.DATA_PLANE_MANAGEMENT_TOKEN
    profile.require(type(token) is str and 0 < len(token.encode("utf-8")) <= 4096)
    outbound = urllib.request.Request(url, data=original, method="POST", headers={"Accept": "application/json",
        "Accept-Encoding": "identity", "Content-Type": "application/json", "X-Serverware-Data-Plane-Token": token})
    trust.check()
    profile.require(not owner.dispatched)
    owner.dispatched = True  # One observation contact; no implicit replay on failure.
    try:
        response = http_client.request_bytes(outbound, timeout=30, max_bytes=MAX_EVIDENCE,
            deadline=http_client.HttpDeadline(owner.deadline / 1_000_000_000), require_https=False,
            expected_statuses=(200,), expected_content_types=("application/json",))
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError("native observation unavailable") from None
    trust.check()
    # HTTP formatting is not the signature preimage. Reject duplicate members;
    # exact canonical request equality also rejects float/bool integer aliases.
    evidence = codec.document(response.body, MAX_EVIDENCE, exact=False)
    trust.verify(evidence, request, policy_original_sha256=profile.sha256(policy_raw), route_digest=assignment["routePolicyDigest"])
    profile.require(_credential(owner) == credential_original and app._policy_shadow_generation_url(PATH) == url
        and app.DATA_PLANE_MANAGEMENT_TOKEN == token)
    owner.check()
    observation = {"apiVersion": "serverware.setupNativeLoadedPolicyObservation/v1", "scope": "native-loaded-policy-only",
        "okForAction": False, "automaticRetryAllowed": False, "nativeLoadedPolicyVerified": True, "proxyReady": False,
        "continuationSha256": context["continuationSha256"], "currentCredentialStateSha256": context["currentCredentialStateSha256"],
        "requestOriginal": original.decode("ascii"), "evidenceOriginal": profile.canonical(evidence).decode("ascii")}
    raw = profile.canonical(observation)
    profile.require(len(raw) <= MAX_OBSERVATION)
    result = {"apiVersion": "serverware.setupNativePolicyObservation/v1", "okForAction": False,
        "automaticRetryAllowed": False, "proxyReady": False, "setupSessionId": owner.session["id"],
        "observationOriginal": raw.decode("ascii")}
    profile.require(len(profile.canonical(result)) <= MAX_RESPONSE)
    trust.check()
    return result
