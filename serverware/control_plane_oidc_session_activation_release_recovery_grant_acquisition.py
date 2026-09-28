"""One original-only recovery-grant exchange, without public permission.

Independent policy/resource originals and a separately configured fixed issuer
endpoint enter explicitly. No parent actor configuration, durable retry gate,
release staging, private outcome observation or token opening is supplied here.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_release_recovery_grant_transport as transport
from serverware import oidc_session_activation_release_recovery_grant_admission as receiving


issuer, production = receiving.issuer, receiving.production
authorization, capture = issuer.authorization, issuer.capture
MAX_ORIGINAL_BYTES = receiving.MAX_ORIGINAL_BYTES


class OidcSessionActivationReleaseRecoveryGrantAcquisitionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryGrantAcquisitionError(message)


def _acquire_on_work(*, request_originals, issuer_policy_bytes, release_custody_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_public_key, endpoint,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Return only the actual original-admission result after one exchange."""
    capture._SharedLedger(work)
    request = production._request_originals(request_originals)
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent recovery issuer policy")
    custody_raw = authorization._original(release_custody_bytes, issuer.MAX_CUSTODY_BYTES,
        "independent historical release custody")
    proof_raw = authorization._original(proof_enrollment_bytes, issuer.MAX_PROOF_ENROLLMENT_BYTES,
        "independent recovery proof enrollment")
    intent_raw = authorization._original(intent_enrollment_bytes, issuer.MAX_INTENT_ENROLLMENT_BYTES,
        "independent recovery intent enrollment")
    selected_endpoint = transport._endpoint(endpoint)
    root = root_public_key
    window = issuer.clock._validate(live_window)
    issuer.shape._integer(transport_deadline_ns, minimum=1)
    lifetime = production._Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    originals = (*request, policy_raw, custody_raw, proof_raw, intent_raw)
    # Reserve both policy admissions and their historical nested originals;
    # reserve eight reply footprints for native buffers and genuine receiving.
    # This deliberately tightens individual codec maxima rather than borrowing
    # their separate allowances or accepting an oversized reply then rejecting.
    held = (16 * len(custody_raw)
        + 8 * receiving._unique_bytes((*request, policy_raw, proof_raw, intent_raw))
        + 4096 + 4 * transport.REQUEST_HEADER_BYTES + 4 * transport.RESPONSE_HEADER_BYTES
        + len(transport.PURPOSE))
    if MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or held >= MAX_ORIGINAL_BYTES:
        _fail("recovery grant acquisition exhausts its original aggregate capacity")
    maximum_response = min(transport.MAX_RESPONSE_BYTES, (MAX_ORIGINAL_BYTES - held) // 8)
    maximum_response = transport._response_limit(maximum_response)
    work.charge(input_bytes=sum(map(len, originals)))
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_raw, release_custody_bytes=custody_raw,
        proof_enrollment_bytes=proof_raw, intent_enrollment_bytes=intent_raw,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("recovery grant acquisition requires genuine independent policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    current()
    production.shared._same_bytes(request[2], proof_raw, work,
        "recovery acquisition exact independently enrolled proof original")
    production.shared._same_bytes(request[4], intent_raw, work,
        "recovery acquisition exact independently enrolled intent original")
    current()
    wire = transport._originals((transport.PURPOSE, *request), response=False)
    response = transport._socket_request_on_work(selected_endpoint, originals=wire,
        deadline_ns=lifetime.bound, work=work, current=current,
        maximum_response_bytes=maximum_response)
    current()
    response = transport._originals(response, response=True)
    admitted = receiving._verify_on_work(response_originals=response, request_originals=request,
        issuer_policy_bytes=policy_raw, release_custody_bytes=custody_raw,
        proof_enrollment_bytes=proof_raw, intent_enrollment_bytes=intent_raw,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(admitted) is not receiving._RecoveryGrantMaterial:
        _fail("recovery grant acquisition requires actual triple-original admission")
    current()
    admitted.live()
    return admitted
