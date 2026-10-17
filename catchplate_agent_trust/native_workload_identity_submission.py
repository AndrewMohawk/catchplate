"""Explicit native options/submission, not diagnostic-derived CA authority.

The pinned native grant is a requested association here, not locally verified
issuance permission. The server independently replays its signed cold scope and
all authority originals. Only the retained request/key and independent issuer
can admit a returned leaf locally. No catchplate import or v1 packet alias exists.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import re
import time

from . import _workload_operator_http as http
from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from . import native_workload_identity_provisioning as native_local
from . import workload_identity_provisioning as local
from . import workload_identity_submission as shared
from ._workload_stream import Budget, WorkloadClientError


POST_PATH, OPTIONS_PATH, ACTION = shared.POST_PATH, shared.OPTIONS_PATH, shared.ACTION
REQUEST_SCHEMA, RESPONSE_SCHEMA = shared.REQUEST_SCHEMA, shared.RESPONSE_SCHEMA
MAX_RECEIPT_BYTES = shared.MAX_RECEIPT_BYTES
MAX_PACKET_BYTES = 512 * 1024
MAX_AUTHORIZATION_BYTES = 32 * 1024
_FIXED_RESERVATION = http.RESERVATION_BYTES + 4 * 1024 * 1024
_MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_GRANT_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "bootstrapDigest",
    "configurationDigest", "authorizationKeySpkiDigest", "issuerCertificateSha256",
    "issuerCertificateDerSha256", "issuerSpkiSha256", "policyHash", "releaseRecordSha256",
    "runtimeConfigurationSha256", "runtimeCaCertificateSha256", "runtimeCaSpkiSha256",
    "journalNamespace", "grantId", "packetSha256", "delegationSha256", "setupSha256",
    "policyRequirementsSha256", "identityPolicySha256", "certificateSelectorsSha256",
    "requestSha256", "csrSha256", "subjectPublicKeyInfoSha256", "principalId", "nonce",
    "selectedSans", "serialNumber", "notBeforeEpochSeconds", "notAfterEpochSeconds",
    "issuedAtEpochNs", "expiresAtEpochNs",
})
IssuanceOptions, SubmittedIdentity = shared.IssuanceOptions, shared.SubmittedIdentity


def _fail():
    raise WorkloadClientError("native workload issuance originals or association were refused")


def _preflight(pins, budget):
    held, packet_limit = shared._preflight(pins, budget)
    upper = sum((size * 8 + 5) // 6 for size in (
        MAX_AUTHORIZATION_BYTES, packet_limit, local.MAX_REQUEST_BYTES)) + 32 * 1024 + 4096
    # Native nested originals and the HTTP encoding coexist. This forecast
    # precedes body reads and never supplies another budget or allowance.
    if (upper > http.MAX_REQUEST_BYTES
            or _FIXED_RESERVATION + 16 * held + 16 * upper > _MAX_ORIGINAL_BYTES):
        _fail()
    return held, packet_limit


def _binding(admission, authorization, budget):
    envelope = shared._json(authorization.raw, MAX_AUTHORIZATION_BYTES, budget)
    shared._object(envelope, {"schema", "payload", "signature"})
    if (envelope["schema"] != "catchplate.signedNativeWorkloadIdentityIssuanceAuthorization/v1"
            or type(envelope["signature"]) is not str
            or re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", envelope["signature"]) is None
            or packets._canonical(envelope, MAX_AUTHORIZATION_BYTES, budget) != authorization.raw):
        _fail()
    if len(shared._decode(envelope["signature"][8:], 64)) != 64:
        _fail()
    grant = shared._object(envelope["payload"], _GRANT_FIELDS)
    if (grant["schema"] != "catchplate.nativeWorkloadIdentityIssuanceAuthorization/v1"
            or grant["purpose"] != "native-workload-identity-issuance"
            or grant["trustMode"] != "trusted-host-local"):
        _fail()
    for name in _GRANT_FIELDS:
        if name.endswith(("Sha256", "Digest")) or name == "policyHash":
            shared._digest(grant[name])
    shared._text(grant["sourceRevision"], 128)
    for name in ("grantId", "journalNamespace"):
        text = shared._text(grant[name], 128)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", text) is None:
            _fail()
    requested, components = admission.requested, admission.packet_components
    # Component extraction is DATA ONLY. The server verifies the independent
    # signatures; these comparisons bind exact pinned bytes, never permission.
    expected = {
        "packetSha256": admission.packet_original.sha256,
        "delegationSha256": local._digest(components.delegation_bytes),
        "setupSha256": local._digest(components.setup_authorization_bytes),
        "policyRequirementsSha256": local._digest(components.policy_requirements_bytes),
        "requestSha256": admission.request_original.sha256,
        "csrSha256": requested.csr_digest,
        "subjectPublicKeyInfoSha256": requested.subject_public_key_digest,
        "issuerCertificateSha256": admission.issuer_original.sha256,
        "issuerCertificateDerSha256": requested.issuer_certificate_der_digest,
        "issuerSpkiSha256": requested.issuer_spki_digest,
        "principalId": requested.principal_id, "nonce": requested.nonce,
    }
    if any(type(grant[name]) is not type(value) or grant[name] != value
            for name, value in expected.items()):
        _fail()
    if packets._canonical(grant["selectedSans"], 8192, budget) != packets._canonical(
            admission.selected, 8192, budget):
        _fail()
    serial = grant["serialNumber"]
    if (type(serial) is not str or re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", serial) is None
            or int(serial, 16) >= 1 << 159):
        _fail()
    for name in ("notBeforeEpochSeconds", "notAfterEpochSeconds"):
        if type(grant[name]) is not int or not 1 <= grant[name] <= 9_223_372_036:
            _fail()
    before, after = grant["notBeforeEpochSeconds"], grant["notAfterEpochSeconds"]
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        if type(grant[name]) is not int or not 1 <= grant[name] < 1 << 63:
            _fail()
    if (not 0 < grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= 300_000_000_000
            or not grant["issuedAtEpochNs"] <= before * 1_000_000_000
                < after * 1_000_000_000 <= grant["expiresAtEpochNs"]
            or not requested.created_at_epoch_ms <= before * 1000
                < after * 1000 <= requested.expires_at_epoch_ms):
        _fail()
    binding = {"action": ACTION, "authorizationDigest": authorization.sha256,
        "packetDigest": admission.packet_original.sha256,
        "requestDigest": admission.request_original.sha256,
        "principalId": requested.principal_id, "nonce": requested.nonce,
        "bootstrapDigest": grant["bootstrapDigest"],
        "configurationDigest": grant["configurationDigest"],
        "issuerCertificateDigest": admission.issuer_original.sha256, "grantId": grant["grantId"]}
    resource = local._digest(packets._canonical({"principalId": requested.principal_id,
        "nonce": requested.nonce}, 32 * 1024, budget))
    digest = local._digest(packets._canonical(binding, 32 * 1024, budget))
    return grant, resource, digest


def _body(admission, authorization, mfa, held, budget):
    originals = (authorization.raw, admission.packet_original.raw, admission.request_original.raw)
    mfa_size = 0 if mfa is None else len(packets._canonical(mfa, 32 * 1024, budget))
    upper = sum((len(raw) * 8 + 5) // 6 for raw in originals) + mfa_size + 4096
    if (upper > http.MAX_REQUEST_BYTES
            or _FIXED_RESERVATION + 16 * held + 16 * upper > _MAX_ORIGINAL_BYTES):
        _fail()
    value = {"schema": REQUEST_SCHEMA, **{name: shared._wrap(raw) for name, raw in zip(
        ("authorization", "packet", "request"), originals)}}
    if mfa is not None:
        value["mfa"] = mfa
    return packets._canonical(value, upper, budget)


def _safe_result(response, grant, authorization, admission, resource, digest, budget):
    if type(response.status) is not int or type(response.body) is not bytes:
        _fail()
    if response.status == 428:
        return "approval-required", shared._approval(response.body, resource, digest, budget), None
    value = shared._json(response.body, http.MAX_RESPONSE_BYTES, budget)
    certificate = None
    if response.status == 200:
        shared._object(value, {"schema", "status", "association", "certificate",
            "proxyAuthenticated", "enrollmentComplete", "automaticRetryAllowed"})
        if value["status"] != "certificate-issued":
            _fail()
        certificate = shared._unwrap(value["certificate"], local.MAX_CERTIFICATE_BYTES)
        expected = {"schema": "catchplate.workloadIdentityIssuerResponse/v1",
            "authorizationDigest": authorization.sha256,
            "requestDigest": admission.request_original.sha256,
            "issuerCertificateDigest": admission.issuer_original.sha256,
            "certificateSha256": local._digest(certificate), "serialNumber": grant["serialNumber"]}
        shared._object(value["association"], expected)
        if any(type(value["association"][name]) is not type(item)
                or value["association"][name] != item for name, item in expected.items()):
            _fail()
    else:
        if response.status not in {400, 401, 403, 405, 409, 412, 413, 415, 503}:
            _fail()
        shared._object(value, {"schema", "status", "automaticRetryAllowed",
            "proxyAuthenticated", "enrollmentComplete"})
        if value["status"] not in {"refused", "issuance-outcome-unknown"}:
            _fail()
    if (value["schema"] != RESPONSE_SCHEMA or value["automaticRetryAllowed"] is not False
            or value["proxyAuthenticated"] is not False or value["enrollmentComplete"] is not False):
        _fail()
    if certificate is not None:
        admission.verify_leaf(certificate, expected_leaf=(int(grant["serialNumber"], 16),
            grant["notBeforeEpochSeconds"], grant["notAfterEpochSeconds"]))
    return value["status"], None, certificate


def _run(*, connection, packet, issuer, authorization, request, expected_principal,
        expected_nonce, requested_sans, output_directory, timeout_ms, private_key=None,
        options=None, assertion=None, approval=None, issue=False):
    budget = Budget(timeout_ms)
    pins = [(packet, MAX_PACKET_BYTES, False), (issuer, local.MAX_CERTIFICATE_BYTES, False),
        (authorization, MAX_AUTHORIZATION_BYTES, False), (request, local.MAX_REQUEST_BYTES, False)]
    if issue:
        pins += [(private_key, local._PRIVATE_KEY_BYTES, True),
            (options, MAX_RECEIPT_BYTES, True), (assertion, 32 * 1024, True)]
        if approval is not None:
            pins.append((approval, MAX_RECEIPT_BYTES, True))
    held, packet_limit = _preflight(pins, budget)
    with ExitStack() as owners:
        transport = http._prepare_on_budget(connection, budget=budget, owners=owners)
        admission = native_local._certificate_admission_on_budget(packet=packet, issuer=issuer,
            request=request, expected_principal=expected_principal, expected_nonce=expected_nonce,
            requested_sans=requested_sans, private_key=private_key, output_directory=output_directory,
            budget=budget, owners=owners, _maximum_packet_bytes=packet_limit)
        authorization_original = tls._load_original(authorization, MAX_AUTHORIZATION_BYTES,
            False, budget, owners)
        grant, resource, digest = _binding(admission, authorization_original, budget)
        protected, mfa = [], None
        if issue:
            option_original = tls._load_original(options, MAX_RECEIPT_BYTES, True, budget, owners)
            option_body = shared._receipt(option_original, origin=connection.origin,
                path=OPTIONS_PATH, status=200, budget=budget)
            public = shared._options(option_body, resource, digest, budget)
            assertion_original = tls._load_original(assertion, 32 * 1024, True, budget, owners)
            mfa = {"assertion": shared._assertion(assertion_original.raw, public, connection.origin, budget)}
            protected += [option_original, assertion_original]
            if approval is not None:
                approval_original = tls._load_original(approval, MAX_RECEIPT_BYTES, True, budget, owners)
                body = shared._receipt(approval_original, origin=connection.origin,
                    path=POST_PATH, status=428, budget=budget)
                mfa["approvalId"] = shared._approval(body, resource, digest, budget)
                protected.append(approval_original)
        last_wall, failed = 0, False

        def current():
            nonlocal last_wall, failed
            if failed:
                _fail()
            failed = True
            admission.current()
            authorization_original.recheck(budget)
            now = time.time_ns()
            if (now < last_wall or not grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"]
                    or not grant["notBeforeEpochSeconds"] * 1_000_000_000 <= now
                        < grant["notAfterEpochSeconds"] * 1_000_000_000):
                _fail()
            last_wall = now
            for original in protected:
                original.recheck(budget)
            transport.current()
            failed = False

        current()
        body = _body(admission, authorization_original, mfa, held, budget)
        if issue:
            claim = packets._canonical({"schema": "catchplate.nativeWorkloadIdentitySubmissionClaim/v1",
                "origin": connection.origin, "action": ACTION, "resourceId": resource,
                "payloadDigest": digest, "authorizationDigest": authorization_original.sha256,
                "packetDigest": admission.packet_original.sha256,
                "requestDigest": admission.request_original.sha256,
                "optionsReceiptDigest": options.sha256,
                "approvalReceiptDigest": None if approval is None else approval.sha256}, 32 * 1024, budget)
            admission.directory.publish("submission.claim", claim, budget)
        current()
        response = transport.post(path=POST_PATH if issue else OPTIONS_PATH, body=body)
        current()
        if not issue:
            if response.status != 200:
                _fail()
            shared._options(response.body, resource, digest, budget)
            pin = shared._retain(response, admission=admission, origin=connection.origin,
                path=OPTIONS_PATH, name="options-response.json", budget=budget)
            current()
            result = IssuanceOptions(pin, ACTION, resource, digest)
        else:
            status, approval_id, certificate = _safe_result(response, grant, authorization_original,
                admission, resource, digest, budget)
            current()
            pin = shared._retain(response, admission=admission, origin=connection.origin,
                path=POST_PATH, name="submission-response.json", budget=budget)
            identity = None
            if certificate is not None:
                certificate_pin = admission.directory.publish("issued-certificate.pem", certificate, budget)
                identity = admission.publish(certificate_pin, _expected_leaf=(int(grant["serialNumber"], 16),
                    grant["notBeforeEpochSeconds"], grant["notAfterEpochSeconds"]))
            current()
            result = SubmittedIdentity(status, pin, identity, approval_id)
    budget.check()
    return result


def request_issuance_options(*, connection, packet: tls.PinnedFile, issuer: tls.PinnedFile,
        authorization: tls.PinnedFile, request: tls.PinnedFile, expected_principal: str,
        expected_nonce: str, requested_sans: dict[str, list[str]], output_directory: Path | str,
        timeout_ms: int = 30_000) -> IssuanceOptions:
    """One native options request; no assertion submission or CA-worker contact."""
    try:
        return _run(connection=connection, packet=packet, issuer=issuer, authorization=authorization,
            request=request, expected_principal=expected_principal, expected_nonce=expected_nonce,
            requested_sans=requested_sans, output_directory=output_directory, timeout_ms=timeout_ms)
    except Exception:
        raise WorkloadClientError("native workload options unavailable; no issuance was requested") from None


def submit_issuance(*, connection, packet: tls.PinnedFile, issuer: tls.PinnedFile,
        authorization: tls.PinnedFile, request: tls.PinnedFile, expected_principal: str,
        expected_nonce: str, requested_sans: dict[str, list[str]], private_key: tls.PinnedFile,
        options: tls.PinnedFile, assertion: tls.PinnedFile, output_directory: Path | str,
        approval: tls.PinnedFile | None = None, timeout_ms: int = 30_000) -> SubmittedIdentity:
    """One sticky attempt; only an explicit exact 428 permits fresh continuation."""
    try:
        return _run(connection=connection, packet=packet, issuer=issuer, authorization=authorization,
            request=request, expected_principal=expected_principal, expected_nonce=expected_nonce,
            requested_sans=requested_sans, output_directory=output_directory, timeout_ms=timeout_ms,
            private_key=private_key, options=options, assertion=assertion, approval=approval, issue=True)
    except Exception:
        raise WorkloadClientError("native workload issuance not confirmed; retain this attempt directory and do not retry an unknown outcome") from None
