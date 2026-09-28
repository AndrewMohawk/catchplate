"""Explicit operator options and one-shot workload certificate submission.

Local packet/request possession is not issuance authority. The independently
supplied grant is genuinely verified by the server, not minted or replaced by
this client. Each attempt directory is sticky, not a global deduplication store.
Only an exact retained 428 permits an explicit approved continuation with fresh
options/assertion in another directory. Unknown outcomes never authorize retry.
No packet, CA-install capability, cookie, assertion or key is journaled here.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import re
import time

from . import _workload_operator_http as http
from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from . import workload_identity_provisioning as local
from ._workload_stream import Budget, WorkloadClientError


POST_PATH = "/api/agents/workload-identity/issue"
OPTIONS_PATH = POST_PATH + "/options"
ACTION = "workload.identity.issue"
REQUEST_SCHEMA = "serverware.workloadIdentityIssuanceRequest/v1"
RESPONSE_SCHEMA = "serverware.workloadIdentityIssuanceResponse/v1"
RECEIPT_SCHEMA = "serverware.workloadIdentitySubmissionReceipt/v1"
MAX_RECEIPT_BYTES = 192 * 1024
_SMALL_BYTES = 32 * 1024
_MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_FIXED_RESERVATION = http.RESERVATION_BYTES + 4 * 1024 * 1024
_GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "bootstrapDigest", "configurationDigest", "authorizationKeySpkiDigest",
    "issuerCertificateSha256", "issuerSpkiSha256", "packetSigningKeySha256",
    "policyHash", "runtimeManifestDigest", "journalNamespace", "grantId", "packetSha256",
    "requestSha256", "csrSha256", "subjectPublicKeyInfoSha256", "principalId", "nonce",
    "selectedSans", "serialNumber", "notBeforeEpochSeconds", "notAfterEpochSeconds",
    "issuedAtEpochNs", "expiresAtEpochNs"})


@dataclass(frozen=True, slots=True, repr=False)
class IssuanceOptions:
    response: tls.PinnedFile
    action: str
    resource_id: str
    payload_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class SubmittedIdentity:
    status: str
    response: tls.PinnedFile
    identity: local.ProvisionedIdentity | None
    approval_id: str | None


def _fail():
    raise WorkloadClientError("workload issuance originals or action binding were refused")


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()
    return value


def _text(value, maximum=512):
    if (type(value) is not str or not 1 <= len(value.encode("utf-8")) <= maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        _fail()
    return value


def _digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _fail()
    return value


def _json(raw, maximum, budget):
    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        _fail()
    return packets._parse_packet(raw, budget)


def _decode(value, maximum):
    if (type(value) is not str or not 1 <= len(value) <= (maximum * 8 + 5) // 6
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None):
        _fail()
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if (not 1 <= len(raw) <= maximum
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        _fail()
    return raw


def _wrap(raw):
    return {"base64Url": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "byteCount": len(raw), "bytesDigest": local._digest(raw)}


def _unwrap(value, maximum):
    _object(value, {"base64Url", "byteCount", "bytesDigest"})
    if type(value["byteCount"]) is not int or not 1 <= value["byteCount"] <= maximum:
        _fail()
    raw = _decode(value["base64Url"], maximum)
    if len(raw) != value["byteCount"] or local._digest(raw) != _digest(value["bytesDigest"]):
        _fail()
    return raw


def _preflight(pins, budget):
    """Measure held local originals before their bodies; no second allowance."""
    total = 0
    packet_limit = None
    for index, (pin, maximum, protected) in enumerate(pins):
        _, parts = tls._validate_pin(pin)
        descriptor = tls._open_original(parts, budget)
        try:
            budget.check()
            metadata = os.fstat(descriptor)
            tls._check_file(metadata, maximum, protected)
            # Carry the measured packet bound into its actual descriptor read.
            # All other originals reserve their full small caps, so replacement
            # between this measurement and pinned acquisition cannot grow the
            # admitted representation set beyond the pre-body reservation.
            if index == 0:
                packet_limit = metadata.st_size
                total += packet_limit
            else:
                total += maximum
        finally:
            os.close(descriptor)
    if _FIXED_RESERVATION + 8 * total > _MAX_ORIGINAL_BYTES:
        _fail()
    return total, packet_limit


def _binding(admission, authorization, budget):
    # These pinned grant claims select only the exact requested association.
    # No local signature claim is made: the server independently admits the
    # actual original under its cold authorizer before options or any effect.
    envelope = _json(authorization.raw, _SMALL_BYTES, budget)
    _object(envelope, {"schema", "payload", "signature"})
    if (envelope["schema"] != "serverware.signedWorkloadIdentityIssuanceAuthorization/v1"
            or type(envelope["signature"]) is not str
            or re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", envelope["signature"]) is None):
        _fail()
    grant = _object(envelope["payload"], _GRANT_FIELDS)
    if (grant["schema"] != "serverware.workloadIdentityIssuanceAuthorization/v1"
            or grant["purpose"] != "workload-identity-issuance"
            or grant["trustMode"] != "trusted-host-local"):
        _fail()
    expected = {name: admission.binding[name] for name in (
        "packetSha256", "packetSigningKeySha256", "principalId", "nonce",
        "issuerCertificateSha256", "issuerSpkiSha256")}
    expected["requestSha256"] = admission.originals[3].sha256
    expected["subjectPublicKeyInfoSha256"] = local._digest(local._spki(admission.public))
    if any(type(grant[name]) is not type(value) or grant[name] != value
            for name, value in expected.items()):
        _fail()
    if packets._canonical(grant["selectedSans"], 8192, budget) != packets._canonical(
            admission.selected, 8192, budget):
        _fail()
    grant_id = _text(grant["grantId"], 128)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", grant_id) is None:
        _fail()
    serial = grant["serialNumber"]
    if type(serial) is not str or re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", serial) is None:
        _fail()
    if int(serial, 16) >= 1 << 159:
        _fail()
    for name in ("notBeforeEpochSeconds", "notAfterEpochSeconds"):
        if type(grant[name]) is not int or not 1 <= grant[name] <= 253402300799:
            _fail()
    if grant["notBeforeEpochSeconds"] >= grant["notAfterEpochSeconds"]:
        _fail()
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        if type(grant[name]) is not int or not 1 <= grant[name] < 1 << 63:
            _fail()
    if (not 0 < grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= 900_000_000_000
            or grant["notAfterEpochSeconds"] * 1_000_000_000 > grant["expiresAtEpochNs"]):
        _fail()
    _grant_current(grant)
    binding = {"action": ACTION, "authorizationDigest": authorization.sha256,
        "packetDigest": admission.originals[0].sha256,
        "requestDigest": admission.originals[3].sha256,
        "principalId": admission.binding["principalId"], "nonce": admission.binding["nonce"],
        "bootstrapDigest": _digest(grant["bootstrapDigest"]),
        "configurationDigest": _digest(grant["configurationDigest"]),
        "issuerCertificateDigest": admission.binding["issuerCertificateSha256"], "grantId": grant_id}
    resource = local._digest(packets._canonical({"principalId": binding["principalId"],
        "nonce": binding["nonce"]}, _SMALL_BYTES, budget))
    digest = local._digest(packets._canonical(binding, _SMALL_BYTES, budget))
    return grant, resource, digest


def _grant_current(grant):
    now = time.time_ns()
    if (not grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"]
            or not grant["notBeforeEpochSeconds"] * 1_000_000_000 <= now
                < grant["notAfterEpochSeconds"] * 1_000_000_000):
        _fail()


def _match(value, resource, digest):
    if (value["schema"] != RESPONSE_SCHEMA or value["action"] != ACTION
            or value["resourceId"] != resource or value["payloadDigest"] != digest
            or value["automaticRetryAllowed"] is not False):
        _fail()


def _options(raw, resource, digest, budget):
    value = _json(raw, _SMALL_BYTES, budget)
    _object(value, {"schema", "status", "action", "resourceId", "payloadDigest",
        "options", "automaticRetryAllowed"})
    _match(value, resource, digest)
    if value["status"] != "fresh-assertion-required":
        _fail()
    options = _object(value["options"], {"publicKey", "serverware"})
    public = _object(options["publicKey"], {"challenge", "rpId", "allowCredentials",
        "timeout", "userVerification"})
    metadata = _object(options["serverware"], {"challenge_id", "payload", "payload_digest"})
    payload = _object(metadata["payload"], {"v", "type", "user_id", "action",
        "resource_id", "payload_digest", "nonce"})
    if (type(payload["v"]) is not int or payload["v"] != 1
            or payload["type"] != "serverware.control_plane_mutation"
            or payload["action"] != ACTION or payload["resource_id"] != resource
            or payload["payload_digest"] != digest or public["userVerification"] != "required"
            or type(public["timeout"]) is not int or not 1 <= public["timeout"] <= 120000):
        _fail()
    for item in (payload["user_id"], payload["nonce"], metadata["challenge_id"], public["rpId"]):
        _text(item)
    original = packets._canonical(payload, _SMALL_BYTES, budget)
    challenge = _decode(public["challenge"], 32)
    if len(challenge) != 32:
        _fail()
    expected_digest = local._digest(original)
    if (metadata["payload_digest"] != expected_digest
            or challenge.hex() != expected_digest[7:]):
        _fail()
    credentials = public["allowCredentials"]
    if type(credentials) is not list or not 1 <= len(credentials) <= 64:
        _fail()
    identifiers = set()
    for item in credentials:
        if type(item) is not dict or not {"id", "type"} <= set(item) <= {"id", "type", "transports"}:
            _fail()
        _decode(item["id"], 3072)
        if item["type"] != "public-key" or item["id"] in identifiers:
            _fail()
        identifiers.add(item["id"])
        if "transports" in item and (type(item["transports"]) is not list
                or len(item["transports"]) > 8
                or any(type(entry) is not str or entry not in
                    {"usb", "nfc", "ble", "internal", "hybrid"} for entry in item["transports"])):
            _fail()
    return public


def _receipt(original, *, origin, path, status, budget):
    value = _json(original.raw, MAX_RECEIPT_BYTES, budget)
    _object(value, {"schema", "origin", "path", "httpStatus", "body"})
    if (value["schema"] != RECEIPT_SCHEMA or value["origin"] != origin
            or value["path"] != path or type(value["httpStatus"]) is not int
            or value["httpStatus"] != status):
        _fail()
    return _unwrap(value["body"], http.MAX_RESPONSE_BYTES)


def _approval(raw, resource, digest, budget):
    value = _json(raw, _SMALL_BYTES, budget)
    _object(value, {"schema", "status", "action", "resourceId", "payloadDigest",
        "approvalId", "freshAuthorizationRequired", "automaticRetryAllowed"})
    _match(value, resource, digest)
    if (value["status"] != "approval-required" or value["freshAuthorizationRequired"] is not True
            or type(value["approvalId"]) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value["approvalId"]) is None):
        _fail()
    return value["approvalId"]


def _assertion(raw, public, origin, budget):
    value = _json(raw, _SMALL_BYTES, budget)
    _object(value, {"id", "rawId", "type", "response"})
    if (value["type"] != "public-key" or value["id"] != value["rawId"]
            or value["id"] not in {item["id"] for item in public["allowCredentials"]}):
        _fail()
    response = value["response"]
    required = {"clientDataJSON", "authenticatorData", "signature"}
    if type(response) is not dict or not required <= set(response) <= required | {"userHandle"}:
        _fail()
    client = _json(_decode(response["clientDataJSON"], 8192), 8192, budget)
    if (not {"type", "challenge", "origin"} <= set(client) <=
            {"type", "challenge", "origin", "crossOrigin"}
            or client["type"] != "webauthn.get" or client["challenge"] != public["challenge"]
            or client["origin"] != origin or client.get("crossOrigin", False) is not False):
        _fail()
    _decode(response["authenticatorData"], 8192)
    _decode(response["signature"], 8192)
    if response.get("userHandle") is not None:
        _decode(response["userHandle"], 1024)
    # The server, not this association check, verifies the registered key,
    # signature, cookie user, challenge freshness, role and distinct approver.
    return value


def _body(admission, authorization, mfa, held, budget):
    originals = (authorization.raw, admission.originals[0].raw, admission.originals[3].raw)
    mfa_size = 0 if mfa is None else len(packets._canonical(mfa, _SMALL_BYTES, budget))
    upper = sum((len(raw) * 8 + 5) // 6 for raw in originals) + mfa_size + 4096
    if (upper > http.MAX_REQUEST_BYTES
            or _FIXED_RESERVATION + 8 * held + 16 * upper > _MAX_ORIGINAL_BYTES):
        _fail()
    payload = {"schema": REQUEST_SCHEMA, **{name: _wrap(raw) for name, raw in zip(
        ("authorization", "packet", "request"), originals)}}
    if mfa is not None:
        payload["mfa"] = mfa
    return packets._canonical(payload, upper, budget)


def _retain(response, *, admission, origin, path, name, budget):
    # Only the closed safe public response has reached this point. Preserve its
    # exact bytes and HTTP status, not reconstructed JSON or request material.
    raw = packets._canonical({"schema": RECEIPT_SCHEMA, "origin": origin, "path": path,
        "httpStatus": response.status, "body": _wrap(response.body)}, MAX_RECEIPT_BYTES, budget)
    return admission.directory.publish(name, raw, budget)


def _safe_result(response, grant, authorization, admission, resource, digest, budget):
    if type(response.status) is not int or type(response.body) is not bytes:
        _fail()
    if response.status == 428:
        return "approval-required", _approval(response.body, resource, digest, budget), None
    value = _json(response.body, http.MAX_RESPONSE_BYTES, budget)
    if response.status == 200:
        _object(value, {"schema", "status", "association", "certificate",
            "proxyAuthenticated", "enrollmentComplete", "automaticRetryAllowed"})
        if value["status"] != "certificate-issued":
            _fail()
        certificate = _unwrap(value["certificate"], local.MAX_CERTIFICATE_BYTES)
        expected = {"schema": "serverware.workloadIdentityIssuerResponse/v1",
            "authorizationDigest": authorization.sha256,
            "requestDigest": admission.originals[3].sha256,
            "issuerCertificateDigest": admission.binding["issuerCertificateSha256"],
            "certificateSha256": local._digest(certificate), "serialNumber": grant["serialNumber"]}
        _object(value["association"], expected)
        if any(type(value["association"][name]) is not type(item)
                or value["association"][name] != item for name, item in expected.items()):
            _fail()
        # Do not retain arbitrary response data under a certificate-shaped
        # wrapper. Authenticate the public leaf before journaling the original;
        # final local publication independently repeats it with the retained key.
        leaf = local._leaf(certificate, admission.issuer_certificate, admission.selected,
            admission.public, admission.binding, admission.selectors, budget).certificate
        if (leaf.serial_number != int(grant["serialNumber"], 16)
                or int(leaf.not_valid_before_utc.timestamp()) != grant["notBeforeEpochSeconds"]
                or int(leaf.not_valid_after_utc.timestamp()) != grant["notAfterEpochSeconds"]):
            _fail()
    else:
        if response.status not in {400, 401, 403, 405, 409, 412, 413, 415, 503}:
            _fail()
        _object(value, {"schema", "status", "automaticRetryAllowed",
            "proxyAuthenticated", "enrollmentComplete"})
        if value["status"] not in {"refused", "issuance-outcome-unknown"}:
            _fail()
        certificate = None
    if (value["schema"] != RESPONSE_SCHEMA or value["automaticRetryAllowed"] is not False
            or value["proxyAuthenticated"] is not False or value["enrollmentComplete"] is not False):
        _fail()
    return value["status"], None, certificate


def _run(*, connection, packet, packet_signing_key, issuer, authorization, request,
        expected_principal, expected_nonce, output_directory, timeout_ms,
        private_key=None, options=None, assertion=None, approval=None, issue=False):
    budget = Budget(timeout_ms)
    pins = [(packet, 8 * 1024 * 1024, False), (packet_signing_key, local.MAX_KEY_BYTES, False),
        (issuer, local.MAX_CERTIFICATE_BYTES, False), (authorization, _SMALL_BYTES, False),
        (request, local.MAX_REQUEST_BYTES, False)]
    if issue:
        pins += [(private_key, local._PRIVATE_KEY_BYTES, True),
            (options, MAX_RECEIPT_BYTES, True), (assertion, _SMALL_BYTES, True)]
        if approval is not None:
            pins.append((approval, MAX_RECEIPT_BYTES, True))
    held, packet_limit = _preflight(pins, budget)
    with ExitStack() as owners:
        transport = http._prepare_on_budget(connection, budget=budget, owners=owners)
        admission = local._certificate_admission_on_budget(packet=packet,
            packet_signing_key=packet_signing_key, issuer=issuer,
            expected_principal=expected_principal, expected_nonce=expected_nonce,
            request=request, private_key=private_key, output_directory=output_directory,
            budget=budget, owners=owners, _maximum_packet_bytes=packet_limit)
        authorizer = tls._load_original(authorization, _SMALL_BYTES, False, budget, owners)
        grant, resource, digest = _binding(admission, authorizer, budget)
        protected = []
        mfa = None
        if issue:
            option_original = tls._load_original(options, MAX_RECEIPT_BYTES, True, budget, owners)
            option_body = _receipt(option_original, origin=connection.origin,
                path=OPTIONS_PATH, status=200, budget=budget)
            public = _options(option_body, resource, digest, budget)
            assertion_original = tls._load_original(assertion, _SMALL_BYTES, True, budget, owners)
            mfa = {"assertion": _assertion(assertion_original.raw, public, connection.origin, budget)}
            protected += [option_original, assertion_original]
            if approval is not None:
                approval_original = tls._load_original(approval, MAX_RECEIPT_BYTES, True, budget, owners)
                approved = _receipt(approval_original, origin=connection.origin,
                    path=POST_PATH, status=428, budget=budget)
                mfa["approvalId"] = _approval(approved, resource, digest, budget)
                protected.append(approval_original)

        def current():
            admission.current()
            authorizer.recheck(budget)
            _grant_current(grant)
            for original in protected:
                original.recheck(budget)
            transport.current()

        body = _body(admission, authorizer, mfa, held, budget)
        current()
        if issue:
            claim = packets._canonical({"schema": "serverware.workloadIdentitySubmissionClaim/v1",
                "origin": connection.origin, "action": ACTION, "resourceId": resource,
                "payloadDigest": digest, "authorizationDigest": authorization.sha256,
                "packetDigest": packet.sha256, "requestDigest": request.sha256,
                "optionsReceiptDigest": options.sha256,
                "approvalReceiptDigest": None if approval is None else approval.sha256},
                _SMALL_BYTES, budget)
            admission.directory.publish("submission.claim", claim, budget)
        current()
        response = transport.post(path=POST_PATH if issue else OPTIONS_PATH, body=body)
        current()
        if not issue:
            if response.status != 200:
                _fail()
            _options(response.body, resource, digest, budget)
            pin = _retain(response, admission=admission, origin=connection.origin,
                path=OPTIONS_PATH, name="options-response.json", budget=budget)
            current()
            result = IssuanceOptions(pin, ACTION, resource, digest)
        else:
            status, approval_id, certificate = _safe_result(response, grant, authorizer,
                admission, resource, digest, budget)
            pin = _retain(response, admission=admission, origin=connection.origin,
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


def request_issuance_options(*, connection, packet: tls.PinnedFile,
        packet_signing_key: tls.PinnedFile, issuer: tls.PinnedFile,
        authorization: tls.PinnedFile, request: tls.PinnedFile,
        expected_principal: str, expected_nonce: str, output_directory: Path | str,
        timeout_ms: int = 30_000) -> IssuanceOptions:
    """One explicit options request; never submits an assertion or contacts the CA worker."""
    try:
        return _run(connection=connection, packet=packet, packet_signing_key=packet_signing_key,
            issuer=issuer, authorization=authorization, request=request,
            expected_principal=expected_principal, expected_nonce=expected_nonce,
            output_directory=output_directory, timeout_ms=timeout_ms)
    except Exception:
        raise WorkloadClientError("workload issuance options unavailable; no issuance was requested") from None


def submit_issuance(*, connection, packet: tls.PinnedFile, packet_signing_key: tls.PinnedFile,
        issuer: tls.PinnedFile, authorization: tls.PinnedFile, request: tls.PinnedFile,
        expected_principal: str, expected_nonce: str, private_key: tls.PinnedFile,
        options: tls.PinnedFile, assertion: tls.PinnedFile, output_directory: Path | str,
        approval: tls.PinnedFile | None = None, timeout_ms: int = 30_000) -> SubmittedIdentity:
    """One explicit attempt; preserve its claim and response after every uncertainty."""
    try:
        return _run(connection=connection, packet=packet, packet_signing_key=packet_signing_key,
            issuer=issuer, authorization=authorization, request=request,
            expected_principal=expected_principal, expected_nonce=expected_nonce,
            output_directory=output_directory, timeout_ms=timeout_ms, private_key=private_key,
            options=options, assertion=assertion, approval=approval, issue=True)
    except Exception:
        raise WorkloadClientError("workload issuance not confirmed; retain this attempt directory and do not retry an unknown outcome") from None
