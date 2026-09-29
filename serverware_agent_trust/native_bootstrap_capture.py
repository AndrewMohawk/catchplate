"""Extract exact public packet bytes; no signature, quote or success authority.

The native client capture is a local diagnostic, not an authenticated receipt.
Pinned acquisition and request association do not change that trust boundary.
The original native issuer must still authenticate every issuance authority.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
import json
from pathlib import Path
import re

from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from . import native_enrollment_packet as native_packet
from . import workload_identity_bootstrap_originals as requests
from . import workload_identity_provisioning as local
from ._workload_stream import Budget, WorkloadClientError


MAX_CAPTURE_BYTES = 1536 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
_CAPTURE_FIELDS = frozenset({"apiVersion", "resultScope", "okForAction",
    "configurationSha256", "requestSha256", "endpoint", "challengeSource",
    "evidenceBase64url", "verification"})
_CAPTURE_V2_FIELDS = _CAPTURE_FIELDS | {"installation"}
_CAPTURE_V3_FIELDS = _CAPTURE_FIELDS | {"egress"}
_CAPTURE_V4_FIELDS = _CAPTURE_FIELDS | {"egress", "attachment"}
_INSTALLATION_FIELDS = frozenset({"apiVersion", "resultScope", "okForAction", "status",
    "authorizationSha256", "operationSha256", "reservationSha256", "setupSha256",
    "capabilityId", "runtimeCaCertificateSha256", "destinationPath"})
_EGRESS_FIELDS = frozenset({"apiVersion", "resultScope", "okForAction", "status",
    "authorizationSha256", "creationSlotSha256", "creationRecordSha256",
    "kernelSemanticSha256", "kernelEvidenceSha256", "workload"})
_ATTACHMENT_FIELDS = frozenset({"apiVersion", "resultScope", "okForAction", "status",
    "authorizationSha256", "planSha256", "evidenceSha256", "semanticSha256"})
_WORKLOAD_U32_FIELDS = frozenset({"launcherProcessId", "launcherThreadId",
    "childProcessId", "backendPortId"})
_WORKLOAD_U64_FIELDS = frozenset({"pidfdDevice", "pidfdInode", "namespaceDevice",
    "namespaceInode", "backendSocketDevice", "backendSocketInode"})
_EVIDENCE_FIELDS = frozenset({"apiVersion", "evidenceScope", "okForAction",
    "packetBase64url", "ingressSessionEvidenceBase64url", "enrollmentSignatureBase64url",
    "enrollmentPublicKeyBase64url", "enrollmentQuoteBase64url"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9_-]+\Z")
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")


def _fail():
    raise WorkloadClientError("native bootstrap capture extraction was refused")


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        _fail()
    return value


def _base64_original(value, maximum, budget):
    if (type(value) is not str or not 1 <= len(value) <= (maximum * 8 + 5) // 6
            or _BASE64.fullmatch(value) is None):
        _fail()
    budget.check()
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if (not 1 <= len(raw) <= maximum
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        _fail()
    packets._charge(budget, input_bytes=len(raw))
    budget.check()
    return raw


def _installation_data(value, budget):
    """Check only a closed bounded representation, never installation state."""
    budget.check()
    value = _object(value, _INSTALLATION_FIELDS)
    if (value["apiVersion"] != "serverware.nativeCaInstallationReceipt/v1"
            or value["resultScope"] != "local-authorized-native-ca-installation-only"
            or value["okForAction"] is not False
            or value["status"] not in ("installed", "already-complete")):
        _fail()
    for name in ("authorizationSha256", "operationSha256", "reservationSha256",
            "setupSha256", "runtimeCaCertificateSha256"):
        if type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None:
            _fail()
    capability = value["capabilityId"]
    if type(capability) is not str or _CAPABILITY.fullmatch(capability) is None:
        _fail()
    path = value["destinationPath"]
    if (type(path) is not str or not 2 <= len(path) <= 4096 or not path.startswith("/")
            or not path.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in path)
            or "\\" in path or any(part in ("", ".", "..") for part in path[1:].split("/"))):
        _fail()
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(raw) <= 8191:
        _fail()
    packets._charge(budget, input_bytes=len(raw))
    budget.check()


def _egress_data(value, budget):
    """Check data shape only; never infer kernel, workload or journal ownership."""
    budget.check()
    value = _object(value, _EGRESS_FIELDS)
    if (value["apiVersion"] != "serverware.nativeEgressObservation/v1"
            or value["resultScope"] != "local-authorized-egress-observed-before-owner-teardown"
            or value["okForAction"] is not False
            or value["status"] not in ("observed-created", "observed-complete")):
        _fail()
    for name in ("authorizationSha256", "creationSlotSha256", "creationRecordSha256",
            "kernelSemanticSha256", "kernelEvidenceSha256"):
        if type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None:
            _fail()
    workload = _object(value["workload"], _WORKLOAD_U32_FIELDS | _WORKLOAD_U64_FIELDS)
    for names, maximum in ((_WORKLOAD_U32_FIELDS, (1 << 32) - 1),
            (_WORKLOAD_U64_FIELDS, (1 << 64) - 1)):
        for name in names:
            # In particular, bool is not an integer and large inode values are
            # never converted through floating point or truncated to JS width.
            if type(workload[name]) is not int or not 0 <= workload[name] <= maximum:
                _fail()
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(raw) <= 8191:
        _fail()
    packets._charge(budget, input_bytes=len(raw))
    budget.check()


def _attachment_data(value, budget):
    """Check observation shape only; no link, route or connectivity authority."""
    budget.check()
    value = _object(value, _ATTACHMENT_FIELDS)
    if (value["apiVersion"] != "serverware.nativeNetworkAttachmentObservation/v1"
            or value["resultScope"] != "local-authorized-network-attachment-observed-before-owner-teardown"
            or value["okForAction"] is not False
            or value["status"] != "observed-attached"):
        _fail()
    for name in ("authorizationSha256", "planSha256", "evidenceSha256", "semanticSha256"):
        if type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None:
            _fail()
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(raw) <= 8191:
        _fail()
    packets._charge(budget, input_bytes=len(raw))
    budget.check()


def _packet_on_budget(capture_bytes, target_request_bytes, budget):
    """Return unverified data only; this function never returns a verdict."""
    budget.check()
    if (type(capture_bytes) is not bytes or not 1 <= len(capture_bytes) <= MAX_CAPTURE_BYTES
            or not capture_bytes.endswith(b"\n") or b"\n" in capture_bytes[:-1]
            or b"\r" in capture_bytes
            or type(target_request_bytes) is not bytes
            or not 1 <= len(target_request_bytes) <= requests.MAX_REQUEST_BYTES):
        _fail()
    # Reserve for the bounded original representations before nested decoding.
    # This is a representation ceiling, not a process-memory or watchdog claim.
    reserve = (16 * len(capture_bytes) + 16 * MAX_EVIDENCE_BYTES
        + 16 * native_packet.MAX_BYTES + 16 * len(target_request_bytes) + 1024 * 1024)
    if reserve > native_packet.MAX_ORIGINAL_BYTES:
        _fail()
    value = packets._parse_packet(capture_bytes, budget)
    if value.get("apiVersion") == "serverware.nativeBootstrapClientCapture/v1":
        value = _object(value, _CAPTURE_FIELDS)
        expected_scope = "local-fixed-endpoint-bootstrap-originals-only"
    elif value.get("apiVersion") == "serverware.nativeBootstrapClientCapture/v2":
        value = _object(value, _CAPTURE_V2_FIELDS)
        expected_scope = "local-fixed-endpoint-bootstrap-and-host-installation"
        _installation_data(value["installation"], budget)
    elif value.get("apiVersion") == "serverware.nativeBootstrapClientCapture/v3":
        value = _object(value, _CAPTURE_V3_FIELDS)
        expected_scope = "local-fixed-endpoint-bootstrap-and-egress-observation"
        _egress_data(value["egress"], budget)
    elif value.get("apiVersion") == "serverware.nativeBootstrapClientCapture/v4":
        value = _object(value, _CAPTURE_V4_FIELDS)
        expected_scope = "local-fixed-endpoint-bootstrap-and-network-attachment-observation"
        _egress_data(value["egress"], budget)
        _attachment_data(value["attachment"], budget)
    else:
        _fail()
    if (value["resultScope"] != expected_scope or value["okForAction"] is not False
            or value["challengeSource"] != "independently-pinned"):
        _fail()
    for name in ("configurationSha256", "requestSha256"):
        if type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None:
            _fail()
    endpoint = value["endpoint"]
    if (type(endpoint) is not str or not 1 <= len(endpoint) <= 64
            or not endpoint.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in endpoint)):
        _fail()
    diagnostic = value["verification"]
    if type(diagnostic) is not dict:
        _fail()
    # Match the producing client's bounded diagnostic representation, but do
    # not read any success/measurement/identity claim from it as authority.
    diagnostic_bytes = json.dumps(diagnostic, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(diagnostic_bytes) <= 4095:
        _fail()
    budget.check()
    evidence_raw = _base64_original(value["evidenceBase64url"], MAX_EVIDENCE_BYTES, budget)
    native_packet._flat_preflight(evidence_raw, budget)
    evidence = _object(packets._parse_packet(evidence_raw, budget), _EVIDENCE_FIELDS)
    if (evidence["apiVersion"] != "serverware.nativeEnrollmentBootstrapEvidence/v1"
            or evidence["evidenceScope"] != "unverified-bootstrap-enrollment-public-material"
            or evidence["okForAction"] is not False
            or packets._canonical(evidence, MAX_EVIDENCE_BYTES - 1, budget) + b"\n" != evidence_raw):
        _fail()
    packet = _base64_original(evidence["packetBase64url"], native_packet.MAX_BYTES, budget)
    for name, maximum, exact in (
            ("ingressSessionEvidenceBase64url", 96 * 1024, None),
            ("enrollmentSignatureBase64url", 64, 64),
            ("enrollmentPublicKeyBase64url", 32, 32),
            ("enrollmentQuoteBase64url", 12 * 1024, None)):
        raw = _base64_original(evidence[name], maximum, budget)
        if ((exact is not None and len(raw) != exact)
                or (name == "enrollmentPublicKeyBase64url" and not any(raw))):
            _fail()
    originals = native_packet.decode_packet_originals_on_budget(packet_bytes=packet, budget=budget)
    if originals.target_request_bytes != target_request_bytes:
        _fail()
    exchange = {"apiVersion": "serverware.nativeEnrollmentBootstrapRequest/v1"}
    for name, raw in (("delegationBase64url", originals.delegation_bytes),
            ("setupAuthorizationBase64url", originals.setup_authorization_bytes),
            ("targetRequestBase64url", originals.target_request_bytes)):
        exchange[name] = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    request_raw = packets._canonical(exchange, 192 * 1024 - 1, budget) + b"\n"
    if packets._digest(request_raw, budget) != value["requestSha256"]:
        _fail()
    budget.check()
    return packet


def extract_packet(*, capture: tls.PinnedFile, target_request: tls.PinnedFile,
        output_directory: Path | str, timeout_ms: int = 30_000) -> tls.PinnedFile:
    """Publish one no-overwrite native-packet.json from exact pinned originals.

    No network, key access, issuance, installation, lifetime renewal or retry.
    The caller retains the producer exit status separately. Even a parseable
    capture following failed acquisition is not a successful acquisition proof.
    """
    try:
        budget = Budget(timeout_ms)
        tls._require_linux()
        with ExitStack() as owners:
            capture_original = tls._load_original(capture, MAX_CAPTURE_BYTES, False, budget, owners)
            request_original = tls._load_original(target_request, requests.MAX_REQUEST_BYTES,
                False, budget, owners)
            packet = _packet_on_budget(capture_original.raw, request_original.raw, budget)
            directory = local._Directory(output_directory, budget, owners)
            capture_original.recheck(budget)
            request_original.recheck(budget)
            result = directory.publish("native-packet.json", packet, budget)
            capture_original.recheck(budget)
            request_original.recheck(budget)
            directory.check(budget)
            budget.check()
            return result
    except WorkloadClientError:
        raise WorkloadClientError("native bootstrap capture extraction was refused") from None
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        raise WorkloadClientError("native bootstrap capture extraction was refused") from None
