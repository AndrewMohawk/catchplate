"""Native packet/request/leaf originals, never certificate issuance authority.

Independent cold roots select setup/delegation and the actual issuer. A separate
issuer grant authorizes the exact originals; no role-5 evidence, CLI diagnostic,
legacy packet signer or runtimeManifestDigest is accepted here. Certificate
selector compatibility does not authenticate a future proxy request.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from serverware import native_enrollment_assignment as assignment
from serverware import native_enrollment_bootstrap_setup as setup
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import native_enrollment_packet as packet
from serverware_agent_trust import workload_identity_bootstrap_originals as request
from serverware_agent_trust import workload_identity_originals as crypto
from serverware_agent_trust.workload_transport import validate_mtls_identity


MAX_PACKET_BYTES = packet.MAX_BYTES
MAX_REQUEST_BYTES = request.MAX_REQUEST_BYTES
MAX_CERTIFICATE_BYTES = request.MAX_CERTIFICATE_BYTES
MAX_REQUIREMENTS_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
REQUIREMENTS_SCHEMA = "serverware.nativeEnrollmentPolicyRequirements/v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,38})\Z")
_MTLS_FIELDS = frozenset({"sanSpiffeIds", "sanDnsNames", "sanUris",
    "certificateSha256", "spkiSha256", "issuerSpkiSha256"})
_PRINCIPAL_FIELDS = frozenset({"id", "identityPolicySha256", "sourceCidrs", "mtls",
    "requiredHeaderNames", "requiredHeaderValues", "proxyAuthorization"})
_POLICY_FIELDS = frozenset({"hash", "id", "sequence", "rollbackEpoch", "trustGeneration",
    "compiledBehaviorSha256", "policySigningKeyId"})
_ROUTE_FIELDS = frozenset({"id", "scheme", "host", "port", "resolvedAddressPolicy",
    "methods", "paths", "credentialRef", "adapterType", "discardHeaders",
    "adapterConfigSha256", "requestPolicySha256", "responsePolicySha256",
    "requiredProviderHeaderNames", "constraintsSha256", "jitSha256", "jitRequired",
    "responseObservation"})


class NativeWorkloadIdentityOriginalsError(ValueError):
    pass


def _fail():
    raise NativeWorkloadIdentityOriginalsError("native workload identity originals are invalid")


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        _fail()
    return value


def _text(value):
    if type(value) is not str or len(value.encode("utf-8")) > MAX_REQUIREMENTS_BYTES:
        _fail()
    return value


def _strings(value):
    if type(value) is not list or len(value) > MAX_REQUIREMENTS_BYTES:
        _fail()
    for item in value:
        _text(item)
    return value


def _digest(value):
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail()
    return value


def _integer(value, maximum=(1 << 64) - 1, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _decimal(value):
    if type(value) is not str or _DECIMAL.fullmatch(value) is None or int(value) >= 1 << 128:
        _fail()


def _route(value):
    _object(value, _ROUTE_FIELDS)
    for field in ("id", "scheme", "host", "adapterType"):
        _text(value[field])
    _integer(value["port"], 65535, 1)
    for field in ("methods", "discardHeaders", "requiredProviderHeaderNames"):
        _strings(value[field])
    if value["credentialRef"] is not None:
        _text(value["credentialRef"])
    for field in ("adapterConfigSha256", "requestPolicySha256", "constraintsSha256", "jitSha256"):
        _digest(value[field])
    if value["responsePolicySha256"] is not None:
        _digest(value["responsePolicySha256"])
    if type(value["jitRequired"]) is not bool:
        _fail()
    resolved = value["resolvedAddressPolicy"]
    if type(resolved) is not dict:
        _fail()
    if resolved.get("type") == "public-only":
        _object(resolved, {"type"})
    elif resolved.get("type") == "explicit-cidrs":
        _object(resolved, {"type", "cidrs"})
        _strings(resolved["cidrs"])
    else:
        _fail()
    if type(value["paths"]) is not list:
        _fail()
    for path in value["paths"]:
        if type(path) is not list:
            _fail()
        for segment in path:
            if type(segment) is not dict or len(segment) != 1:
                _fail()
            name, selected = next(iter(segment.items()))
            if name in {"literal", "variable"}:
                _text(selected)
            elif name not in {"wildcard", "glob"} or selected is not True:
                _fail()
    observation = value["responseObservation"]
    if observation is not None:
        _object(observation, {"version", "lifecycleTimeoutNanos", "publicationTargetId",
            "publicationTargetPolicySha256"})
        if observation["version"] not in ("v1", "v2"):
            _fail()
        _decimal(observation["lifecycleTimeoutNanos"])
        if observation["publicationTargetId"] is not None:
            _text(observation["publicationTargetId"])
        if observation["publicationTargetPolicySha256"] is not None:
            _digest(observation["publicationTargetPolicySha256"])


def _requirements(raw, delegated, requested, budget):
    assignment.shared._raw(raw, MAX_REQUIREMENTS_BYTES)
    # The existing bounded strict parser rejects duplicate keys, nonintegral
    # numbers, excessive depth/nodes and invalid Unicode before shape checks.
    value = packets._parse_packet(raw, budget)
    if not raw.isascii() or packets._canonical(value, MAX_REQUIREMENTS_BYTES, budget) != raw:
        _fail()
    _object(value, {"apiVersion", "policy", "principal", "routes"})
    if value["apiVersion"] != REQUIREMENTS_SCHEMA:
        _fail()
    policy = _object(value["policy"], _POLICY_FIELDS)
    for field in ("hash", "compiledBehaviorSha256", "policySigningKeyId"):
        _digest(policy[field])
    _text(policy["id"])
    for field in ("sequence", "rollbackEpoch", "trustGeneration"):
        _integer(policy[field])
    principal = _object(value["principal"], _PRINCIPAL_FIELDS)
    if policy["hash"] != delegated.policy_hash or principal["id"] != requested.principal_id:
        _fail()
    identity_digest = _digest(principal["identityPolicySha256"])
    _strings(principal["sourceCidrs"])
    _strings(principal["requiredHeaderNames"])
    if principal["requiredHeaderValues"] != "externally-provisioned":
        _fail()
    authorization = principal["proxyAuthorization"]
    if authorization is not None:
        _object(authorization, {"type", "externallyProvisioned", "sourceCidrs", "expiresAtEpochMs"})
        _strings(authorization["sourceCidrs"])
        if authorization["externallyProvisioned"] is not True:
            _fail()
        if authorization["type"] == "legacyExact":
            if authorization["sourceCidrs"] or authorization["expiresAtEpochMs"] is not None:
                _fail()
        elif authorization["type"] == "bearerToken":
            if authorization["expiresAtEpochMs"] is not None:
                _decimal(authorization["expiresAtEpochMs"])
        else:
            _fail()
    routes = value["routes"]
    if type(routes) is not list or len(routes) > 128:
        _fail()
    previous = None
    for route in routes:
        budget.check()
        _route(route)
        if previous is not None and route["id"] <= previous:
            _fail()
        previous = route["id"]
    mtls = _object(principal["mtls"], _MTLS_FIELDS)
    # This is a policy requirement, NOT fabricated proof of trusted ingress.
    # The shared checker explicitly does not treat this required flag as fact.
    selectors = {"verifiedByTrustedIngress": True}
    for field in ("sanSpiffeIds", "sanDnsNames", "sanUris"):
        values = _strings(mtls[field])
        if values:
            selectors[field] = values
    for field in ("certificateSha256", "spkiSha256", "issuerSpkiSha256"):
        if mtls[field] is not None:
            selectors[field] = _digest(mtls[field])
    selectors = validate_mtls_identity(selectors)
    # A first certificate cannot be predetermined by its own DER hash. Reject
    # before a journal claim; do not burn a serial on an unfulfillable profile.
    if "certificateSha256" in selectors:
        _fail()
    if (selectors.get("spkiSha256", requested.subject_public_key_digest)
            != requested.subject_public_key_digest
            or selectors.get("issuerSpkiSha256", requested.issuer_spki_digest)
            != requested.issuer_spki_digest):
        _fail()
    dns, uris = map(set, requested.requested_sans)
    spiffe = set()
    for uri in uris:
        parsed = crypto.identity._canonical_uri(uri)
        if uri.startswith("spiffe://"):
            if (parsed.hostname is None or crypto.identity._DNS.fullmatch(parsed.hostname) is None
                    or parsed.port is not None or "?" in uri or "//" in parsed.path):
                _fail()
            spiffe.add(uri)
    for field, actual in (("sanDnsNames", dns), ("sanUris", uris),
            ("sanSpiffeIds", spiffe)):
        if field in selectors and not actual.intersection(selectors[field]):
            _fail()
    selector_digest = packets._digest(packets._canonical(mtls, MAX_REQUIREMENTS_BYTES, budget), budget)
    budget.check()
    return selectors, identity_digest, selector_digest


@dataclass(frozen=True, slots=True, repr=False)
class _NativeRequestOriginals:
    packet_digest: str
    policy_requirements_digest: str
    identity_policy_digest: str
    certificate_selectors_digest: str
    issuer_certificate_digest: str
    delegation: object
    setup: object
    requested: object
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _admit(*, packet_bytes, request_bytes, issuer_certificate_bytes,
        delegation_public_key_bytes, expected_delegation_pem_sha256,
        setup_public_key_bytes, expected_setup_pem_sha256, expected_principal,
        expected_nonce, expected_sans, work, live_window, transport_deadline_ns,
        _current, _additional_original_bytes, certificate_bytes=None, leaf_expectations=None):
    try:
        assignment.clock.evidence.capture._SharedLedger(work)
        _integer(_additional_original_bytes, MAX_ORIGINAL_BYTES)
        inputs = ((packet_bytes, MAX_PACKET_BYTES), (request_bytes, MAX_REQUEST_BYTES),
            (issuer_certificate_bytes, MAX_CERTIFICATE_BYTES),
            (delegation_public_key_bytes, assignment.MAX_KEY_BYTES),
            (setup_public_key_bytes, assignment.MAX_KEY_BYTES))
        for raw, maximum in inputs:
            assignment.shared._raw(raw, maximum)
        certificate_size = 0
        if certificate_bytes is not None:
            assignment.shared._raw(certificate_bytes, MAX_CERTIFICATE_BYTES)
            certificate_size = len(certificate_bytes)
        held = (_additional_original_bytes + 24 * len(packet_bytes)
            + 16 * (sum(len(raw) for raw, _ in inputs[1:]) + certificate_size) + 512 * 1024)
        if held > min(MAX_ORIGINAL_BYTES, work.limits.max_input_bytes - work.metrics.input_bytes):
            _fail()
        outer = assignment._Lifetime(work, live_window, transport_deadline_ns, _current)
        decoded = packet.decode_packet_originals_on_budget(packet_bytes=packet_bytes, budget=outer)
        outer.charge(input_bytes=len(request_bytes) + len(decoded.target_request_bytes))
        if decoded.target_request_bytes != request_bytes:
            _fail()
        # Reuse the setup verifier's actual original-only context, not an
        # external verified-result parameter. It genuinely admits the pinned
        # delegation key/signature and request before setup signature admission.
        originals = ((decoded.setup_authorization_bytes, setup.MAX_BYTES),
            (setup_public_key_bytes, setup.MAX_KEY_BYTES),
            (decoded.delegation_bytes, setup.delegation.MAX_BYTES),
            (delegation_public_key_bytes, setup.MAX_KEY_BYTES),
            (request_bytes, MAX_REQUEST_BYTES), (issuer_certificate_bytes, MAX_CERTIFICATE_BYTES),
            (decoded.policy_requirements_bytes, MAX_REQUIREMENTS_BYTES))
        additional = _additional_original_bytes + 8 * len(packet_bytes) + 8 * certificate_size + 128 * 1024
        budget, public, delegated = setup._context(originals, additional, work,
            outer.window, outer.bound, outer.current, setup_public_key_bytes,
            expected_setup_pem_sha256, decoded.delegation_bytes, delegation_public_key_bytes,
            expected_delegation_pem_sha256, request_bytes, issuer_certificate_bytes)
        configured = setup._admit(decoded.setup_authorization_bytes, public, delegated,
            decoded.policy_requirements_bytes, budget)
        requested = request.verify_request_on_budget(request_bytes=request_bytes,
            issuer_certificate_bytes=issuer_certificate_bytes, expected_principal=expected_principal,
            expected_nonce=expected_nonce, expected_sans=expected_sans, budget=budget)
        budget.charge(input_bytes=len(decoded.target_issuer_certificate_der_bytes)
            + len(requested.issuer_certificate.der))
        if (decoded.target_issuer_certificate_der_bytes != requested.issuer_certificate.der
                or delegated.target_principal_id != requested.principal_id
                or delegated.target_nonce != requested.nonce
                or delegated.target_request_sha256 != requested.request_digest
                or delegated.target_requested_sans != requested.requested_sans):
            _fail()
        selectors, identity_digest, selector_digest = _requirements(
            decoded.policy_requirements_bytes, delegated, requested, budget)
        # These exact scalar dates come from the genuinely verified setup
        # payload, never a caller-created successful carrier or processing TTL.
        setup_payload = assignment.shared._decode(configured.payload_bytes, setup.MAX_PAYLOAD_BYTES, budget)
        valid_from = max(setup_payload["notBeforeUnixSeconds"] * 1_000_000_000,
            delegated.not_before_unix_seconds * 1_000_000_000,
            requested.created_at_epoch_ms * 1_000_000,
            request._epoch_ns(requested.issuer_certificate.certificate.not_valid_before_utc))
        valid_until = min(setup_payload["expiresAtUnixSeconds"] * 1_000_000_000,
            delegated.expires_at_unix_seconds * 1_000_000_000,
            requested.expires_at_epoch_ms * 1_000_000,
            request._epoch_ns(requested.issuer_certificate.certificate.not_valid_after_utc))
        budget.interval(valid_from, valid_until)
        if certificate_bytes is not None:
            serial, before, after = leaf_expectations
            _integer(serial, (1 << 159) - 1, 1)
            _integer(before, request.MAX_EPOCH_MS // 1000, 1)
            _integer(after, request.MAX_EPOCH_MS // 1000, before + 1)
            if not valid_from <= before * 1_000_000_000 < after * 1_000_000_000 <= valid_until:
                _fail()
            selected = {"dnsNames": list(requested.requested_sans[0]),
                "uris": list(requested.requested_sans[1])}
            leaf = crypto._leaf_for_interval(certificate_bytes, requested.issuer_certificate,
                selected, requested.public_key, valid_from // 1_000_000, valid_until // 1_000_000,
                selectors, budget).certificate
            if (leaf.serial_number != serial
                    or request._epoch_ns(leaf.not_valid_before_utc) != before * 1_000_000_000
                    or request._epoch_ns(leaf.not_valid_after_utc) != after * 1_000_000_000):
                _fail()
            budget.interval(before * 1_000_000_000, after * 1_000_000_000)

        def live():
            delegated.live()
            configured.live()
            requested.live()
            return budget.current()

        result = _NativeRequestOriginals(packets._digest(packet_bytes, budget),
            configured.policy_requirements_digest, identity_digest, selector_digest,
            packets._digest(issuer_certificate_bytes, budget), delegated, configured, requested,
            valid_from, valid_until, budget.window, budget.bound, live)
        live()
        return result
    except NativeWorkloadIdentityOriginalsError:
        raise
    except Exception:
        raise NativeWorkloadIdentityOriginalsError("native workload identity original verification failed") from None


def _verify_on_work(*, packet_bytes, request_bytes, issuer_certificate_bytes,
        delegation_public_key_bytes, expected_delegation_pem_sha256,
        setup_public_key_bytes, expected_setup_pem_sha256, expected_principal,
        expected_nonce, expected_sans, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    return _admit(packet_bytes=packet_bytes, request_bytes=request_bytes,
        issuer_certificate_bytes=issuer_certificate_bytes,
        delegation_public_key_bytes=delegation_public_key_bytes,
        expected_delegation_pem_sha256=expected_delegation_pem_sha256,
        setup_public_key_bytes=setup_public_key_bytes, expected_setup_pem_sha256=expected_setup_pem_sha256,
        expected_principal=expected_principal, expected_nonce=expected_nonce, expected_sans=expected_sans,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        _current=_current, _additional_original_bytes=_additional_original_bytes)


def _verify_certificate_on_work(*, certificate_bytes, expected_serial_number,
        expected_not_before_epoch_seconds, expected_not_after_epoch_seconds,
        packet_bytes, request_bytes, issuer_certificate_bytes,
        delegation_public_key_bytes, expected_delegation_pem_sha256,
        setup_public_key_bytes, expected_setup_pem_sha256, expected_principal,
        expected_nonce, expected_sans, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    return _admit(packet_bytes=packet_bytes, request_bytes=request_bytes,
        issuer_certificate_bytes=issuer_certificate_bytes,
        delegation_public_key_bytes=delegation_public_key_bytes,
        expected_delegation_pem_sha256=expected_delegation_pem_sha256,
        setup_public_key_bytes=setup_public_key_bytes, expected_setup_pem_sha256=expected_setup_pem_sha256,
        expected_principal=expected_principal, expected_nonce=expected_nonce, expected_sans=expected_sans,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        _current=_current, _additional_original_bytes=_additional_original_bytes,
        certificate_bytes=certificate_bytes, leaf_expectations=(expected_serial_number,
            expected_not_before_epoch_seconds, expected_not_after_epoch_seconds))
