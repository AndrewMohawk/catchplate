"""Original-only public caller for the independently authorized issuer.

An actual cold owner supplies a request scope before HTTP body one. Options
admission never contacts the issuer. Issuance re-admits the original grant,
packet and request, spends that scope before its only socket, then genuinely
re-admits the original leaf. Failure does not establish nonissuance or permit
automatic retry. This module has no private key, signer, journal or key path.
"""
from __future__ import annotations

import hashlib

from catchplate import workload_identity_issuance_authorization as authorization
from catchplate import native_workload_identity_issuance_authorization as native_authorization
from catchplate import workload_identity_issuer_transport as transport


# Preserve the shared verifier's conservative fixed journal/leaf floor even
# though this caller never opens a journal. This is inside the original 64 MiB,
# not another work allowance or permission to read a larger HTTP body.
EXCHANGE_RESERVATION_BYTES = transport.FIXED_RESERVATION_BYTES
_CONSTRUCTION = object()
_ADMISSION_FIELDS = ("authorization_digest", "bootstrap_digest", "configuration_digest",
    "packet_digest", "request_digest", "csr_digest", "subject_public_key_digest",
    "issuer_certificate_digest", "issuer_spki_digest", "packet_signing_key_digest",
    "authorization_key_digest", "grant_id", "journal_namespace", "principal_id",
    "nonce", "selected_sans", "serial_number", "not_before_epoch_seconds",
    "not_after_epoch_seconds", "window", "deadline_ns")
_NATIVE_ADMISSION_FIELDS = tuple(name for name in _ADMISSION_FIELDS
    if name != "packet_signing_key_digest") + ("delegation_digest", "setup_digest",
    "policy_requirements_digest", "identity_policy_digest", "certificate_selectors_digest",
    "issuer_certificate_der_digest")


class WorkloadIdentityClientError(ValueError):
    pass


def _fail(message):
    raise WorkloadIdentityClientError(message)


def _scope(context):
    from catchplate import control_plane_workload_identity_startup as startup

    if type(context) is not startup._CallerScope:
        _fail("workload issuer caller requires its actual pre-body request context")
    return startup._require_context(context)


def _cold_pin(context):
    return (context.owner, context.material, context.work,
        context.issuer_root_public_key, context.issuer_bootstrap_bytes,
        context.endpoint, context.peer_uid, context.peer_gid,
        context.original_reservation_bytes, context.material.profile)


def _authorization_profile(context):
    """Only the source-owned cold material selects a verifier, never HTTP bytes."""
    cold = context.material.issuer_material
    if (type(cold) is not authorization.bootstrap._IssuerMaterial
            or cold.bootstrap_bytes is not context.issuer_bootstrap_bytes
            or cold.profile != context.material.profile):
        _fail("workload issuer caller lost its exact cold verifier profile")
    authorization.bootstrap._enrollment_original_byte_count(cold)
    if context.material.profile == authorization.bootstrap.LEGACY_PROFILE:
        return authorization, authorization._IssuanceMaterial, _ADMISSION_FIELDS
    if context.material.profile in (authorization.bootstrap.NATIVE_PROFILE,
            authorization.bootstrap.NATIVE_SERVICE_PROFILE):
        return native_authorization, native_authorization._NativeIssuanceMaterial, _NATIVE_ADMISSION_FIELDS
    _fail("workload issuer caller has an unsupported cold verifier profile")


def _check_cold(context, pin):
    # Only the source-owned base ancestor is invoked here. Attached verifier
    # children must never call context.current and thereby become their own
    # descendants. The actual context retains its registry/clock/owner seals.
    now = context.base_current()
    observed = _cold_pin(context)
    if (any(observed[index] is not pin[index] for index in range(5))
            or observed[5:] != pin[5:]):
        _fail("workload issuer caller changed its independent cold originals")
    _authorization_profile(context)
    return now


def _capacity(context, raw):
    held = transport._originals(raw, response=False)
    verifier, _, _ = _authorization_profile(context)
    if len(held[1]) > verifier.MAX_PACKET_BYTES:
        _fail("workload issuer packet exceeds its cold-selected profile")
    base = context.original_reservation_bytes
    if (type(base) is not int or not 0 < base < transport.MAX_ORIGINAL_BYTES
            or base < 8 * len(context.issuer_bootstrap_bytes)
            or base + 8 * sum(map(len, held)) + EXCHANGE_RESERVATION_BYTES
                > transport.MAX_ORIGINAL_BYTES):
        _fail("workload issuer caller exceeds its original complete representation reserve")
    return held


def _retain_admission(context, admitted):
    verifier, material_type, field_names = _authorization_profile(context)
    if type(admitted) is not material_type:
        _fail("workload issuer caller lacks genuine original admission")
    pin, work = _cold_pin(context), context.work
    fields = tuple(getattr(admitted, name) for name in field_names)
    original_live, public_key, association = admitted.live, admitted.public_key, admitted.association

    def live():
        _check_cold(context, pin)
        selected, selected_type, selected_fields = _authorization_profile(context)
        work.prepare_comparison(tuple(getattr(admitted, name) for name in field_names), fields)
        if (selected is not verifier or selected_type is not material_type or selected_fields is not field_names
                or type(admitted) is not material_type
                or tuple(getattr(admitted, name) for name in field_names) != fields
                or admitted.live is not original_live or admitted.public_key is not public_key
                or admitted.association is not association):
            _fail("workload issuer caller admission changed its signed association")
        now = original_live()
        after = _check_cold(context, pin)
        if (type(now) is not int or type(after) is not int or after < now
                or not admitted.not_before_epoch_seconds * 1_000_000_000
                    <= after < admitted.not_after_epoch_seconds * 1_000_000_000):
            _fail("workload issuer caller original certificate authority expired")
        return after

    live()
    context._retain_current(live, admitted.window, admitted.deadline_ns)
    context.current()
    return admitted


def _verify(context, raw, *, certificate_bytes=None):
    _scope(context)
    held = _capacity(context, raw)
    pin = _cold_pin(context)

    def base_current():
        return _check_cold(context, pin)

    kwargs = dict(authorization_bytes=held[0], packet_bytes=held[1], request_bytes=held[2],
        bootstrap_bytes=context.issuer_bootstrap_bytes,
        root_public_key=context.issuer_root_public_key,
        live_window=context.window, transport_deadline_ns=context.deadline_ns,
        work=context.work, _current=base_current,
        _additional_original_bytes=context.original_reservation_bytes + EXCHANGE_RESERVATION_BYTES)
    context.current()
    verifier, _, _ = _authorization_profile(context)
    if certificate_bytes is None:
        admitted = verifier._verify_on_work(**kwargs)
    else:
        admitted = verifier._verify_certificate_on_work(certificate_bytes=certificate_bytes, **kwargs)
    context.current()
    return _retain_admission(context, admitted)


def _admit_on_context(context, originals):
    """Options/action binding only: original signatures, no socket or claim."""
    return _verify(context, originals)


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _same_association(actual, expected, work, *, profile):
    # The fixed tuple contains a canonical SAN bytes original, so it must not
    # pass through JSON-only comparison accounting or be converted to text.
    if type(actual) is not tuple or type(expected) is not tuple or len(actual) != 17 or len(expected) != 17:
        _fail("workload issuer response lacks its closed association")
    if profile not in (authorization.bootstrap.LEGACY_PROFILE, authorization.bootstrap.NATIVE_PROFILE,
            authorization.bootstrap.NATIVE_SERVICE_PROFILE):
        _fail("workload issuer association has no cold-selected profile")
    for index, (left, right) in enumerate(zip(actual, expected)):
        if type(left) is not type(right):
            _fail("workload issuer association scalar type changed")
        if type(left) is bytes:
            if max(len(left), len(right)) > 8192:
                _fail("workload issuer association original exceeds its bound")
            work.charge(input_bytes=len(left) + len(right))
        elif type(left) is str:
            if profile in (authorization.bootstrap.NATIVE_PROFILE,
                    authorization.bootstrap.NATIVE_SERVICE_PROFILE) and index == 1:
                if not (1 <= len(left.encode("utf-8")) <= 1024
                        and 1 <= len(right.encode("utf-8")) <= 1024):
                    _fail("native workload issuer principal exceeds its original UTF-8 bound")
            elif max(len(left), len(right)) > 512:
                _fail("workload issuer association text exceeds its bound")
            work.charge(input_bytes=4 * (len(left) + len(right)))
        elif type(left) is int:
            if max(left.bit_length(), right.bit_length()) > 159:
                _fail("workload issuer association integer exceeds its bound")
            work.charge(input_bytes=40)
        else:
            _fail("workload issuer association has an unsupported scalar")
        if left != right:
            _fail("workload issuer returned leaf changes its genuinely admitted association")


def _response_association(admitted, certificate, work):
    return work.wire({"schema": "catchplate.workloadIdentityIssuerResponse/v1",
        "authorizationDigest": admitted.authorization_digest,
        "requestDigest": admitted.request_digest,
        "issuerCertificateDigest": admitted.issuer_certificate_digest,
        "certificateSha256": _digest(certificate, work),
        "serialNumber": format(admitted.serial_number, "x")})


class _IssuedWorkloadIdentity:
    """Same-context public originals only; never an external authority input."""

    __slots__ = ("association_bytes", "certificate_bytes", "_context", "_construction",
        "_guard", "_pin")

    def __init__(self, construction, *, context, association_bytes, certificate_bytes, guard):
        if construction is not _CONSTRUCTION:
            _fail("workload issuer result lacks its source construction")
        self.association_bytes, self.certificate_bytes = association_bytes, certificate_bytes
        self._context, self._construction, self._guard = context, construction, guard
        self._pin = context, association_bytes, certificate_bytes, guard

    def current(self):
        return _result_current(self, context=self._context)


def _result_current(value, *, context):
    if (type(value) is not _IssuedWorkloadIdentity or value._construction is not _CONSTRUCTION
            or value._context is not context or value._pin[0] is not context
            or value.association_bytes is not value._pin[1]
            or value.certificate_bytes is not value._pin[2] or value._guard is not value._pin[3]):
        _fail("workload issuer result changed its exact original response or context")
    _scope(context)
    return value._guard()


def _require_result(value, *, context):
    _result_current(value, context=context)
    return value


def _issue_on_context(context, *, authorization_bytes, packet_bytes, request_bytes):
    """Re-admit raw3, spend before contact, receive and verify exact raw2 once.

    The actual HTTP owner must finish role/WebAuthn/two-person checks before
    invoking this method. A prior options result is not an admission input.
    Exceptions leave dispatch unknown; this function never opens another
    context, retries a connection, or upgrades evidence into a session claim.
    """
    _scope(context)
    raw = _capacity(context, (authorization_bytes, packet_bytes, request_bytes))
    pin, work = _cold_pin(context), context.work
    admitted = _verify(context, raw)
    original_association = admitted.association
    cold = context.material.issuer_material
    if (type(cold) is not authorization.bootstrap._IssuerMaterial
            or cold.bootstrap_bytes is not context.issuer_bootstrap_bytes
            or context.endpoint != transport.LISTENER_PATH
            or (context.peer_uid, context.peer_gid)
                != (transport.CONNECTED_SERVER_UID, transport.CONNECTED_SERVER_GID)):
        _fail("workload issuer caller lost its independently admitted fixed endpoint")
    listener_pin = cold.listener_path_device, cold.listener_path_inode

    def live():
        _check_cold(context, pin)
        if (context.material.issuer_material is not cold
                or (cold.listener_path_device, cold.listener_path_inode) != listener_pin
                or admitted.association is not original_association):
            _fail("workload issuer caller changed its request or listener association")
        return context.current()

    live()
    # Irrevocable even if connect, read, signature admission or response send
    # subsequently fails. Remote absence/nonissuance cannot be inferred here.
    context._claim_exchange()
    response = transport._exchange_on_work(raw, endpoint=context.endpoint,
        peer_uid=context.peer_uid, peer_gid=context.peer_gid,
        listener_device=listener_pin[0], listener_inode=listener_pin[1],
        maximum_original_bytes=transport.MAX_ORIGINAL_BYTES - context.original_reservation_bytes,
        deadline_ns=context.deadline_ns, work=work, current=live)
    live()
    response = transport._originals(response, response=True)
    verified = _verify(context, raw, certificate_bytes=response[1])
    _same_association(verified.association, original_association, work,
        profile=context.material.profile)
    expected = _response_association(verified, response[1], work)
    work.charge(input_bytes=len(expected) + len(response[0]))
    if expected != response[0]:
        _fail("workload issuer response is not the exact canonical verified association")
    live()
    result = _IssuedWorkloadIdentity(_CONSTRUCTION, context=context,
        association_bytes=response[0], certificate_bytes=response[1], guard=live)
    return _require_result(result, context=context)
