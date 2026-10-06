"""One protected issuance using genuine originals and irreversible custody.

The cold owner alone holds the CA signer. A principal/nonce claim and signed
serial are durable before signing; an incomplete prior claim never signs again.
Only exact retained public certificate bytes leave after independent admission.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from serverware import workload_identity_issuance_authorization as authorization
from serverware import workload_identity_issuer_journal as journal
from serverware import workload_identity_issuer_transport as transport


class WorkloadIdentityIssuerServiceError(ValueError):
    pass


def _fail(message):
    raise WorkloadIdentityIssuerServiceError(message)


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _same(actual, expected, work):
    if type(actual) is bytes and type(expected) is bytes:
        work.charge(input_bytes=len(actual) + len(expected))
    else:
        work.prepare_comparison(actual, expected)
    if actual != expected:
        _fail("workload issuer original association differs")


def _same_association(actual, expected, work):
    # The closed association ends in canonical SAN bytes, not a JSON scalar.
    # Meter every scalar before equality; the JSON work walker rejects bytes.
    if (type(actual) is not tuple or type(expected) is not tuple
            or len(actual) != 17 or len(expected) != 17):
        _fail("workload issuer association is not its exact seventeen-scalar tuple")
    work.charge(input_bytes=36, json_nodes=2)
    for index, (left, right) in enumerate(zip(actual, expected)):
        kind = str if index < 13 else int if index < 16 else bytes
        if type(left) is not kind or type(right) is not kind:
            _fail("workload issuer association scalar type differs")
        if kind is bytes:
            work.charge(input_bytes=len(left) + len(right), json_nodes=2)
        else:
            work.prepare_comparison(left, right)
    if actual != expected:
        _fail("workload issuer original association differs")


def _authorization_on_owner(owner):
    """Select only from the authenticated cold owner, never request contents."""
    from serverware import workload_identity_issuer_bootstrap as bootstrap

    material = owner.material
    if type(material) is not bootstrap._IssuerMaterial or type(material.profile) is not str:
        _fail("workload issuer lost its exact cold admission profile")
    if material.profile == "legacy-v1":
        if (material.native_scope is not None
                or type(material.packet_signing_key_bytes) is not bytes
                or type(material.runtime_manifest_digest) is not str):
            _fail("legacy workload issuer cold scope is not its original profile")
        return authorization, authorization._IssuanceMaterial
    if material.profile in (bootstrap.NATIVE_PROFILE, bootstrap.NATIVE_SERVICE_PROFILE):
        if (type(material.native_scope) is not bootstrap._NativeEnrollmentScope
                or material.packet_signing_key_bytes is not None
                or material.runtime_manifest_digest is not None):
            _fail("native workload issuer cold scope is not its original profile")
        from serverware import native_workload_identity_issuance_authorization as native_authorization

        return native_authorization, native_authorization._NativeIssuanceMaterial
    _fail("workload issuer cold admission profile is unsupported")


def _certificate_builder(owner, admitted, *, work, current, deadline_ns):
    """Prepare the fixed leaf profile; this function performs no signature."""
    raw, private = owner.material.issuer_certificate_bytes, owner.ca_private_key
    work.charge(input_bytes=3 * len(raw) + 16 * 1024)
    kwargs = dict(work=work, current=current, deadline_ns=deadline_ns)
    issuer = transport._native(lambda: x509.load_pem_x509_certificate(raw), **kwargs)
    if (not isinstance(private, ed25519.Ed25519PrivateKey)
            and not (isinstance(private, ec.EllipticCurvePrivateKey)
                and isinstance(private.curve, (ec.SECP256R1, ec.SECP384R1)))
            and not (isinstance(private, rsa.RSAPrivateKey) and 3072 <= private.key_size <= 4096)):
        _fail("workload issuer actual CA signer has an unsupported key profile")
    public = transport._native(lambda: private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), **kwargs)
    expected = transport._native(lambda: issuer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), **kwargs)
    _same(public, expected, work)
    _same(_digest(raw, work), admitted.issuer_certificate_digest, work)
    _same(_digest(public, work), admitted.issuer_spki_digest, work)
    selected = admitted.selected_sans
    if (type(selected) is not tuple or len(selected) != 2
            or any(type(names) is not tuple for names in selected)
            or not 1 <= sum(map(len, selected)) <= 8):
        _fail("workload issuer admission lacks its exact bounded SAN selection")
    for names in selected:
        for name in names:
            work.prepare_utf8(name)
    current()

    def build():
        names = [x509.DNSName(name) for name in selected[0]]
        names.extend(x509.UniformResourceIdentifier(name) for name in selected[1])
        return (x509.CertificateBuilder().subject_name(x509.Name([]))
            .issuer_name(issuer.subject).public_key(admitted.public_key)
            .serial_number(admitted.serial_number)
            .not_valid_before(datetime.fromtimestamp(admitted.not_before_epoch_seconds, timezone.utc))
            .not_valid_after(datetime.fromtimestamp(admitted.not_after_epoch_seconds, timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=True))

    builder = transport._native(build, **kwargs)
    algorithm = None if isinstance(private, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder, private, algorithm


def _issue_on_owner(owner, originals, *, current, _request=None):
    """Internal only: actual cold owner plus raw3, never an admission DTO."""
    from serverware import workload_identity_issuer_startup as startup

    startup._require_owner(owner)
    if owner.material.profile == startup.bootstrap.NATIVE_SERVICE_PROFILE:
        startup._require_request(_request, owner)
        window, original_deadline = _request.window, _request.deadline_ns
    else:
        if _request is not None:
            _fail("one-shot issuer cannot replace its original processing context")
        window, original_deadline = owner.window, owner.deadline_ns
    verifier, material_type = _authorization_on_owner(owner)
    raw = transport._originals(originals, response=False)
    work = owner.work
    if (type(owner.original_reservation_bytes) is not int
            or not 0 < owner.original_reservation_bytes < transport.MAX_ORIGINAL_BYTES
            or journal.MAX_OPERATION_RESERVATION_BYTES != transport.JOURNAL_RESERVATION_BYTES
            or owner.original_reservation_bytes + transport._request_reservation(tuple(map(len, raw)))
                > transport.MAX_ORIGINAL_BYTES):
        _fail("workload issuer lost its original cold/exchange representation reservation")
    kwargs = dict(authorization_bytes=raw[0], bootstrap_bytes=owner.material.bootstrap_bytes,
        root_public_key=owner.root_public_key, packet_bytes=raw[1], request_bytes=raw[2],
        live_window=window, transport_deadline_ns=original_deadline, work=work,
        _current=current, _additional_original_bytes=(owner.original_reservation_bytes
            + transport.FIXED_RESERVATION_BYTES))
    admitted = verifier._verify_on_work(**kwargs)
    if type(admitted) is not material_type:
        _fail("workload issuer requires actual original grant, packet and request admission")
    deadline = min(original_deadline, admitted.deadline_ns, admitted.window[4])

    def admitted_current():
        current()
        admitted.live()
        now = current()
        if type(now) is not int or not (admitted.not_before_epoch_seconds * 1_000_000_000
                <= now < admitted.not_after_epoch_seconds * 1_000_000_000):
            _fail("workload issuer certificate interval is not currently authorized")
        return now

    admitted_current()
    # Building is not signing. Even builder/key errors occur before a new
    # claim; no call to the CA signer is possible until a new durable receipt.
    builder, private, algorithm = _certificate_builder(owner, admitted,
        work=work, current=admitted_current, deadline_ns=deadline)
    io = dict(work=work, current=admitted_current,
        maximum_original_bytes=transport.JOURNAL_RESERVATION_BYTES)
    claim = journal.WorkloadIdentityIssuerJournal.claim(owner.journal,
        association=admitted.association, **io)
    if type(claim) is not journal._IssuerClaim:
        _fail("workload issuer did not receive its actual durable claim")
    _same_association(claim.association, admitted.association, work)
    for actual, expected in ((claim.serial_number, admitted.serial_number),
            (claim.not_before_epoch_seconds, admitted.not_before_epoch_seconds),
            (claim.not_after_epoch_seconds, admitted.not_after_epoch_seconds)):
        _same(actual, expected, work)
    if claim.state == "unknown":
        _fail("workload issuer claim has no complete certificate; signing cannot resume")
    if claim.state == "complete":
        certificate = claim.certificate_bytes
    elif claim.state == "new":
        if claim.certificate_bytes is not None:
            _fail("new workload issuer claim unexpectedly contains a certificate")
        admitted_current()
        work.charge(hashes=1, input_bytes=4 * transport.RESPONSE_LIMITS[1])
        # The serial and nonce claim are already durably published/read back.
        signed = transport._native(lambda: builder.sign(private, algorithm),
            work=work, current=admitted_current, deadline_ns=deadline)
        certificate = transport._native(lambda: signed.public_bytes(serialization.Encoding.PEM),
            work=work, current=admitted_current, deadline_ns=deadline)
        if type(certificate) is not bytes or not 2 <= len(certificate) <= transport.RESPONSE_LIMITS[1]:
            _fail("workload issuer signed certificate exceeds its fixed public bound")
        retained = journal.WorkloadIdentityIssuerJournal.complete(owner.journal,
            claim=claim, certificate_bytes=certificate, **io)
        _same(retained, certificate, work)
        certificate = retained
    else:
        _fail("workload issuer durable claim has an unknown state")
    if type(certificate) is not bytes or not 2 <= len(certificate) <= transport.RESPONSE_LIMITS[1]:
        _fail("workload issuer retained certificate is unavailable or oversized")
    admitted_current()
    # Re-admit original authorization/packet/request and actual readback leaf;
    # the first result is not accepted as a substitute for those signatures.
    verified = verifier._verify_certificate_on_work(certificate_bytes=certificate,
        **{**kwargs, "live_window": admitted.window, "transport_deadline_ns": deadline,
            "_current": admitted_current})
    if type(verified) is not material_type:
        _fail("workload issuer retained certificate lacks independent original admission")
    _same_association(verified.association, admitted.association, work)

    def response_current():
        admitted_current()
        verified.live()
        return admitted_current()

    response_current()
    association = work.wire({"schema": "serverware.workloadIdentityIssuerResponse/v1",
        "authorizationDigest": verified.authorization_digest,
        "requestDigest": verified.request_digest,
        "issuerCertificateDigest": verified.issuer_certificate_digest,
        "certificateSha256": _digest(certificate, work), "serialNumber": format(verified.serial_number, "x")})
    response = transport._originals((association, certificate), response=True)
    response_current()
    return response, response_current, min(deadline, verified.deadline_ns, verified.window[4])


def _serve_on_owner(owner):
    """One invocation: one-shot v1/v2 or explicitly bounded sequential v3."""
    from serverware import workload_identity_issuer_startup as startup

    startup._require_owner(owner)
    owner.claim_service()
    if owner.material.profile != startup.bootstrap.NATIVE_SERVICE_PROFILE:
        return _exchange_on_owner(owner)
    # Idle waiting consumes the original service lifetime, not an issuance
    # request window. Every accepted exchange gets one fresh clipped context,
    # while all exchanges retain the SAME cold ledger, journal and lease.
    for _ in range(owner.material.service_maximum_exchanges):
        startup._require_owner(owner)
        transport._ready(owner.listener, writing=False, work=owner.work,
            current=owner.current, deadline_ns=owner.deadline_ns)
        request = startup._IssuerRequest(startup._CONSTRUCTION, owner)
        _exchange_on_owner(owner, _request=request)
        startup._finish_request(request, owner)
    # No error is swallowed: an uncertain exchange ends this owner, retaining
    # all journal claims and the consumed attempt rather than trying another.
    return None


def _exchange_on_owner(owner, *, _request=None):
    """One accepted exchange; normal return only after guarded socket close."""
    from serverware import workload_identity_issuer_startup as startup

    startup._require_owner(owner)
    owner_deadline = owner.deadline_ns
    if owner.material.profile == startup.bootstrap.NATIVE_SERVICE_PROFILE:
        startup._require_request(_request, owner)
        deadline, base_current = _request.deadline_ns, _request.current
    else:
        if _request is not None:
            _fail("one-shot issuer cannot receive a service request context")
        deadline, base_current = owner_deadline, owner.current
    work, listener = owner.work, owner.listener
    connection, identity = None, None

    def current():
        startup._require_owner(owner)
        now = base_current()
        if owner.work is not work or owner.listener is not listener or owner.deadline_ns != owner_deadline:
            _fail("workload issuer service changed its original cold owner")
        if connection is not None and identity is not None:
            work.charge(input_bytes=1)
            observed = os.fstat(connection.fileno())
            if (connection.fileno(), observed.st_dev, observed.st_ino, observed.st_mode) != identity:
                _fail("workload issuer accepted connection changed identity")
        return now

    def accept():
        nonlocal connection, identity
        connection, _address = listener.accept()
        connection.setblocking(False)
        observed = os.fstat(connection.fileno())
        identity = connection.fileno(), observed.st_dev, observed.st_ino, observed.st_mode

    def close():
        nonlocal connection, identity
        connection.close()
        connection, identity = None, None

    try:
        current()
        if type(listener) is not socket.socket:
            _fail("workload issuer listener is not the actual cold socket")
        transport._ready(listener, writing=False, work=work, current=current, deadline_ns=deadline)
        transport._native(accept, work=work, current=current, deadline_ns=deadline)
        originals = transport._recv_request(connection,
            maximum_original_bytes=transport.MAX_ORIGINAL_BYTES - owner.original_reservation_bytes,
            deadline_ns=deadline, work=work, current=current)
        response, response_current, response_deadline = _issue_on_owner(owner, originals,
            current=current, _request=_request)
        transport._send_response(connection, response, deadline_ns=response_deadline,
            work=work, current=response_current)
        response_current()
        transport._native(close, work=work, current=response_current, deadline_ns=response_deadline)
        response_current()
        return None
    finally:
        if connection is not None:
            connection.close()
