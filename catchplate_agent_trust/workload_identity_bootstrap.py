"""Local request-first key possession, without enrollment or issuance authority.

This fresh-key profile needs no packet or client certificate. The independently
pinned issuer identifies the requested issuing CA, not permission to use it.
No network, certificate issuance, installation or enrollment action occurs.
Generated keys are software-held and published only to protected local files,
not erased-memory or HSM custody. Native crypto and filesystem calls still need
an outer watchdog for interruption guarantees.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
from pathlib import Path
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from . import workload_identity_bootstrap_originals as originals
from . import workload_identity_provisioning as provisioning
from ._workload_stream import Budget, WorkloadClientError
from .workload_identity_originals import (
    MAX_CERTIFICATE_BYTES, _P256_ORDER, _digest, _fail, _issuer, _names,
    _sans, _spki,
)


def prepare_bootstrap(*, issuer: tls.PinnedFile, expected_principal: str,
        expected_nonce: str, requested_sans: dict[str, list[str]],
        output_directory: Path | str, timeout_ms: int = 30_000
        ) -> provisioning.PreparedIdentity:
    """Create one local key/CSR/PoP request, never a grant or enrollment packet.

    A claim sticks before key generation. Published or partial originals are
    not removed, overwritten or retried in that directory after any failure.
    """
    try:
        budget = Budget(timeout_ms)
        began_monotonic = time.monotonic()
        began_ms = time.time_ns() // 1_000_000
        last_ms = began_ms
        interval = None

        def current():
            # Raw ancestor only: neither this callback nor its clock sampling
            # calls Budget.check or the verifier's same-budget live callback.
            nonlocal last_ms
            now = time.time_ns() // 1_000_000
            if not 0 < began_ms <= last_ms <= now <= originals.MAX_EPOCH_MS:
                _fail("workload bootstrap original wall clock changed")
            if interval is not None:
                before, until = interval
                if (not before <= now < until
                        or time.monotonic() >= began_monotonic + (until - began_ms) / 1000):
                    _fail("workload bootstrap original request or issuer interval ended")
            last_ms = now

        budget._bind_lifetime(began_monotonic + timeout_ms / 1000, current)
        tls._require_linux()
        originals._expectations(expected_principal, expected_nonce)
        selected = _sans(requested_sans)
        with ExitStack() as owners:
            issuer_original = tls._load_original(issuer, MAX_CERTIFICATE_BYTES,
                False, budget, owners)
            issuer_certificate = _issuer(issuer_original.raw, budget)
            certificate = issuer_certificate.certificate
            before = originals._epoch_ns(certificate.not_valid_before_utc) // 1_000_000
            until = min(began_ms + originals.MAX_LIFETIME_MS,
                originals._epoch_ns(certificate.not_valid_after_utc) // 1_000_000)
            if not 0 <= before <= began_ms < until <= originals.MAX_EPOCH_MS:
                _fail("workload bootstrap request exceeds the original issuer interval")
            interval = (before, until)
            budget.check()
            issuer_der_digest = _digest(issuer_certificate.der, budget)
            issuer_spki_digest = _digest(issuer_certificate.spki_der, budget)
            directory = provisioning._Directory(output_directory, budget, owners)

            def retained_current():
                issuer_original.recheck(budget)
                directory.check(budget)
                budget.check()

            binding = {
                "principalId": expected_principal, "nonce": expected_nonce,
                "issuerCertificateDerSha256": issuer_der_digest,
                "issuerSpkiSha256": issuer_spki_digest, "requestedSans": selected,
                "createdAtEpochMs": began_ms, "expiresAtEpochMs": until,
            }
            retained_current()
            claim = packets._canonical({
                "schema": "catchplate.workloadIdentityBootstrapPreparation/v1",
                "issuerOriginalSha256": issuer.sha256, **binding,
            }, originals.MAX_REQUEST_BYTES, budget)
            # Shared preparation.claim prevents cross-profile directory reuse.
            directory.publish("preparation.claim", claim, budget)
            retained_current()
            private = ec.generate_private_key(ec.SECP256R1())
            budget.check()
            csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
                .add_extension(x509.SubjectAlternativeName(_names(selected)), critical=True)
                .sign(private, hashes.SHA256()))
            budget.check()
            csr_raw = csr.public_bytes(serialization.Encoding.PEM)
            if not 1 <= len(csr_raw) <= originals.MAX_CSR_BYTES:
                _fail("workload bootstrap CSR exceeds its original bound")
            public_digest = _digest(_spki(private.public_key()), budget)
            payload = {"schema": originals.PAYLOAD_SCHEMA, **binding,
                "subjectPublicKeyInfoSha256": public_digest,
                "csr": {"pem": csr_raw.decode("ascii"), "sha256": _digest(csr_raw, budget)}}
            unsigned = packets._canonical(payload, originals.MAX_REQUEST_BYTES, budget)
            budget.check()
            signature = private.sign(originals.REQUEST_DOMAIN + unsigned,
                ec.ECDSA(hashes.SHA256()))
            budget.check()
            r, s = utils.decode_dss_signature(signature)
            signature = utils.encode_dss_signature(r, min(s, _P256_ORDER - s))
            request_raw = packets._canonical({"schema": originals.REQUEST_SCHEMA,
                "payload": payload, "signature": "ecdsa-p256-sha256:"
                    + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
                originals.MAX_REQUEST_BYTES, budget)

            def verify(request_bytes):
                admitted = originals.verify_request_on_budget(request_bytes=request_bytes,
                    issuer_certificate_bytes=issuer_original.raw,
                    expected_principal=expected_principal, expected_nonce=expected_nonce,
                    expected_sans=selected, budget=budget)
                if (admitted.csr_bytes != csr_raw
                        or admitted.subject_public_key_digest != public_digest):
                    _fail("workload bootstrap verified request differs from the generated key/CSR")
                admitted.live()
                return admitted

            # Original signature/CSR admission happens before publishing key,
            # CSR or request originals. Its result never grants issuance.
            admitted = verify(request_raw)
            private_raw = private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            if len(private_raw) > provisioning._PRIVATE_KEY_BYTES:
                _fail("workload bootstrap key exceeds its protected local bound")
            retained_current()
            admitted.live()
            private_pin = directory.publish("private-key.pem", private_raw, budget)
            csr_pin = directory.publish("request.pem", csr_raw, budget)
            request_pin = directory.publish("request.json", request_raw, budget)
            # Hold and recheck the actual named originals together, including
            # current-user ownership before any retained private-key body read.
            key_original = provisioning._retained_key(private_pin, budget, owners)
            csr_original = tls._load_original(csr_pin, originals.MAX_CSR_BYTES,
                False, budget, owners)
            request_original = tls._load_original(request_pin, originals.MAX_REQUEST_BYTES,
                False, budget, owners)
            if (key_original.raw != private_raw or csr_original.raw != csr_raw
                    or request_original.raw != request_raw):
                _fail("workload bootstrap retained originals changed")
            retained = verify(request_original.raw)
            for original in (key_original, csr_original, request_original):
                original.recheck(budget)
            retained_current()
            retained.live()
            result = provisioning.PreparedIdentity(request_pin, csr_pin, private_pin)
        budget.check()
        return result
    except WorkloadClientError:
        raise
    except Exception:
        raise WorkloadClientError(
            "local workload bootstrap failed; retain any published files and do not retry that directory"
        ) from None
