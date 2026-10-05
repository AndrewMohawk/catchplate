"""One narrow import/codec/refusal check; no native proof-issuance claim."""
import base64
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer
from serverware import oidc_session_activation_release_proof_resources as resources
from serverware import oidc_session_activation_release_proof_input_production as production
from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as acquisition
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def work():
    return _ValidationWork(QueryReadValidationLimits())


def wrapped(raw):
    return dict(base64Url=base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"), byteCount=len(raw),
        bytesDigest="sha256:" + hashlib.sha256(raw).hexdigest())


class ProofResourceControl(unittest.TestCase):
    def test_explicit_resource_profile_real_signature_and_invalid_nested_original_refusal(self):
        # These are public shape fixtures, not actual launch/resource observations.
        source = issuer.bootstrap
        launch = dict(schema=source.LAUNCH_SCHEMA, role=source.ROLE, processMode=source.PROCESS_MODE,
            serviceUid=source.SERVICE_UID, serviceGid=source.SERVICE_GID,
            peerUid=source.PEER_UID, peerGid=source.PEER_GID, listenerPath=source.LISTENER_PATH,
            inheritedFileDescriptors=list(source.INHERITED_DESCRIPTORS), requestTimeoutSeconds=10,
            listenerSocketDevice=0, listenerPathDevice=0, listenerSocketInode=1, listenerPathInode=1,
            **dict(source._FD_FIELDS))
        pin = "sha256:" + "1" * 64
        identity = {name: pin for name in issuer.shape.IDENTITY_FIELDS}
        scope = dict(configurationDigest=pin, databaseId="fixture-database", generationDigest=pin,
            runtimeClosureDigest=pin, producerId="fixture-proof", producerIdentity=identity, receiverIdentity=identity)
        epoch, mono, age = 1_800_000_000_000_000_000, 1_000_000_000, 7_200_000_000_000
        # Runtime delegation may be long; actual processing remains a separate
        # source-bounded short original window, never a two-hour request grant.
        processing_age = 1_000_000_000
        window = (epoch, mono, mono, epoch + processing_age, mono + processing_age, processing_age, 0)
        payload = dict(schema=issuer.V3_PAYLOAD_SCHEMA, sourceRevision=issuer.authority.SOURCE_REVISION,
            purpose=issuer.PURPOSE, trustMode="trusted-host-local", proofEnrollmentDigest=pin,
            intentEnrollmentDigest=pin, proofScope=scope, callerId="fixture-intent", proofLaunch=launch,
            issuedAtEpochNs=epoch, expiresAtEpochNs=epoch + age,
            activationIssuancePolicy=wrapped(b"{}"))
        issuer._payload_shape(payload, work())
        self.assertEqual(issuer.V3_MAX_BYTES, 6 * 1024 * 1024)
        self.assertNotIn("completionBootstrapDigest", issuer.V3_PAYLOAD_FIELDS)
        self.assertNotIn("currentActivationPlanner", issuer.V3_PAYLOAD_FIELDS)
        for name, value in (("completionBootstrapDigest", pin), ("currentActivationPlanner", wrapped(b"{}"))):
            with self.subTest(field=name), self.assertRaises(ValueError):
                issuer._payload_shape(dict(payload, **{name: value}), work())
        private = Ed25519PrivateKey.from_private_bytes(b"\x61" * 32)
        public = private.public_key()
        # Actual signature primitive authenticates only this intentionally
        # invalid resource-policy envelope; it is not a successful resource DTO.
        raw = resources.resources.planner.signing._sign(payload, issuer.V3_SCHEMA,
            issuer.V3_MAX_BYTES, private, public, work())
        envelope = issuer._read(raw, work())
        issuer._signature(envelope, public, work())
        with self.assertRaises(InvalidSignature):
            issuer._signature(envelope, Ed25519PrivateKey.from_private_bytes(b"\x62" * 32).public_key(), work())
        selected = dict(schema=acquisition.V3_SCHEMA,
            endpoint=dict(path=acquisition.SOCKET_PATH, timeoutSeconds=10, peerUid=0, peerGid=0),
            issuerPolicy={name: value for name, value in wrapped(raw).items() if name != "bytesDigest"})
        self.assertIsNone(acquisition._shape(selected))
        with patch.object(issuer.clock.time, "time_ns", return_value=epoch + 100), \
                patch.object(issuer.clock.time, "monotonic_ns", return_value=mono + 100), \
                patch.object(resources.resources, "_verify_on_work", wraps=resources.resources._verify_on_work) as genuine:
            with self.assertRaises(ValueError):
                resources._verify_on_work(policy_bytes=raw, proof_enrollment_bytes=b"{}",
                    intent_enrollment_bytes=b"{}", root_public_key=public,
                    live_window=window, transport_deadline_ns=window[4], work=work())
            self.assertEqual(genuine.call_count, 1)
            self.assertEqual(genuine.call_args.kwargs["policy_bytes"], b"{}")
        # The application caller remains behind its genuine process-mode
        # startup guard; inspect its exact source without bypassing that guard.
        # The actual pure producer import must remain joined to real source.
        source_text = (ROOT / "serverware/control_plane_oidc_session_activation_release_proof.py").read_text()
        self.assertIn("requested._planner_original_on_permission(permission)", source_text)
        self.assertIn("activation_policy_bytes=resource_original", source_text)
        self.assertNotIn("owner._material =", source_text)
        producer = Path(production.__file__).read_text()
        self.assertIn("issuer._verify_on_work(policy_bytes=policy_raw", producer)
        self.assertIn("bootstrap._produce_on_work(payload=proof_payload", producer)
        self.assertIn("*(interval[1] for interval in completed_intervals)", producer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
