#!/usr/bin/env python3
"""Signed synthetic public evidence and real FD signing; no runtime admission."""
import ast
import copy
import inspect
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from scripts.authority import local_runtime_trust as cli
from scripts.test_authority_local_configuration import fixture as configuration_fixture, sealed, SEED
from serverware import authority_local_runtime_trust as local

PIN = "sha256:" + "1" * 64
ERRORS = (ValueError, RuntimeError, KeyError, InvalidSignature)


def replace_payload(selected, payload):
    result = copy.deepcopy(selected)
    raw = local.canonical(payload)
    result.update(payloadOriginal=raw.decode("ascii"), payloadSha256=local.sha(raw))
    return result


def replace_evidence(selected, evidence, root):
    result = copy.deepcopy(selected)
    evidence = copy.deepcopy(evidence)
    evidence["signature"] = local.spec.strict_base64url_encode(root.sign(local.service._domain_digest(
        local.service.TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA, local.canonical(evidence["payload"])).encode("ascii")))
    raw = local.canonical(evidence)
    result.update(verifierAttestationOriginal=raw.decode("ascii"), verifierAttestationSha256=local.sha(raw))
    payload = local.document(result["payloadOriginal"].encode("ascii"), local.service.MAX_RUNTIME_TRUST_BYTES)
    payload["attestationEvidence"] = evidence
    payload["attestationReceiptDigest"] = local.service._domain_digest(
        local.service.TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA, raw)
    return replace_payload(result, payload)


def fixture():
    original, source, root = configuration_fixture()
    source["roles"]["verifier"]["maximumEndToEndDeadlineNs"] = 5_000_000_000
    source["credentialReleaseTrust"]["maximumReceiptAgeNs"] = 300_000_000_000
    bindings = local.spec.role_binding_digests(original["roleManifests"])
    _, digest = local.configuration._validate_payload(source, "authority-service", original["generation"], bindings)
    signed = dict(schema=local.service.SIGNED_CONFIG_SCHEMA, payload=source,
        signature=local.spec.strict_base64url_encode(root.sign(
            local.configuration.signature_message("authority-service", source))))
    signed_raw = local.canonical(signed)
    now = original["issuedAtUnixNanos"]
    claims = dict(trustMode="trusted-host-local", coLocated=True, hardwareBacked=False,
        nativeStageZero=False, hsmBackedKeys=False, teeVerified=False, externalWitnessVerified=False)
    receipt = dict(schema=local.service.TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA, role="verifier",
        processMode=local.launcher.PROCESS_MODES["verifier"], configurationDigest=digest,
        sourceRevision=local.service.SOURCE_REVISION, launchManifestDigest=PIN,
        runtimeClosureDigest=local.service._domain_digest("serverware.policyAuthorityRuntimeClosure/v2",
            PIN.encode("ascii"), local.canonical(source["packageVersions"])),
        operationManifestDigest=local.service.authority_contract.OPERATION_MANIFEST_DIGEST,
        generationDigest="sha256:"+"2"*64, stageZeroRequestDigest="sha256:"+"3"*64,
        artifactPackageDigest="sha256:"+"4"*64, measurementDigest=source["roles"]["verifier"]["measurementDigest"],
        responseSigningSpkiDigest=source["roles"]["verifier"]["responseSigningSpkiDigest"],
        issuedAtEpochNs=now-1_000_000_000, expiresAtEpochNs=now+90_000_000_000, **claims)
    response = source["roles"]["verifier"]["signingPublicKeyBase64Url"]
    payload = dict(schema=local.service.RUNTIME_TRUST_SCHEMA, sourceRevision=local.service.SOURCE_REVISION,
        configurationDigest=digest, operationManifestDigest=local.service.authority_contract.OPERATION_MANIFEST_DIGEST,
        relaySocketPath=local.launcher.ROLE_SOCKET_PATHS["runtime"], relayServiceUid=65524, relayServiceGid=65524,
        verifierSocketPath=local.launcher.ROLE_SOCKET_PATHS["verifier"], verifierServiceUid=65520, verifierServiceGid=65520,
        controlPlaneUid=65532, controlPlaneGid=65532, verifierSigningPublicKeyBase64Url=response,
        maximumDeadlineNs=1_000_000_000, attestationReceiptDigest=PIN, attestationEvidence={},
        attestationVerificationPolicy=dict(schema="serverware.trustedHostLocalPublicAttestationPolicy/v1",
            rootPublicKeyBase64Url=original["configurationRootPublicKeyBase64Url"],
            verifierSigningPublicKeyBase64Url=response, maximumReceiptAgeNs=300_000_000_000, **claims),
        trustMode="trusted-host-local", controlPlaneInheritedFileDescriptors=[32, 33],
        relayInheritedFileDescriptors=[3, 32, 33])
    selected = dict(schema=local.SCHEMA, purpose=local.PURPOSE,
        configurationRootPublicKeyBase64Url=original["configurationRootPublicKeyBase64Url"],
        serviceConfigurationOriginal=signed_raw.decode("ascii"), serviceConfigurationSha256=local.sha(signed_raw),
        verifierAttestationOriginal="{}", verifierAttestationSha256=PIN,
        payloadOriginal="{}", payloadSha256=PIN, generation=original["generation"], roleManifests=original["roleManifests"],
        bootIdDigest=original["bootIdDigest"], issuedAtBoottimeNs=original["issuedAtBoottimeNs"],
        deadlineBoottimeNs=original["issuedAtBoottimeNs"]+60_000_000_000,
        issuedAtUnixNanos=now, expiresAtUnixNanos=now+60_000_000_000)
    selected = replace_evidence(replace_payload(selected, payload),
        dict(schema=local.service.TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA, payload=receipt, signature=""), root)
    return selected, source, root


def prepare(selected):
    return local.prepare(local.canonical(selected), boot=selected["bootIdDigest"],
        now_boottime_ns=selected["issuedAtBoottimeNs"], now_unix_ns=selected["issuedAtUnixNanos"])


class LocalRuntimeTrustControls(unittest.TestCase):
    def test_signed_service_and_existing_public_attestation_join(self):
        selected, source, _ = fixture()
        result = prepare(selected)
        self.assertEqual(local.canonical(result["payload"]), result["payloadOriginal"])
        self.assertEqual(result["payload"]["verifierSigningPublicKeyBase64Url"], source["roles"]["verifier"]["signingPublicKeyBase64Url"])
        self.assertEqual(result["deadline"], selected["deadlineBoottimeNs"])

    def test_exact_service_domain_not_artifact_or_service_config_domain(self):
        selected, _, root = fixture()
        payload = prepare(selected)["payload"]
        message = local.signature_message(payload)
        self.assertEqual(message, local.service._domain_digest(local.service.SIGNED_RUNTIME_TRUST_SCHEMA, local.canonical(payload)).encode("ascii"))
        self.assertNotEqual(message, local.spec.domain_digest(local.service.SIGNED_RUNTIME_TRUST_SCHEMA, local.canonical(payload)).encode("ascii"))
        with self.assertRaises(InvalidSignature):
            root.public_key().verify(root.sign(message), local.configuration.signature_message("authority-service", payload))

    def test_actual_protected_fd_signature_once_without_owner_claim(self):
        if os.geteuid() != 0 or os.getegid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            self.skipTest("requires actual isolated root -I -B, no simulated owner")
        selected, _, root = fixture()
        raw = local.canonical(selected)
        public, private = sealed(raw), sealed(SEED)
        try:
            owner = local.LocalRuntimeTrustIssuer(approval_fd=public, approval_sha256=local.sha(raw), signing_key_fd=private)
            result_raw = owner.issue()
            result = local.document(result_raw, local.service.MAX_RUNTIME_TRUST_BYTES)
            self.assertEqual(local.canonical(result["payload"]), selected["payloadOriginal"].encode("ascii"))
            self.assertFalse(result_raw.endswith(b"\n"))
            root.public_key().verify(local.spec.strict_base64url_decode(result["signature"], name="signature", decoded_size=64),
                local.signature_message(result["payload"]))
            with self.assertRaises(ValueError): owner.issue()
        finally:
            os.close(public); os.close(private)

    def test_source_original_pins_signatures_and_role_binding_refuse(self):
        selected, _, _ = fixture()
        mutations = []
        for name in ("serviceConfigurationSha256", "verifierAttestationSha256", "payloadSha256"):
            changed = copy.deepcopy(selected); changed[name] = PIN; mutations.append(changed)
        changed = copy.deepcopy(selected)
        value = local.document(changed["serviceConfigurationOriginal"].encode("ascii"), local.configuration.MAX_CONFIGURATION)
        value["payload"]["launchNonceDigest"] = "sha256:"+"9"*64
        raw = local.canonical(value)
        changed.update(serviceConfigurationOriginal=raw.decode("ascii"), serviceConfigurationSha256=local.sha(raw)); mutations.append(changed)
        changed = copy.deepcopy(selected); changed["roleManifests"][0]["sha256"] = "sha256:"+"9"*64; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ERRORS): prepare(changed)

    def test_prospective_fd_rosters_and_source_fixed_peer_topology(self):
        selected, _, _ = fixture()
        payload = prepare(selected)["payload"]
        for field, value in (("controlPlaneInheritedFileDescriptors", [32, 32]),
            ("relayInheritedFileDescriptors", [32, 33]), ("relayInheritedFileDescriptors", [3, True]),
            ("controlPlaneInheritedFileDescriptors", [33, 32]), ("controlPlaneUid", 0),
            ("relaySocketPath", "/tmp/proxy.sock"), ("maximumDeadlineNs", 6_000_000_000)):
            changed = copy.deepcopy(payload); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ERRORS): prepare(replace_payload(selected, changed))

    def test_genuine_signature_does_not_waive_evidence_scope_or_expiry(self):
        selected, _, root = fixture()
        evidence = prepare(selected)["payload"]["attestationEvidence"]
        for field, value in (("role", "issuer"), ("measurementDigest", "sha256:"+"9"*64),
            ("runtimeClosureDigest", PIN), ("configurationDigest", PIN), ("teeVerified", True),
            ("expiresAtEpochNs", selected["expiresAtUnixNanos"]-1)):
            changed = copy.deepcopy(evidence); changed["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(ERRORS): prepare(replace_evidence(selected, changed, root))

    def test_no_root_substitution_native_profile_or_original_window_renewal(self):
        selected, _, _ = fixture()
        payload = prepare(selected)["payload"]
        for field, value in (("purpose", "sign-anything"), ("expiresAtUnixNanos", selected["issuedAtUnixNanos"]),
            ("deadlineBoottimeNs", selected["issuedAtBoottimeNs"]),
            ("configurationRootPublicKeyBase64Url", payload["verifierSigningPublicKeyBase64Url"])):
            changed = copy.deepcopy(selected); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ERRORS): prepare(changed)
        changed = copy.deepcopy(selected); changed["generation"]["trustMode"]["mode"] = "native"
        with self.assertRaises(ERRORS): prepare(changed)
        changed = copy.deepcopy(payload); changed["attestationVerificationPolicy"]["rootPublicKeyBase64Url"] = payload["verifierSigningPublicKeyBase64Url"]
        with self.assertRaises(ERRORS): prepare(replace_payload(selected, changed))

    def test_fixed_cli_and_no_runtime_admission_or_key_read_before_public_validation(self):
        args = ["--approval-fd", "3", "--approval-sha256", PIN, "--signing-key-fd", "4"]
        self.assertEqual(cli.arguments(args)["signing_key_fd"], 4)
        for wrong in (args+["--native", "yes"], args[:-1]+["3"], [args[0], "03", *args[2:]]):
            with self.assertRaises(ValueError): cli.arguments(wrong)
        tree = ast.parse(inspect.getsource(local))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertNotIn("service.AuthorityRuntimeClient.from_environment", calls)
        self.assertIn("service._verify_public_attestation_evidence", calls)
        issue = inspect.getsource(local.LocalRuntimeTrustIssuer.issue)
        self.assertLess(issue.index("self._used = True"), issue.index("io.signing_key"))
        self.assertNotIn("io.signing_key", inspect.getsource(local.LocalRuntimeTrustIssuer.__init__))


if __name__ == "__main__": unittest.main()
