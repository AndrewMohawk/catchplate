#!/usr/bin/env python3
"""Real synthetic signatures/certificates and protected-FD issuance, not launch."""
import ast
import copy
import fcntl
import hashlib
import inspect
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_configuration as cli
from catchplate import authority_local_configuration as local
from catchplate import authority_historical_archive as history
from scripts.test_authority_local_database_credentials import fixture as certificate_fixture
from catchplate.authority_local_database_credentials import issuance

PIN = "sha256:" + "1" * 64
SEED = b"C" * 32


def fixture():
    credentials = certificate_fixture(now_unix_ns=time.time_ns())
    now = credentials["now_unix_ns"]
    root = Ed25519PrivateKey.from_private_bytes(SEED)
    encoded = lambda key: local.spec.strict_base64url_encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    keys = {name: encoded(Ed25519PrivateKey.from_private_bytes(bytes([index + 1]) * 32))
            for index, name in enumerate(sorted(local.RUNTIME_KEY_ROLES))}
    generation = dict(generationId="synthetic-local-configuration", sequence=0, predecessorDigest=None,
        minimumRollbackSequence=0, validFrom=datetime.fromtimestamp(now // 10**9 - 60, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        validUntil=datetime.fromtimestamp(now // 10**9 + 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        operationManifestDigest=local.generator.authority_contract.OPERATION_MANIFEST_DIGEST, trustMode=dict(local.LOCAL))
    role_originals, roles = {}, []
    for name in sorted(local.launcher.PROCESS_MODES):
        original = local.spec.canonical_json_bytes(dict(schema="synthetic.staticRole/v1", role=name))
        role_originals[name] = original.decode("ascii")
        environment = ["CATCHPLATE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"]
        if name in local.spec.RUNTIME_EVIDENCE_ROLES:
            environment.append(local.spec.RUNTIME_EVIDENCE_NAME)
        mutable = [] if name != "witness" else [dict(name="witness-state", runtimePath="/var/lib/catchplate/witness",
            atomicRecordProtocol="append-canonical-record-fdatasync-renameat2-noreplace-fsyncdir-v1",
            quotaBytes=1024*1024, singletonLeaseRequired=True, networkAllowed=False)]
        roles.append(dict(path="roles/"+name+".json", sha256=local.sha(original), role=name,
            runtimeUid=local.launcher.ROLE_IDENTITIES[name][0], runtimeGid=local.launcher.ROLE_IDENTITIES[name][1],
            processMode=local.launcher.PROCESS_MODES[name], entrypointPath="/runtime/authority.py",
            listenerName=local.launcher.ROLE_LISTENER_NAMES[name],
            credentialNames=sorted(local.launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[name]), cwd="/runtime",
            pathEntries=["/runtime/python/bin"], argv=dict(schema=local.spec.LOCAL_ARGUMENTS_SCHEMA),
            environmentAllowlist=sorted(environment), mutableStateDescriptors=mutable))
    bindings = local.spec.role_binding_digests(roles)
    identities = {name: issuance(credentials["originals"][name], purpose=name) for name in local.SERVICE_ROLES}
    config_roles = {}
    for name in sorted(local.SERVICE_ROLES):
        peer = {"verifier": "runtime", "planner": "verifier", "planner-writer": "planner",
                "issuer": "verifier", "executor": "verifier"}[name]
        row = dict(processMode=local.launcher.PROCESS_MODES[name], serviceUid=local.launcher.ROLE_IDENTITIES[name][0],
            serviceGid=local.launcher.ROLE_IDENTITIES[name][1], peerUid=local.launcher.ROLE_IDENTITIES[peer][0],
            peerGid=local.launcher.ROLE_IDENTITIES[peer][1], socketPath=local.launcher.ROLE_SOCKET_PATHS[name],
            measurementDigest=PIN, responseSigningSpkiDigest=local._spki(keys[name]), requestTimeoutSeconds=1,
            databaseConnectTimeoutSeconds=2, maximumInternalAgeNs=1000, capabilityLifetimeNs=1000,
            workers=1, maximumInFlight=2, listenBacklog=2)
        row.update({field: identities[name][field] for field in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn")})
        if name in ("verifier", "planner"):
            row.update(signingSpkiDigest=local._spki(keys[name]), signingPublicKeyBase64Url=keys[name])
        if name == "verifier":
            row.update(runtimeSocketPath=row["socketPath"], maximumEndToEndDeadlineNs=10000)
        elif name == "planner":
            row.update(enabledOperations=[], plannerSessionIdentityDigest=PIN)
        elif name == "planner-writer":
            row.update(plannerSessionIdentityDigest=PIN, plannerSigningSpkiDigest=local._spki(keys["planner"]),
                plannerSigningPublicKeyBase64Url=keys["planner"], responseSigningPublicKeyBase64Url=keys[name])
        config_roles[name] = row
    packages = {"python": "synthetic-test"}
    payload = dict(schema=local.generator.SERVICE_CONFIGURATION_PAYLOAD_SCHEMA,
        sourceRevision=local.generator.authority_contract.SOURCE_REVISION, roles=config_roles,
        runtimeUid=65524, runtimeGid=65524, roleBindingDigests={name: bindings[name] for name in local.SERVICE_ROLES},
        roleRuntimeClosureDigests={name: local.spec.role_runtime_closure_digest(bindings[name], packages) for name in local.SERVICE_ROLES},
        packageVersions=packages, launchNonceDigest=PIN, queryManifestDigest=local.primary.source_query_manifest_digest(),
        generationSequence=0, generationBindingDigest=local.spec.configuration_generation_binding_digest(generation),
        generationPredecessorDigest=None, generationMinimumRollbackSequence=0,
        credentialReleaseTrust=dict(schema="catchplate.trustedHostLocalCredentialReleaseTrust/v1",
            trustMode="trusted-host-local", maximumReceiptAgeNs=1000),
        replayWitness=dict(socketPath=local.launcher.ROLE_SOCKET_PATHS["witness"], serviceUid=65523, serviceGid=65523,
            requestTimeoutSeconds=1, identityDigest=PIN, signingPublicKeyBase64Url=keys["witness"]),
        webauthn=dict(rpId="example.invalid", origin="https://example.invalid", challengeLifetimeNs=1000,
            maximumChallengeAgeNs=1000, allowedAuthenticatorClasses=["synthetic-test"], requireAttestationTrusted=True),
        executorSessionIdentityDigest=PIN, executorRole=identities["executor"]["databaseRole"],
        executorTlsClientDn=identities["executor"]["tlsClientDn"], executorTlsClientSerial=identities["executor"]["tlsClientSerial"],
        executorTlsIssuerDn=identities["executor"]["tlsIssuerDn"],
        verifierCredentialIssuanceDigest=identities["verifier"]["credentialIssuanceDigest"],
        issuerCredentialIssuanceDigest=identities["issuer"]["credentialIssuanceDigest"],
        executorCredentialIssuanceDigest=identities["executor"]["credentialIssuanceDigest"])
    raw = local.spec.canonical_json_bytes(payload)
    selected = dict(schema=local.SCHEMA, purpose=local.PURPOSES["authority-service"], role="authority-service",
        configurationRootPublicKeyBase64Url=encoded(root), payloadOriginal=raw.decode("ascii"), payloadSha256=local.sha(raw),
        generation=generation, roleManifests=roles, roleOriginals=role_originals, runtimePublicKeys=keys,
        databaseIssuanceOriginals={name: credentials["originals"][name].decode("ascii") for name in local.SERVICE_ROLES},
        serviceConfigurationOriginal=None, bootIdDigest=local.launcher._boot_identity_digest(),
        issuedAtBoottimeNs=local.io._clock(), deadlineBoottimeNs=local.io._clock()+120*10**9,
        issuedAtUnixNanos=now, expiresAtUnixNanos=now+120*10**9)
    return selected, payload, root


def prepare(selected):
    return local.prepare(local.spec.canonical_json_bytes(selected), boot=selected["bootIdDigest"],
        now_boottime_ns=selected["issuedAtBoottimeNs"], now_unix_ns=selected["issuedAtUnixNanos"])


def witness(selected, service, root):
    result = copy.deepcopy(selected)
    envelope = dict(schema=local.generator.SERVICE_CONFIGURATION_SCHEMA, payload=service,
        signature=local.spec.strict_base64url_encode(root.sign(local.signature_message("authority-service", service))))
    result.update(role="witness", purpose=local.PURPOSES["witness"],
                  serviceConfigurationOriginal=local.spec.canonical_json_bytes(envelope).decode("ascii"))
    bindings = local.spec.role_binding_digests(selected["roleManifests"])
    _, digest = local._validate_payload(service, "authority-service", selected["generation"], bindings)
    payload = dict(schema=local.generator.WITNESS_CONFIGURATION_PAYLOAD_SCHEMA,
        sourceRevision=local.generator.authority_contract.SOURCE_REVISION, roleBindingDigest=bindings["witness"],
        generationBindingDigest=service["generationBindingDigest"],
        operationManifestDigest=local.generator.authority_contract.OPERATION_MANIFEST_DIGEST,
        authorityConfigurationDigests=[digest], identityDigest=PIN, signingSpkiDigest=local._spki(selected["runtimePublicKeys"]["witness"]),
        verifierSigningPublicKeyBase64Url=selected["runtimePublicKeys"]["verifier"], serviceUid=65523, serviceGid=65523,
        peerUid=65520, peerGid=65520, socketPath=local.launcher.ROLE_SOCKET_PATHS["witness"],
        socketActivationName=local.launcher.ROLE_LISTENER_NAMES["witness"], listenBacklog=2, workers=1, maximumInFlight=2,
        requestTimeoutSeconds=1, maximumRequestAgeNs=1000, minimumSequence=0, minimumReceiptDigest=None,
        releaseConsumerPeers={name: dict(uid=local.launcher.ROLE_IDENTITIES[name][0],
                                       gid=local.launcher.ROLE_IDENTITIES[name][1]) for name in local.SERVICE_ROLES})
    return replace_payload(result, payload)


def replace_payload(selected, payload):
    result = copy.deepcopy(selected)
    raw = local.spec.canonical_json_bytes(payload)
    result.update(payloadOriginal=raw.decode("ascii"), payloadSha256=local.sha(raw))
    return result


def sealed(raw):
    fd = os.memfd_create("synthetic-configuration", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, raw); os.fchmod(fd, 0o400); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, local.io.SEALS)
    return fd


def historical_configuration(selected, payload, root):
    # Real configuration signatures and exact binding projections only. The
    # partial package below is never represented as an admitted artifact package.
    bindings = local.spec.role_binding_digests(selected["roleManifests"])
    schema, digest = local._validate_payload(payload, "authority-service", selected["generation"], bindings)
    envelope = dict(schema=local.generator.SERVICE_CONFIGURATION_SCHEMA, payload=payload,
        signature=local.spec.strict_base64url_encode(root.sign(local.signature_message("authority-service", payload))))
    binding = dict(fileDigest=local.sha(local.spec.canonical_json_bytes(envelope)),
        payloadDigest=digest, payloadSchema=schema, role="authority-service")
    generation = dict(sequence=selected["generation"]["sequence"],
        predecessorDigest=selected["generation"]["predecessorDigest"],
        minimumRollbackSequence=selected["generation"]["minimumRollbackSequence"],
        configurationBindingDigest=local.spec.configuration_generation_binding_digest(selected["generation"]),
        roleBindingDigests=bindings, configurationPayloadBindings=[binding])
    entry = dict(configurationEnvelope=envelope, configurationDigest=digest,
        artifactPackage=dict(generation=selected["generation"]))
    return entry, generation


class LocalConfigurationControls(unittest.TestCase):
    def test_fresh_signing_rejects_v1_but_historical_preparation_keeps_originals(self):
        from catchplate import authority_local_database_credentials as credentials
        selected, _, _ = fixture()
        local._require_current_database_issuances(selected)
        original = local.document(selected["databaseIssuanceOriginals"]["planner"].encode("ascii"), local.io.MAX_PUBLIC)
        original["schema"] = credentials.LEGACY_ISSUANCE_SCHEMA
        selected["databaseIssuanceOriginals"]["planner"] = local.spec.canonical_json_bytes(original).decode("ascii")
        self.assertEqual(prepare(selected)["selected"], selected)
        with self.assertRaises(ValueError): local._require_current_database_issuances(selected)
        # Source-order control: the actual fresh owner applies this gate before
        # private-key descriptor admission; this is not a live owner fixture.
        source = inspect.getsource(local.LocalConfigurationIssuer.__init__)
        self.assertLess(source.index("_require_current_database_issuances("),
                        source.index("io._input(signing_key_fd"))

    def test_historical_policy_genesis_preserves_exact_configuration_binding(self):
        selected, payload, root = fixture()
        payload[local.generator.genesis_policy.FIELD] = dict(
            auditStoreIdentityDigest=PIN, auditSignerPublicKeyDigest=local.sha(b"synthetic-audit-signer"))
        self.assertEqual(prepare(replace_payload(selected, payload))["payload"], payload)
        entry, generation = historical_configuration(selected, payload, root)
        self.assertEqual(history._configuration(entry, generation, root.public_key()),
            (payload, entry["configurationDigest"]))
        for field in (None, "fileDigest", "payloadDigest"):
            changed = copy.deepcopy(generation)
            if field is None:
                changed["configurationPayloadBindings"] = []
            else:
                changed["configurationPayloadBindings"][0][field] = local.sha(b"wrong-binding")
            with self.subTest(field=field), self.assertRaises(history.HistoricalArchiveError):
                history._configuration(entry, changed, root.public_key())

    def test_historical_policy_genesis_rejects_authenticated_root_as_audit_signer(self):
        selected, payload, root = fixture()
        payload[local.generator.genesis_policy.FIELD] = dict(auditStoreIdentityDigest=PIN,
            auditSignerPublicKeyDigest=local._spki(selected["configurationRootPublicKeyBase64Url"]))
        # The ordinary static validator has no root argument here. The actual
        # historical verifier must supply its authenticated root independently.
        entry, generation = historical_configuration(selected, payload, root)
        with self.assertRaises(local.generator.genesis_policy.core.TransitionKernelError):
            history._configuration(entry, generation, root.public_key())

    def test_historical_oauth_purpose_key_must_differ_from_authenticated_root(self):
        selected, original, root = fixture()
        policy = local.generator.oauth_activation_policy
        separate = Ed25519PrivateKey.from_private_bytes(b"O" * 32).public_key()
        for purpose_key, accepted in ((separate, True), (root.public_key(), False)):
            payload = copy.deepcopy(original)
            encoded = local.spec.strict_base64url_encode(purpose_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            payload[policy.FIELD] = dict(schema=policy.SCHEMA, deploymentId="synthetic-history",
                controlPlaneConfigurationDigest=PIN, enrollmentRootPublicKeyBase64Url=encoded,
                enrollmentRootSpkiSha256=local._spki(encoded))
            entry, generation = historical_configuration(selected, payload, root)
            with self.subTest(accepted=accepted):
                if accepted:
                    self.assertEqual(history._configuration(entry, generation, root.public_key()),
                        (payload, entry["configurationDigest"]))
                else:
                    with self.assertRaises((history.HistoricalArchiveError, local.generator.GeneratorError)):
                        history._configuration(entry, generation, root.public_key())

    def test_real_certificate_source_service_and_signed_witness_joins(self):
        selected, payload, root = fixture()
        self.assertEqual(prepare(selected)["payload"], payload)
        second = witness(selected, payload, root)
        result = prepare(second)
        self.assertEqual(result["payload"]["authorityConfigurationDigests"], [prepare(selected)["payloadDigest"]])

    def test_two_existing_signature_domains_are_not_interchangeable(self):
        payload = {"public": "synthetic-domain-only"}
        raw = local.spec.canonical_json_bytes(payload)
        service = ("sha256:" + hashlib.sha256(local.generator.SERVICE_CONFIGURATION_SCHEMA.encode("ascii")
            + b"\0" + len(raw).to_bytes(8, "big") + raw).hexdigest()).encode("ascii")
        self.assertEqual(local.signature_message("authority-service", payload), service)
        self.assertEqual(local.signature_message("witness", payload), local.spec.domain_digest(
            local.generator.WITNESS_CONFIGURATION_SCHEMA, raw).encode("ascii"))
        key = Ed25519PrivateKey.from_private_bytes(SEED)
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(key.sign(service), local.signature_message("witness", payload))

    def test_actual_protected_fd_owner_signs_exact_payload_once(self):
        if os.geteuid() != 0 or os.getegid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            self.skipTest("real protected owner requires isolated root -I -B; not simulated")
        selected, payload, root = fixture()
        raw = local.spec.canonical_json_bytes(selected)
        public, private = sealed(raw), sealed(SEED)
        try:
            owner = local.LocalConfigurationIssuer(approval_fd=public, approval_sha256=local.sha(raw), signing_key_fd=private)
            result_raw = owner.issue()
            result = local.document(result_raw, local.MAX_CONFIGURATION)
            self.assertEqual(result["payload"], payload)
            self.assertFalse(result_raw.endswith(b"\n"))
            root.public_key().verify(local.spec.strict_base64url_decode(result["signature"], name="actual output", decoded_size=64),
                                     local.signature_message("authority-service", payload))
            with self.assertRaises(ValueError):
                owner.issue()
        finally:
            os.close(public); os.close(private)

    def test_purpose_root_role_bytes_and_original_clock_substitutions_refuse(self):
        selected, _, _ = fixture()
        changes = []
        for fields in (dict(purpose="sign-anything"), dict(deadlineBoottimeNs=selected["issuedAtBoottimeNs"]),
                       dict(expiresAtUnixNanos=selected["issuedAtUnixNanos"]), dict(bootIdDigest="sha256:"+"9"*64)):
            changed = copy.deepcopy(selected); changed.update(fields); changes.append(changed)
        changed = copy.deepcopy(selected); changed["generation"]["trustMode"]["mode"] = "tee-hardware"; changes.append(changed)
        changed = copy.deepcopy(selected); changed["roleOriginals"]["issuer"] += " "; changes.append(changed)
        changed = copy.deepcopy(selected); changed["runtimePublicKeys"]["issuer"] = selected["configurationRootPublicKeyBase64Url"]; changes.append(changed)
        for changed in changes:
            with self.subTest(change=changed["purpose"]), self.assertRaises((ValueError, local.generator.GeneratorError)):
                local.prepare(local.spec.canonical_json_bytes(changed), boot=selected["bootIdDigest"],
                    now_boottime_ns=selected["issuedAtBoottimeNs"], now_unix_ns=selected["issuedAtUnixNanos"])

    def test_actual_certificate_identity_and_issuance_pin_substitutions_refuse(self):
        selected, payload, _ = fixture()
        for field in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn"):
            changed = copy.deepcopy(payload); changed["roles"]["issuer"][field] += "changed"
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare(replace_payload(selected, changed))
        for role in ("verifier", "issuer", "executor"):
            changed = copy.deepcopy(payload); changed[role + "CredentialIssuanceDigest"] = PIN
            with self.subTest(role=role), self.assertRaises(ValueError):
                prepare(replace_payload(selected, changed))

    def test_verifier_issuance_requires_its_actual_original_not_another_role(self):
        selected, payload, _ = fixture()
        for replacement in (None, payload["issuerCredentialIssuanceDigest"],
                            payload["executorCredentialIssuanceDigest"]):
            changed = copy.deepcopy(payload)
            if replacement is None:
                del changed["verifierCredentialIssuanceDigest"]
            else:
                changed["verifierCredentialIssuanceDigest"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(local.generator.GeneratorError):
                prepare(replace_payload(selected, changed))

    def test_witness_requires_literal_signed_service_and_no_fabricated_history(self):
        selected, payload, root = fixture()
        second = witness(selected, payload, root)
        altered = copy.deepcopy(second)
        service = local.document(altered["serviceConfigurationOriginal"].encode("ascii"), local.MAX_CONFIGURATION)
        service["payload"]["launchNonceDigest"] = "sha256:"+"9"*64
        altered["serviceConfigurationOriginal"] = local.spec.canonical_json_bytes(service).decode("ascii")
        with self.assertRaises(InvalidSignature):
            prepare(altered)
        changed = local.document(second["payloadOriginal"].encode("ascii"), local.MAX_CONFIGURATION)
        changed["minimumReceiptDigest"] = PIN
        with self.assertRaises(ValueError):
            prepare(replace_payload(second, changed))

    def test_fixed_cli_and_canonical_finite_configuration_numbers(self):
        args = ["--approval-fd", "3", "--approval-sha256", PIN, "--signing-key-fd", "4"]
        self.assertEqual(cli.arguments(args)["signing_key_fd"], 4)
        for invalid in (args+["--mode", "native"], args[:-1]+["3"], [args[0], "03", *args[2:]]):
            with self.assertRaises(ValueError):
                cli.arguments(invalid)
        self.assertEqual(local.document(b'{"timeout":0.5}', 64), {"timeout": 0.5})
        for raw in (b'{"timeout":NaN}', b'{"x":1,"x":2}', b'{ "x":1}'):
            with self.assertRaises(ValueError):
                local.document(raw, 64)

    def test_shared_file_validator_delegates_and_public_checks_precede_key_read(self):
        source = inspect.getsource(local.generator._validate_configuration_document)
        self.assertIn("return validate_configuration_payload(", source)
        tree = ast.parse(inspect.getsource(local.LocalConfigurationIssuer))
        issue = next(row for row in tree.body[0].body if isinstance(row, ast.FunctionDef) and row.name == "issue")
        calls = [row for row in ast.walk(issue) if isinstance(row, ast.Call) and isinstance(row.func, ast.Attribute)]
        self.assertLess(next(row.lineno for row in calls if row.func.attr == "check"),
                        next(row.lineno for row in calls if row.func.attr == "signing_key"))
        self.assertIn("self._prepared = prepare(", inspect.getsource(local.LocalConfigurationIssuer.__init__))
        self.assertIn('root_digest=_spki(selected["configurationRootPublicKeyBase64Url"])', inspect.getsource(local._service))


class IssuedConfigurationCustodyControls(unittest.TestCase):
    """Real synthetic issuance/FD custody only; no DB, pilot startup or reader."""

    def setUp(self):
        if os.geteuid() != 0 or os.getegid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            self.skipTest("real protected custody requires isolated root -I -B; not simulated")
        self.inputs = set()
        self.addCleanup(self._close_inputs)

    def _close_inputs(self):
        while self.inputs:
            os.close(self.inputs.pop())

    def _issuer(self, *, regular=False):
        selected, payload, root = fixture()
        raw = local.spec.canonical_json_bytes(selected)
        path = None
        if regular:
            directory = tempfile.TemporaryDirectory(prefix="configuration-custody-")
            self.addCleanup(directory.cleanup)
            path = Path(directory.name) / "approval.json"
            path.write_bytes(raw); path.chmod(0o400)
            public = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            public = sealed(raw)
        private = sealed(SEED)
        self.inputs.update((public, private))
        issuer = local.LocalConfigurationIssuer(approval_fd=public, approval_sha256=local.sha(raw), signing_key_fd=private)
        return issuer, selected, payload, root, public, private, path

    def _take(self, issuer):
        with local._owning():
            custody = issuer.take_public_custody()
        self.addCleanup(custody.close)
        return custody

    def test_successful_public_custody_keeps_originals_without_private_key(self):
        issuer, selected, payload, root, public, private, _ = self._issuer()
        issued = issuer.issue()
        custody = self._take(issuer)
        self.assertEqual(custody.service_original(), issued)
        self.assertEqual(custody.approval_original(), local.spec.canonical_json_bytes(selected))
        self.assertEqual(custody.verifier_issuance_original(), selected["databaseIssuanceOriginals"]["verifier"].encode("ascii"))
        self.assertEqual(os.fstat(custody._fd).st_ino, os.fstat(public).st_ino)
        self.assertNotIn(custody._fd, (public, private))
        self.assertFalse(os.get_inheritable(custody._fd))
        self.assertFalse(hasattr(custody, "issue") or hasattr(custody, "_key_fd") or hasattr(custody, "_prepared"))
        self.assertFalse(any(getattr(custody, name) is issuer for name in custody.__slots__))
        # The caller releases BOTH borrowed originals. Only a public duplicate
        # remains; checks must not reach the issuer or any signing operation.
        for fd in (public, private):
            os.close(fd); self.inputs.remove(fd)
        with mock.patch.object(local.io, "signing_key", side_effect=AssertionError("private access")), \
                mock.patch.object(local.LocalConfigurationIssuer, "check", side_effect=AssertionError("issuer retained")):
            custody.check()
            result = local.document(custody.service_original(), local.MAX_CONFIGURATION)
            root.public_key().verify(local.spec.strict_base64url_decode(result["signature"], name="actual output", decoded_size=64),
                local.signature_message("authority-service", payload))
        owned = custody._fd
        custody.close(); custody.close()
        with self.assertRaises(OSError):
            os.fstat(owned)
        with self.assertRaises(ValueError):
            custody.check()

    def test_failed_issue_duplicate_and_failed_acquisition_refuse(self):
        issuer, *_ = self._issuer()
        with self.assertRaises(ValueError):
            issuer.take_public_custody()
        # Failure after real signing but before the final issuer check returns
        # must not produce a success slot or an acquirable public owner.
        with mock.patch.object(issuer, "check", side_effect=[None, ValueError("synthetic post-sign failure")]):
            with self.assertRaises(ValueError):
                issuer.issue()
        self.assertIsNone(issuer._issued_original)
        with self.assertRaises(ValueError):
            issuer.take_public_custody()
        success, *_ = self._issuer()
        success.issue(); self._take(success)
        with self.assertRaises(ValueError):
            success.take_public_custody()
        failed, *_ = self._issuer()
        failed.issue()
        real_fcntl = fcntl.fcntl
        def fail_dup(fd, operation, *args):
            if operation == fcntl.F_DUPFD_CLOEXEC:
                raise OSError("synthetic duplicate failure")
            return real_fcntl(fd, operation, *args)
        with mock.patch.object(local.fcntl, "fcntl", side_effect=fail_dup):
            with self.assertRaises(OSError):
                failed.take_public_custody()
        self.assertTrue(failed._public_custody_attempted)
        with self.assertRaises(ValueError):
            failed.take_public_custody()

    def test_original_bounds_and_changed_approval_refuse_but_owned_close_remains_safe(self):
        issuer, selected, _, _, public, private, _ = self._issuer()
        issuer.issue(); custody = self._take(issuer)
        with mock.patch.object(local.launcher, "_boot_identity_digest", return_value="sha256:" + "0" * 64):
            with self.assertRaises(ValueError):
                custody.check()
        with mock.patch.object(local.io, "_clock", return_value=selected["issuedAtBoottimeNs"] - 1):
            with self.assertRaises(ValueError):
                custody.check()
        with mock.patch.object(local.io, "_clock", return_value=selected["deadlineBoottimeNs"]), \
                mock.patch.object(local.time, "time_ns", return_value=selected["expiresAtUnixNanos"]):
            with self.assertRaises(ValueError):
                custody.check()
            custody.close()  # Expiry must not leak or consume borrowed inputs.
        os.fstat(public); os.fstat(private)
        changed, _, _, _, original, _, path = self._issuer(regular=True)
        changed.issue(); mutated = self._take(changed)
        path.chmod(0o600)
        with path.open("r+b") as writer:
            writer.seek(-1, os.SEEK_END); writer.write(b"x")
        path.chmod(0o400)
        with self.assertRaises(ValueError):
            mutated.check()
        mutated.close()
        os.fstat(original)

    def test_issued_payload_and_signature_are_checked_not_caller_factory_inputs(self):
        with self.assertRaises(TypeError):
            local.IssuedConfigurationCustody()
        issuer, *_ = self._issuer()
        issuer.issue(); custody = self._take(issuer)
        original = custody._issued
        for field in ("payload", "signature"):
            changed = local.document(original, local.MAX_CONFIGURATION)
            if field == "payload":
                changed["payload"]["launchNonceDigest"] = "sha256:" + "0" * 64
            else:
                changed["signature"] = local.spec.strict_base64url_encode(bytes(64))
            custody._issued = local.spec.canonical_json_bytes(changed)
            with self.subTest(field=field), self.assertRaises((ValueError, InvalidSignature)):
                custody.check()
        custody._issued = original
        custody.check()
        self.assertEqual(tuple(inspect.signature(local.LocalConfigurationIssuer.take_public_custody).parameters), ("self",))
        self.assertEqual(tuple(inspect.signature(local.IssuedConfigurationCustody._take).parameters), ("issuer",))

    def test_real_fork_cannot_issue_or_take_inherited_issuer(self):
        unissued, *_ = self._issuer()
        issued, *_ = self._issuer()
        issued.issue()
        child = os.fork()
        if child == 0:
            try:
                for action in (unissued.check, unissued.issue, issued.take_public_custody):
                    try:
                        action()
                    except ValueError:
                        continue
                    os._exit(31)
                os._exit(0)
            except BaseException:
                os._exit(32)
        reaped, status = os.waitpid(child, 0)
        self.assertEqual(reaped, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertFalse(unissued._used or issued._public_custody_attempted)
        unissued.check()
        self._take(issued).check()

    def test_selected_pilot_template_retains_checks_and_closes_public_owner(self):
        path = os.environ.get("CATCHPLATE_TEST_PILOT_CONFIGURATION_TEMPLATE")
        if path is None:
            self.skipTest("explicit selected template path required for integration source control")
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        owner = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == "LiveConfiguration")
        methods = {row.name: row for row in owner.body if isinstance(row, ast.FunctionDef)}
        calls = lambda node, name: [row for row in ast.walk(node) if isinstance(row, ast.Call)
            and isinstance(row.func, ast.Attribute) and row.func.attr == name]
        signing = methods["_sign_configuration"]
        self.assertLess(calls(signing, "issue")[0].lineno, calls(signing, "_publish")[0].lineno)
        self.assertLess(calls(signing, "_publish")[0].lineno, calls(signing, "take_public_custody")[0].lineno)
        branch = next(row for row in signing.body if isinstance(row, ast.If))
        self.assertEqual(ast.unparse(branch.test), "name == 'authority-service'")
        protected = next(row for row in branch.body if isinstance(row, ast.With))
        self.assertEqual(ast.unparse(protected.items[0].context_expr), "configuration._owning()")
        self.assertEqual(ast.unparse(protected.body[0]), "self.configuration_custody = owner.take_public_custody()")
        for method, operation in (("check", "check"), ("close", "close")):
            self.assertIn("self.configuration_custody." + operation + "()", ast.unparse(methods[method]))
        close = ast.unparse(methods["close"])
        self.assertLess(close.index("self.configuration_custody.close()"), close.index("while self.handles:"))


if __name__ == "__main__":
    unittest.main()
