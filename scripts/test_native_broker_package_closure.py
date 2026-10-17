#!/usr/bin/env python3
"""Offline source-package closure, not a broker launch or native admission.

Use the real producer's source staging and a fresh isolated interpreter with
only that staged catchplate package. Installed third-party packages are still
the test image's packages, but imports outside the producer's explicit three
dependencies are refused. No interpreter/ELF/SquashFS build is performed.
Historical evidence below is explicitly synthetic parser input, not a valid
Nitro quote or signature. Actual rotation and JIT material use real AESGCM;
the JIT owner receives a synthetic broker/channel, not actual FD3 custody.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if not __debug__ or sys.flags.optimize:
    raise RuntimeError("package closure tests require assertions enabled")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import package_native_broker_runtime as producer

# Literal prior source roster (e6bb3a17), independent of the repaired roster.
PRIOR_MODULES = (
    "__init__.py", "native_kms_cms.py", "native_service_tokens.py", "native_secret_broker_helper.py",
    "native_oauth_refresh.py", "native_oauth_refresh_receipts.py", "native_oauth_refresh_tls.py", "native_oauth_refresh_owner.py",
    "native_oauth_exchange.py", "native_oauth_exchange_receipts.py", "native_oauth_exchange_tls.py", "native_oauth_exchange_owner.py",
    "native_oauth_setup.py", "native_oauth_setup_rows.py", "native_oauth_setup_receipts.py", "native_oauth_setup_tls.py", "native_oauth_setup_owner.py",
    "native_oauth_cleanup.py", "native_oauth_cleanup_receipts.py", "native_oauth_cleanup_owner.py",
    "native_oauth_pending_retirement.py", "native_oauth_pending_retirement_receipts.py", "native_oauth_pending_retirement_owner.py",
    "oauth_retirement_values.py", "native_oauth_capture_retirement.py", "native_oauth_capture_retirement_receipts.py", "native_oauth_capture_retirement_owner.py",
    "oauth_retirement_policy_values.py", "oauth_pending_retirement_values.py",
    "oauth_capture_retirement_policy.py", "oauth_pending_retirement_policy.py",
    "native_oauth_reconnect.py", "native_oauth_reconnect_rows.py", "native_oauth_reconnect_receipts.py", "native_oauth_reconnect_tls.py", "native_oauth_reconnect_owner.py",
    "native_secret_broker_history.py", "native_oauth_succession.py", "native_oauth_succession_rows.py",
    "native_oauth_succession_materials.py", "native_oauth_succession_receipts.py", "native_oauth_succession_tls.py", "native_oauth_succession_owner.py",
    "authority_oauth_retirement_succession_catalog.py",
)
ADDED_MODULES = frozenset({
    "aws_credential_boundary.py", "github_app_boundary.py", "native_static_credential.py", "native_static_credential_owner.py",
    "native_static_credential_rotation.py", "native_static_credential_rotation_owner.py",
    "authority_static_credential_create.py", "authority_static_credential_rotate.py",
    "authority_publication_approval.py", "authority_setup_bind_credential.py",
    "authority_oauth_setup.py", "authority_oauth_activation.py", "static_credential_provenance_values.py",
})
JIT_MODULES = frozenset({
    "native_jit_review_owner.py", "native_jit_review_material.py",
    "authority_jit_private_request.py", "authority_jit_request.py",
    "authority_approver_policy.py", "rbac.py", "authority_contract.py",
    "authority_transition_core.py", "authority_complete_query.py",
    "authority_index_projection.py", "authority_index_contract.py", "authority_challenge_id.py",
    "authority_query_reads.py", "authority_query_read_work.py", "authority_request_commitment.py",
})

WORKER = r'''
import base64, copy, hashlib, importlib, json, os, sys
from pathlib import Path
if not __debug__ or sys.flags.optimize:
    raise RuntimeError("assertions disabled")
options = json.loads(sys.stdin.buffer.read(16385))
site = Path(options["site"]).resolve(strict=True)
allowed = {"catchplate"} | {"catchplate." + name[:-3] for name in options["modules"] if name != "__init__.py"}
assert not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules)
assert str(Path(options["checkout"]).resolve()) not in sys.path
sys.path.insert(0, str(site))
third_party = {"cryptography", "cffi", "pycparser", "_cffi_backend"}

class ImportBoundary:
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.partition(".")[0]
        if top == "catchplate":
            if fullname not in allowed:
                raise ImportError("unpackaged local import: " + fullname)
        elif top not in sys.stdlib_module_names and top not in third_party:
            raise ImportError("unpackaged external import: " + fullname)
        return None

sys.meta_path.insert(0, ImportBoundary())

def audit(event, arguments):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.fork", "os.posix_spawn"}:
        raise AssertionError("package test attempted external effect: " + event)

sys.addaudithook(audit)
import catchplate.native_secret_broker_helper as broker
# Import every declared local module, not just the first helper import chain.
for name in sorted(allowed):
    importlib.import_module(name)
from catchplate import authority_static_credential_create as creation
from catchplate import authority_static_credential_rotate as rotation
from catchplate import native_static_credential_rotation as material
from catchplate import native_static_credential_rotation_owner as owner
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
assert broker.native_static_credential_owner.Owner._profile is creation
assert broker.native_static_credential_rotation_owner.Owner is owner.Owner
assert owner.Owner._profile is rotation and owner.Owner._material is material

def refused(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("malformed original was accepted")

checks, jit_checks, jit_exercised = 0, 0, False
if options["operation"] == "rotation":
    # Literal independent grammar fixture: there is no signature/Nitro verifier
    # substitution and no claim that these historical originals prove custody.
    C, H = creation.canonical, creation.sha256
    B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    now = 1_800_000_000_000_000_000
    item = "12345678-1234-4234-8234-123456789abc"
    actor, cfg = "oidc:package-fixture", H(b"public synthetic configuration")
    kek_id, kek = "attested-memory-kek:" + "a" * 24, AESGCM(bytes(range(32)))
    policy = {"rpId": "unit.example", "origins": ["https://unit.example"],
        "allowedAuthenticatorClasses": ["hardware"], "hardwareRequired": True,
        "requireUserPresence": True, "requireUserVerification": True, "maxAssertionAgeSeconds": 30}
    prior = options["prior_version"]
    root_schema = "catchplate.staticCredentialCreationProvenance/v1" if prior == 1 else "catchplate.staticCredentialRotationProvenance/v1"
    digest_field = "creationRequestDigest" if prior == 1 else "rotationRequestDigest"
    statement_schema = "catchplate.nativeStaticCredentialGenerationStatement/v1" if prior == 1 else "catchplate.nativeStaticCredentialRotationStatement/v1"
    operation = "credential.static.create" if prior == 1 else "credential.static.rotate"
    key_id = H(b"synthetic historical key")
    boot_bytes = b"b" * 32
    statement = {"apiVersion": statement_schema, "operation": operation,
        "holderId": H(b"catchplate/credential-currentness-holder/v1\0" + boot_bytes + bytes.fromhex(key_id[7:])),
        "bootId": B(boot_bytes), "keyId": key_id,
        "controlPlaneResponseSigningKeyId": H(b"response key"), "deploymentId": "fixture",
        "instanceId": "spiffe://fixture/native", "controlPlaneConfigurationDigest": cfg,
        "actorId": actor, "credentialId": item, "credentialVersion": prior,
        "intentSha256": H(b"prior intent"), "generationSha256": H(b"prior generation"),
        "inputSha256": H(b"prior input"), "secretKekId": kek_id,
        "generationCreatedAtEpochNs": now - 100_000_000_000, "challenge": B(b"c" * 32),
        "policyHash": H(b"policy"), "dataPlaneBinarySha256": H(b"binary"),
        "intakeOrigin": "https://intake.example", "portalOrigin": "https://unit.example",
        "ingressLeafCertificateSha256": H(b"leaf"), "ingressLeafSpkiSha256": H(b"spki"),
        "issuedAtEpochNs": now - 100_000_000_000, "expiresAtEpochNs": now - 90_000_000_000}
    if prior > 1:
        statement.update(previousCredentialVersion=prior - 1,
            previousCredentialSha256=H(b"previous credential"),
            previousCurrentnessOriginRequestDigest=H(b"earlier request"),
            previousProvenanceSha256=H(b"earlier provenance"),
            predecessorBarrierSha256=H(b"earlier barrier"),
            predecessorCurrentnessRootSha256=H(b"earlier root"))
    evidence = {"statement": statement, "signature": "ed25519:" + B(b"s" * 64),
        "nativeKeyEvidence": {"apiVersion": "catchplate.nativeResponseProofKeyEvidence/v1",
            "responseProofPublicKey": B(b"k" * 32),
            "attestationDocumentB64": B(b"synthetic parser input; not a Nitro quote")}}
    origin = H(b"historical request")
    historical = {"apiVersion": root_schema, digest_field: origin, "nativeEvidenceOriginal": C(evidence).decode("ascii")}
    intent = {"credentialId": item, "previousCredentialVersion": prior, "credentialVersion": prior + 1,
        "previousCredentialSha256": H(b"previous credential bytes"),
        "previousCurrentnessOriginRequestDigest": origin, "previousProvenanceOriginal": C(historical).decode("ascii"),
        "name": "synthetic package fixture", "kind": "bearer", "metadata": {},
        "issuedAtEpochNs": now - 10_000_000_000, "expiresAtEpochNs": now + 300_000_000_000}

    def intent_bytes(value):
        return rotation.intent_original(actor_id=actor, configuration_digest=cfg,
            credential_policy=policy, request=value)

    encoded = intent_bytes(intent)
    assert json.loads(encoded)["request"] == intent
    generation = material.seal_generation_original(actor_id=actor, configuration_digest=cfg,
        credential_policy=policy, intent=intent, raw=b"public synthetic successor", secret_kek_id=kek_id,
        kek=kek, epoch_ns=now - 5_000_000_000)
    args = {"actor_id": actor, "control_plane_configuration_digest": cfg, "credential_policy": policy,
        "approval_id": None, "request": {**intent, "nativeGenerationOriginal": generation,
            "executionIssuedAtEpochNs": now - 1_000_000_000, "executionExpiresAtEpochNs": now + 10_000_000_000,
            "predecessorBarrierSha256": H(b"current barrier"), "predecessorCurrentnessRootSha256": H(b"current root")}}
    assert rotation.arguments(rotation.OPERATION, args) == args
    selected = {"schema": rotation.SCHEMA, "credentialPolicy": policy, "operationMaxSeconds": 30,
        "maximumArgumentBytes": rotation.MAX_ARGUMENT_BYTES, "maximumSecretBytes": rotation.MAX_SECRET_BYTES,
        "twoPersonRequired": False, "nativeSecretKekId": kek_id, "intentMaxSeconds": 3600,
        "nativeCustodyPurpose": rotation.NATIVE_CUSTODY_PURPOSE}
    rotation.verify_request_context(rotation.OPERATION, args, selected_policy=selected,
        expected_configuration_digest=cfg, now_epoch_ns=now)
    for field, value in (("credentialId", "12345678-1234-4234-8234-123456789abd"),
            ("previousCredentialVersion", prior + 1), ("previousCurrentnessOriginRequestDigest", H(b"different origin")),
            ("previousCredentialSha256", "sha256:" + "A" * 64)):
        refused(lambda field=field, value=value: intent_bytes({**intent, field: value}))
        checks += 1
    for field, value in (("holderId", H(b"different holder")), ("unknown", "field")):
        changed = copy.deepcopy(evidence)
        changed["statement"][field] = value
        changed_history = {**historical, "nativeEvidenceOriginal": C(changed).decode("ascii")}
        refused(lambda: intent_bytes({**intent, "previousProvenanceOriginal": C(changed_history).decode("ascii")}))
        checks += 1
    changed = copy.deepcopy(args)
    wrapper = json.loads(generation)
    wrapper["intentSha256"] = H(b"different generation intent")
    changed["request"]["nativeGenerationOriginal"] = C(wrapper).decode("ascii")
    refused(lambda: rotation.arguments(rotation.OPERATION, changed))
    checks += 1

if options["operation"] in {"jit", "jit-refusals"}:
    from unittest.mock import patch
    from catchplate import authority_contract as contract
    from catchplate import authority_jit_private_request as private
    from catchplate import authority_jit_request as jit_request
    from catchplate import native_jit_review_owner as jit
    from catchplate import native_jit_review_material as jit_material
    assert broker.native_jit_review_owner is jit
    C, H = jit_material.canonical, jit_material.sha256
    B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    raw = {"route_id": "route:synthetic", "method": "PUT", "principal_id": "agent:synthetic",
        "credential_id": "credential:synthetic", "credential_version": 7,
        "policy_hash": H(b"synthetic policy"), "request_digest": H(b"provider request"),
        "operation_digest": H(b"provider operation"), "url": "https://synthetic.invalid/private-url-canary",
        "canonical_request": {"private": "private-document-canary", "method": "PUT"},
        "redacted_display": {"label": "private-display-canary", "unicode": "caf\u00e9"},
        "pending_ttl_seconds": 300, "grant_ttl_seconds": 30, "grant_max_uses": 1,
        "required_approver_roles": {"$authorityType": "set", "items": ["approver"]},
        "allowed_approver_ids": None, "require_approver_webauthn": True, "approval_threshold": 1,
        "approver_credential_policy": {"rpId": "synthetic.invalid", "origins": ["https://synthetic.invalid"]}}
    envelope = private.prepare(raw)
    public, documents = private.validate_runtime_input(envelope)
    typed = {**public, "businessIntent": contract.synthesize_business_intent("jit.request", public)}
    authorization = {"schema": "catchplate.policyAuthorityV9Authorization/v1", "operation": "jit.request",
        "handler": "ensure_jit_approval_request", "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": typed}

    def framed(domain, *frames):
        return H(domain.encode("ascii") + b"\0" + b"".join(
            len(frame).to_bytes(8, "big") + frame for frame in frames))

    request_digest = framed("catchplate.policyAuthorityV9Request/v1", C(authorization))
    request = {**authorization, "schema": "catchplate.policyAuthorityV9Request/v1",
        "requestDigest": request_digest, "operationId": framed("catchplate.policyAuthorityOperation/v2",
            b"jit.request", request_digest.encode("ascii"))}
    jit_request.require_public_request(request)

    class Clock:
        wall = 1_800_000_000_000_000_000
        boot = 100_000_000_000
        def boottime(self, kind):
            assert kind == jit.time.CLOCK_BOOTTIME
            return self.boot

    class SyntheticChannel:
        def __init__(self, clock):
            self.clock, self.deadline = clock, clock.boot + 600_000_000_000
            self.messages = []
        def check(self, deadline=None):
            assert self.clock.boot < min(self.deadline, deadline or self.deadline)
        def send(self, value, deadline=None):
            self.check(deadline)
            self.messages.append(copy.deepcopy(value))

    class SyntheticBroker:
        # Not _Broker: no FD3, CMS, authenticated cold config or native claim.
        def __init__(self, channel):
            key = bytes(range(32))
            self.channel, self.kek = channel, AESGCM(key)
            self.commitment, self.rsa, self.service_tokens_opened = H(key), None, True
            self.key_id = "attested-memory-kek:" + self.commitment[7:31]
        def require_owner_configuration(self):
            self.channel.check()

    def configured():
        clock = Clock()
        synthetic = SyntheticBroker(SyntheticChannel(clock))
        identity = {name: H(name.encode("ascii")) for name in jit.IDENTITY_FIELDS}
        boot = b"b" * 32
        identity.update(bootId=B(boot), policyHash=raw["policy_hash"])
        identity["holderId"] = H(b"catchplate/credential-currentness-holder/v1\0" + boot
            + bytes.fromhex(identity["keyId"][7:]))
        config = {"apiVersion": jit.CONFIG, "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": H(b"synthetic configuration"),
            "deploymentId": "synthetic-offline", "instanceId": "spiffe://synthetic.invalid/native",
            "secretKekId": synthetic.key_id, "identity": identity, "attemptCapacity": 1}
        with patch.object(jit.time, "time_ns", lambda: clock.wall), \
                patch.object(jit.time, "clock_gettime_ns", clock.boottime):
            instance = jit.Owner(synthetic, {"apiVersion": jit.CHANNEL, "phase": "configure", "configuration": config})
        command = {"apiVersion": jit.CHANNEL, "phase": "seal-pair", "runtimeInput": copy.deepcopy(envelope),
            "publicRequest": copy.deepcopy(request), "issuedAtEpochNs": clock.wall,
            "sealExpiresAtEpochNs": clock.wall + 20_000_000_000,
            "documentExpiresAtEpochNs": clock.wall + 120_000_000_000,
            "deadlineBoottimeNs": clock.boot + 25_000_000_000, "challenge": B(b"c" * 32)}
        return instance, synthetic, clock, command

    instance, synthetic, clock, command = configured()
    instance.handle(command)
    assert len(synthetic.channel.messages) == 2
    result = synthetic.channel.messages[-1]
    assert result["phase"] == "prepared" and result["operation"] == "jit.request"
    assert result["statementBindings"]["requestDigest"] == request_digest
    assert result["statementBindings"]["pairSha256"] == H(C(result["pair"]))
    assert result["pair"]["scope"]["publicRequest"] == request
    assert jit_material.open_pair(result["pair"], expected_scope=result["pair"]["scope"],
        key_id=synthetic.key_id, kek=synthetic.kek, now_epoch_ns=clock.wall) == documents
    for canary in (b"private-url-canary", b"private-document-canary", b"private-display-canary"):
        assert canary not in C(result)
    assert instance._spent == {request_digest} and instance.operation is None
    jit_exercised = True
    if options["operation"] == "jit-refusals":
        refused(lambda: instance.handle(command))
        assert instance._poisoned and len(synthetic.channel.messages) == 2
        jit_checks += 1
        for failure in ("private", "public-digest", "kek", "open", "release"):
            instance, synthetic, clock, command = configured()
            if failure == "private":
                command["runtimeInput"]["privateDocuments"]["url"] += "-changed"
            elif failure == "public-digest":
                command["publicRequest"]["requestDigest"] = H(b"not the actual request")
            elif failure == "kek":
                synthetic.kek = AESGCM(bytes(reversed(range(32))))
            else:
                command["phase"] = failure
            refused(lambda: instance.handle(command))
            assert instance._poisoned and instance._spent == set()
            assert synthetic.channel.messages == [{"apiVersion": jit.CHANNEL, "phase": "configured"}]
            jit_checks += 1

# Prove both the external and local import fences fail without relying on the
# environment lacking these otherwise-installed modules.
for name in ("cbor2", "sqlite3_forbidden_fixture", "fastapi", "sqlalchemy", "psycopg", "requests",
        "db", "config", "env", "scripts.verify_nitro_tee", "catchplate.app", "catchplate.db",
        "catchplate.config", "catchplate.authority_store", "catchplate.authority_service",
        "catchplate.authority_planner", "catchplate.authority_transition_registry",
        "catchplate.authority_transition_quota", "catchplate.authority_primary_contract"):
    assert name not in sys.modules
    try:
        importlib.import_module(name)
    except ImportError:
        pass
    else:
        raise AssertionError("package import fence accepted " + name)
loaded = sorted(name for name in sys.modules if name == "catchplate" or name.startswith("catchplate."))
assert set(loaded) == allowed
for name in loaded:
    assert Path(sys.modules[name].__file__).resolve().is_relative_to(site / "catchplate")
print(json.dumps({"ok": True, "loaded": loaded, "rotationNegativeControls": checks,
    "jitOwnerExercised": jit_exercised, "jitNegativeControls": jit_checks,
    "brokerConstructed": False, "nativeAdmissionVerified": False}, sort_keys=True))
'''


class PackageClosureTests(unittest.TestCase):
    def staged(self, modules=None):
        temporary = tempfile.TemporaryDirectory(prefix="native-broker-package-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        closure = producer.Closure(1_700_000_000)
        closure.root = root
        with patch.object(producer, "SOURCE", ROOT), patch.object(
                producer, "BROKER_MODULES", producer.BROKER_MODULES if modules is None else modules):
            producer.add_broker_sources(closure)
        return root, closure, root / str(producer.SITE)[1:]

    def child(self, site, *, operation="import", prior_version=1):
        command = [sys.executable, "-I", "-B", "-c", WORKER]
        payload = {"site": str(site), "checkout": str(ROOT), "modules": producer.BROKER_MODULES,
            "operation": operation, "prior_version": prior_version}
        return subprocess.run(command, input=json.dumps(payload), text=True, capture_output=True,
            cwd=site, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}, timeout=20)

    def passed(self, result):
        self.assertEqual(result.returncode, 0, result.stderr[-6000:])
        self.assertEqual(result.stderr, "")
        value = json.loads(result.stdout)
        self.assertTrue(value["ok"])
        self.assertFalse(value["brokerConstructed"])
        self.assertFalse(value["nativeAdmissionVerified"])
        return value

    def test_explicit_roster_and_producer_use(self):
        self.assertIs(type(producer.BROKER_MODULES), tuple)
        self.assertEqual(len(producer.BROKER_MODULES), len(set(producer.BROKER_MODULES)))
        self.assertEqual(set(producer.BROKER_MODULES), set(PRIOR_MODULES) | ADDED_MODULES | JIT_MODULES)
        self.assertEqual(producer.PACKAGES, {"cryptography": "50.0.0", "cffi": "2.1.0", "pycparser": "3.0"})
        self.assertEqual((producer.MAX_FILE, producer.MAX_TOTAL, producer.MAX_FILES),
            (128 * 1024 * 1024, 512 * 1024 * 1024, 20000))
        tree = ast.parse(Path(producer.__file__).read_text())
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "main")
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "add_broker_sources"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0]), "add_broker_sources(closure)")

    def test_real_staging_bytes_modes_inventory_and_entrypoint(self):
        root, closure, site = self.staged()
        expected = {str(producer.SITE / "catchplate" / name) for name in producer.BROKER_MODULES} | {str(producer.HELPER)}
        self.assertEqual(set(closure.files), expected)
        actual = {"/" + str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)
        for name in producer.BROKER_MODULES:
            source, output = ROOT / "catchplate" / name, site / "catchplate" / name
            raw = output.read_bytes()
            self.assertEqual(raw, source.read_bytes())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o444)
            self.assertEqual(closure.files[str(producer.SITE / "catchplate" / name)],
                {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw), "mode": "0444"})
        self.assertEqual((root / str(producer.HELPER)[1:]).read_bytes(),
            (site / "catchplate/native_secret_broker_helper.py").read_bytes())

    def test_prior_roster_reproduces_real_missing_import(self):
        _, _, site = self.staged(PRIOR_MODULES)
        result = self.child(site)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ImportError", result.stderr)
        self.assertIn("aws_credential_boundary", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(str(ROOT / "catchplate"), result.stderr)

    def test_fixed_roster_imports_every_module_without_checkout_fallback(self):
        _, _, site = self.staged()
        value = self.passed(self.child(site))
        self.assertEqual(value["rotationNegativeControls"], 0)

    def test_rotation_creation_predecessor_uses_actual_packaged_parsers(self):
        _, _, site = self.staged()
        value = self.passed(self.child(site, operation="rotation", prior_version=1))
        self.assertEqual(value["rotationNegativeControls"], 7)

    def test_rotation_rotated_predecessor_uses_actual_packaged_parsers(self):
        _, _, site = self.staged()
        value = self.passed(self.child(site, operation="rotation", prior_version=2))
        self.assertEqual(value["rotationNegativeControls"], 7)

    def test_jit_owner_validates_and_seals_real_private_input_in_package(self):
        _, _, site = self.staged()
        value = self.passed(self.child(site, operation="jit"))
        self.assertTrue(value["jitOwnerExercised"])
        self.assertEqual(value["jitNegativeControls"], 0)

    def test_jit_owner_refuses_mismatch_replay_open_and_release_in_package(self):
        _, _, site = self.staged()
        value = self.passed(self.child(site, operation="jit-refusals"))
        self.assertTrue(value["jitOwnerExercised"])
        self.assertEqual(value["jitNegativeControls"], 6)


if __name__ == "__main__":
    unittest.main()
