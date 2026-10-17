#!/usr/bin/env python3
"""Prepared-install contracts with genuine signatures over SYNTHETIC descriptions.

The existing history fixture supplies an actually verified signed package. Its
file, snapshot and ELF descriptions are synthetic, not an installed or frozen
tree. These tests do not open installer custody, install trust, launch a native
process, or prove filesystem/physical-pilot acceptance. Grammar-only controls
are distinguished from actual Ed25519/package-verifier controls below.
"""
import ast
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority_history_roundtrip_fixture import build_package
from scripts.test_authority_local_install import configuration as old_configuration
from scripts.test_authority_local_install import plan as untrusted_plan
from catchplate import authority_artifact_spec as spec
from catchplate import authority_local_artifacts as artifacts
from catchplate import authority_local_install as install
from catchplate import authority_local_trust as trust
from catchplate import authority_local_trust_commit as commit

NOW = "2026-10-10T12:00:00Z"
PIN = "sha256:" + "1" * 64
CONFIGURATION_V2 = "catchplate.authorityTrustedHostLocalInstallation/v2"
PLAN_V3 = "catchplate.authorityTrustedHostLocalProvisioningPlan/v3"
RECEIPT_V2 = "catchplate.authorityTrustedHostLocalProvisioningReceipt/v2"


def synthetic_private(purpose):
    # Exactly the deterministic, public test-only seeds in build_package();
    # never host keys. The real verifier checks their actual public keys.
    return Ed25519PrivateKey.from_private_bytes(bytes([trust.PURPOSES.index(purpose) + 101]) * 32)


def selector():
    return dict(relativePath="prepared-static", device=7, inode=20, generation=3,
        freshPaths=["configuration/service.json"])


def rehash_plan(value):
    value.pop("planId", None)
    value["planId"] = spec.domain_digest(contract.PROVISIONING_PLAN_DIGEST_DOMAIN,
        spec.canonical_json_bytes(value))
    return value


class PreparedContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_package(now_datetime=datetime(2026, 10, 10, 12, tzinfo=timezone.utc))
        cls.verified = cls.fixture["verified"]
        cls.verification = artifacts._receipt(cls.verified, dict(
            signingKeys={"artifact-verifier": trust.key_id("artifact-verifier")},
            verifierSourceSha256=PIN, verifierIdentity="synthetic-prepared-contract",
            verificationValidUntil="2026-10-10T12:10:00Z"), policy_digest=PIN,
            instant=NOW, signer=synthetic_private("artifact-verifier"))

    def plan(self, *, prepared=True, selection=None):
        return contract.build_provisioning_plan(self.verified, self.verification,
            validation_time=NOW, source_root_fd=10, destination_root="/srv/authority-artifacts",
            owner_uid=0, owner_gid=0, trusted_host_local=True,
            prepared_static=(selector() if selection is None else selection) if prepared else None)

    def receipt(self, plan):
        prepared = plan["schema"] == PLAN_V3
        selected = plan.get("preparedStatic", selector())
        identity = dict(device=selected["device"], inode=selected["inode"],
            generation=selected["generation"], mode=plan["destination"]["directoryMode"], uid=0, gid=0)
        entries = [dict(path=row["path"], sha256=row["sourceSha256"], size=row["size"],
            mode=row["mode"], uid=row["uid"], gid=row["gid"], fsVerityDigest=PIN,
            device=selected["device"], inode=100 + index, generation=1, immutable=True,
            **({"action": row["action"]} if prepared else {}))
            for index, row in enumerate(plan["entries"])]
        key = self.verified.require_key(trust.key_id("artifact-provisioner"),
            "artifact-provisioner", at=NOW)
        value = dict(schema=RECEIPT_V2 if prepared else contract.LOCAL_PROVISIONING_RECEIPT_SCHEMA,
            planDigest=contract.provisioning_plan_digest(plan), planId=plan["planId"],
            generationDigest=plan["generationDigest"], generationSequence=plan["generationSequence"],
            destinationRootIdentity=dict(identity, inode=10, mode=0o750),
            generationDirectoryIdentity=identity, installedEntries=entries,
            stepContractDigest=plan["stepContractDigest"],
            completedSteps=[row["step"] for row in plan["steps"]], activated=False,
            completedAt=NOW, executorIdentity="synthetic-prepared-installer",
            executorMeasurementDigest=PIN, signatureKeyId=key.key_id,
            signatureAuthorizationDigest=key.authorization_digest,
            signatureAlgorithm="Ed25519", signatureBase64Url="")
        value["signatureBase64Url"] = spec.strict_base64url_encode(
            synthetic_private("artifact-provisioner").sign(contract.provisioning_receipt_signature_message(value)))
        return value

    def verify_receipt(self, receipt, plan):
        return contract.verify_provisioning_receipt(receipt, plan=plan,
            verified_package=self.verified, validation_time=NOW)

    def reconstruct_at_trust_commit(self, plan):
        # Execute only the actual consumer's selection and equality expressions,
        # with genuine package/receipt verification still inside the real builder.
        # This is not a mocked successful _authenticate/filesystem/trust commit.
        tree = ast.parse(Path(commit.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "LocalArtifactTrustCommit")
        method = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
            and node.name == "_authenticate")
        index = next(index for index, node in enumerate(method.body)
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id == "prepared" for target in node.targets))
        selection, comparison = method.body[index:index + 2]
        self.assertIsInstance(comparison, ast.Expr)
        self.assertIn("contract.build_provisioning_plan", ast.unparse(comparison))
        code = compile(ast.fix_missing_locations(ast.Module(body=[selection, comparison], type_ignores=[])),
            str(commit.__file__), "exec")
        namespace = dict(contract=contract, require=commit.require, plan=plan,
            verified=self.verified, verification=self.verification,
            self=SimpleNamespace(_instant=lambda: NOW),
            selected={"destination": {"path": "/srv/authority-artifacts"}})
        with patch.object(contract, "build_provisioning_plan", wraps=contract.build_provisioning_plan) as observed:
            exec(code, namespace)
            self.assertEqual(observed.call_count, 1)
            return observed.call_args

    def test_configuration_v2_is_closed_and_old_v1_is_unchanged_grammar(self):
        previous = old_configuration()
        self.assertEqual(install.CONFIGURATION_SCHEMA, "catchplate.authorityTrustedHostLocalInstallation/v1")
        self.assertEqual(install.configuration(spec.canonical_json_bytes(previous)), previous)
        current = dict(previous, schema=CONFIGURATION_V2, preparedStatic=selector())
        self.assertEqual(install.PREPARED_CONFIGURATION_SCHEMA, CONFIGURATION_V2)
        self.assertEqual(install.configuration(spec.canonical_json_bytes(current)), current)
        bad = [dict(previous, preparedStatic=selector()), dict(current, schema=previous["schema"]),
            dict(current, extra=True), dict(current, schema=PLAN_V3)]
        missing = deepcopy(current); missing.pop("preparedStatic"); bad.append(missing)
        for value in bad:
            with self.subTest(value=value), self.assertRaises((ValueError, contract.ProvisioningContractError)):
                install.configuration(spec.canonical_json_bytes(value))

    def test_selector_exact_path_metadata_and_types_are_closed_grammar(self):
        self.assertEqual(contract.validate_prepared_static(selector()), selector())
        changes = [dict(relativePath=value) for value in ("other", "../prepared-static", "/prepared-static", "prepared-static/")]
        changes += [dict(extra=True), dict(device=True), dict(device=-1), dict(inode=0),
            dict(inode="20"), dict(generation=0), dict(generation=True), dict(generation=2**64)]
        for change in changes:
            value = dict(selector(), **change)
            with self.subTest(change=change), self.assertRaises(contract.ProvisioningContractError):
                contract.validate_prepared_static(value)
        for field in selector():
            value = selector(); value.pop(field)
            with self.subTest(missing=field), self.assertRaises(contract.ProvisioningContractError):
                contract.validate_prepared_static(value)

    def test_fresh_paths_require_nonempty_sorted_unique_proper_current_roster_subset(self):
        paths = [row["path"] for row in self.verified.package["bundle"]["files"]]
        wrong = [[], paths, ["not-in-current-package"], [paths[0], paths[0]],
            [paths[1], paths[0]], ["../escape"], ["/absolute"], [True], "configuration/service.json", None]
        for fresh in wrong:
            with self.subTest(fresh=fresh), self.assertRaises(contract.ProvisioningContractError):
                self.plan(selection=dict(selector(), freshPaths=fresh))
        for rows in ([], [{"path": paths[0]}], [{"path": paths[0]}, {"path": paths[0]}],
                [{"path": paths[1]}, {"path": paths[0]}], [{"wrong": paths[0]}, {"path": paths[1]}]):
            with self.subTest(rows=rows), self.assertRaises(contract.ProvisioningContractError):
                contract.validate_prepared_static(selector(), rows)

    def test_signed_package_and_verification_receipt_bind_current_plan_entries(self):
        # These are real cryptographic validations, not grammar-only fixtures.
        self.assertEqual(spec.verify_signed_artifact_package(self.fixture["package"],
            trust_state=self.fixture["trust_state"], validation_time=NOW).package_digest,
            self.verified.package_digest)
        self.assertEqual(contract.verify_verification_receipt(self.verification,
            verified_package=self.verified, validation_time=NOW, accepted_receipt_digests=[]), "New")
        selected = selector()
        plan = self.plan(selection=selected)
        self.assertEqual(plan["schema"], PLAN_V3)
        self.assertEqual(plan["preparedStatic"], selected)
        self.assertEqual(plan["entries"], [dict(path=row["path"], sourceSha256=row["sha256"],
            size=row["size"], mode=row["mode"], uid=row["uid"], gid=row["gid"],
            requireFsVerity=True, requireImmutable=True,
            action="copy-fresh" if row["path"] in selected["freshPaths"] else "adopt-prepared-static")
            for row in self.verified.package["bundle"]["files"]])
        selected["freshPaths"].append("not-in-current-package")
        self.assertEqual(plan["preparedStatic"], selector())
        forged = deepcopy(self.verification)
        forged["receiptSignatureBase64Url"] = spec.strict_base64url_encode(b"x" * 64)
        with self.assertRaises(contract.ProvisioningContractError):
            contract.build_provisioning_plan(self.verified, forged, validation_time=NOW,
                source_root_fd=10, destination_root="/srv/authority-artifacts", owner_uid=0,
                owner_gid=0, trusted_host_local=True, prepared_static=selector())

    def test_old_local_and_native_schemas_actions_and_steps_remain_separate(self):
        for local in (True, False):
            previous = untrusted_plan(local=local)
            contract.validate_provisioning_plan(previous)
            self.assertNotIn("preparedStatic", previous)
            self.assertNotIn("action", previous["entries"][0])
            wrong = deepcopy(previous); wrong["preparedStatic"] = selector(); rehash_plan(wrong)
            with self.assertRaises(contract.ProvisioningContractError):
                contract.validate_provisioning_plan(wrong)
            wrong = deepcopy(previous); wrong["entries"][0]["action"] = "copy-fresh"; rehash_plan(wrong)
            with self.assertRaises(contract.ProvisioningContractError):
                contract.validate_provisioning_plan(wrong)
        self.assertEqual(contract.LOCAL_PROVISIONING_PLAN_SCHEMA,
            "catchplate.authorityTrustedHostLocalProvisioningPlan/v2")
        self.assertEqual(contract.LOCAL_PROVISIONING_RECEIPT_SCHEMA,
            "catchplate.authorityTrustedHostLocalProvisioningReceipt/v1")
        plan = self.plan()
        self.assertEqual([row["step"] for row in plan["steps"]], list(contract.LOCAL_PREPARED_PROVISIONING_STEPS))
        self.assertIn("renameat2-prepared-staging-noreplace", contract.LOCAL_PREPARED_PROVISIONING_STEPS)
        self.assertNotEqual(plan["steps"], self.plan(prepared=False)["steps"])

    def test_prepared_plan_rejects_action_step_and_schema_substitution(self):
        original = self.plan()
        changes = [lambda v: v.update(schema=contract.LOCAL_PROVISIONING_PLAN_SCHEMA),
            lambda v: v.update(schema=contract.PROVISIONING_PLAN_SCHEMA),
            lambda v: v.pop("preparedStatic"), lambda v: v["entries"][0].pop("action"),
            lambda v: v["entries"][0].update(action="copy"),
            lambda v: v["entries"][0].update(action="copy-fresh"),
            lambda v: v["entries"][0].update(requireFsVerity=False),
            lambda v: v["steps"][0].update(step="create-private-staging-directory")]
        self.assertEqual(original["entries"][0]["action"], "adopt-prepared-static")
        for change in changes:
            value = deepcopy(original); change(value)
            value["stepContractDigest"] = spec.domain_digest(contract.PROVISIONING_STEP_CONTRACT_DOMAIN,
                spec.canonical_json_bytes(value["steps"]))
            rehash_plan(value)
            with self.subTest(change=change), self.assertRaises(contract.ProvisioningContractError):
                contract.validate_provisioning_plan(value)

    def test_real_receipt_signatures_preserve_new_domain_and_old_local_behavior(self):
        for prepared in (False, True):
            plan = self.plan(prepared=prepared)
            self.assertEqual(self.verify_receipt(self.receipt(plan), plan), "New")
        plan = self.plan(); receipt = self.receipt(plan)
        self.assertEqual(receipt["schema"], RECEIPT_V2)
        self.assertEqual([row["action"] for row in receipt["installedEntries"]],
            [row["action"] for row in plan["entries"]])
        payload = dict(receipt); payload.pop("signatureBase64Url")
        message = contract.provisioning_receipt_signature_message(receipt)
        self.assertEqual(message, spec.domain_digest(contract.LOCAL_PREPARED_PROVISIONING_RECEIPT_SIGNATURE_DOMAIN,
            spec.canonical_json_bytes(payload)).encode("ascii"))
        for domain in (contract.LOCAL_PROVISIONING_RECEIPT_SIGNATURE_DOMAIN,
                contract.PROVISIONING_RECEIPT_SIGNATURE_DOMAIN):
            wrong = deepcopy(receipt)
            wrong["signatureBase64Url"] = spec.strict_base64url_encode(synthetic_private("artifact-provisioner").sign(
                spec.domain_digest(domain, spec.canonical_json_bytes(payload)).encode("ascii")))
            with self.assertRaises(contract.ProvisioningContractError):
                self.verify_receipt(wrong, plan)
        self.assertEqual(contract.provisioning_receipt_digest(receipt), spec.domain_digest(
            contract.LOCAL_PREPARED_PROVISIONING_RECEIPT_DIGEST_DOMAIN, spec.canonical_json_bytes(receipt)))

    def test_receipt_refuses_wrong_identity_device_action_schema_and_extra_fields(self):
        plan = self.plan(); original = self.receipt(plan)
        changes = [lambda v: v.update(schema=contract.LOCAL_PROVISIONING_RECEIPT_SCHEMA),
            lambda v: v.update(schema=contract.PROVISIONING_RECEIPT_SCHEMA), lambda v: v.update(extra=True),
            lambda v: v.update(activated=True), lambda v: v["installedEntries"][0].pop("action"),
            lambda v: v["installedEntries"][0].update(action="copy-fresh"),
            lambda v: v["installedEntries"][0].update(device=8),
            lambda v: v["destinationRootIdentity"].update(device=8)]
        for field in ("device", "inode", "generation"):
            changes.append(lambda v, key=field: v["generationDirectoryIdentity"].update({key: 1000}))
        for change in changes:
            value = deepcopy(original); change(value)
            with self.subTest(change=change), self.assertRaises(contract.ProvisioningContractError):
                contract.validate_provisioning_receipt(value, plan=plan)

    def test_prepared_selection_never_admits_native_or_production_profile(self):
        kwargs = dict(validation_time=NOW, source_root_fd=10, destination_root="/srv/authority-artifacts",
            owner_uid=0, owner_gid=0, prepared_static=selector())
        for local in (False, "true", 1):
            with self.subTest(local=local), self.assertRaises(contract.ProvisioningContractError):
                contract.build_provisioning_plan(self.verified, self.verification,
                    trusted_host_local=local, **kwargs)
        for mode in ("external-production", "tee-hardware"):
            forged = deepcopy(self.fixture["package"])
            forged["bundle"]["trustMode"]["mode"] = mode
            forged["generation"]["trustMode"]["mode"] = mode
            with self.subTest(mode=mode), self.assertRaises(spec.ArtifactContractError):
                spec.verify_signed_artifact_package(forged,
                    trust_state=self.fixture["trust_state"], validation_time=NOW)

    def test_trust_commit_reconstructs_exact_new_selection_and_omits_it_for_old_plan(self):
        plan = self.plan()
        call = self.reconstruct_at_trust_commit(plan)
        self.assertIs(call.kwargs["prepared_static"], plan["preparedStatic"])
        self.assertEqual(call.kwargs["prepared_static"], selector())
        self.assertNotIn("prepared_static", self.reconstruct_at_trust_commit(self.plan(prepared=False)).kwargs)
        for field, value in (("sourceSha256", PIN), ("size", 999), ("mode", 0o444)):
            changed = deepcopy(plan)
            row = next(row for row in changed["entries"] if row["path"] == "configuration/service.json")
            self.assertNotEqual(row[field], value)
            row[field] = value; rehash_plan(changed)
            # A self-consistent plan hash is not the current signed package's
            # roster. The actual consumer's independent rebuild must refuse.
            contract.validate_provisioning_plan(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.reconstruct_at_trust_commit(changed)


if __name__ == "__main__":
    unittest.main()
