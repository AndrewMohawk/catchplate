#!/usr/bin/env python3
"""Exercise real source registration and bounded metadata fault injection.

Positive registration uses the complete actual registry, not invented kernels.
Negative tests change one contributor or operation contract. Registration does
not establish configured authority execution, PostgreSQL admission or a pilot.
"""
from __future__ import annotations

import runpy
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract  # noqa: E402
from serverware import authority_jit_request  # noqa: E402
from serverware import authority_successor_programs  # noqa: E402
from serverware import authority_transition_core as core  # noqa: E402
from serverware import authority_transition_policy  # noqa: E402
from serverware import authority_transition_quota  # noqa: E402
from serverware import authority_transition_registry  # noqa: E402


_CHALLENGE_OPERATIONS = frozenset(
    {
        "webauthn.challenge.create",
        "webauthn.challenge.claim",
        "webauthn.challenge.consume",
    }
)
_DISABLED_OPERATIONS = frozenset({
    "jit.consume",
    "webauthn.recovery.create",
    "webauthn.recovery.candidate",
    "webauthn.recovery.finalize",
    "webauthn.recovery.expire",
    "webauthn.recovery.prune",
    "webauthn.recovery.invalidate",
})
_COMPONENT_ONLY_OPERATIONS = frozenset({
    "jit.review-open.authorize", "jit.review-open.receipt.issue",
})


class AuthorityTransitionRegistryTests(unittest.TestCase):
    def _kernels(self) -> dict[str, core.TransitionKernel]:
        return dict(authority_transition_policy.KERNELS)

    def _load_registry(
        self,
        kernels: dict[str, object],
        *,
        quota_kernels: dict[str, SimpleNamespace] | None = None,
    ) -> dict[str, object]:
        with (
            patch.object(authority_transition_policy, "KERNELS", kernels),
            patch.object(
                authority_transition_quota,
                "KERNELS",
                {**authority_transition_quota.KERNELS, **(quota_kernels or {})},
            ),
        ):
            return runpy.run_path(
                str(ROOT / "serverware" / "authority_transition_registry.py")
            )

    def test_actual_complete_source_partition_is_accepted(self) -> None:
        # Do not replace any registry, operation or kernel for this positive.
        loaded = runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))
        self.assertEqual(loaded["INTENTIONALLY_DISABLED_OPERATIONS"], _DISABLED_OPERATIONS)
        self.assertEqual(loaded["WEBAUTHN_CHALLENGE_OPERATIONS"], _CHALLENGE_OPERATIONS)
        self.assertEqual(set(loaded["KERNELS"]), {
            operation for operation in authority_contract.OPERATION_REGISTRY
            if authority_contract.operation_spec(operation)["planningMode"] == "typed-pure-transition"
        })
        self.assertTrue(all(kernel is authority_transition_registry.KERNELS[operation]
            for operation, kernel in loaded["KERNELS"].items()))
        self.assertEqual(
            loaded["PLANNABLE_OPERATIONS"],
            set(authority_contract.OPERATION_REGISTRY) - _DISABLED_OPERATIONS - _COMPONENT_ONLY_OPERATIONS,
        )
        self.assertEqual(loaded["COMPONENT_ONLY_SUCCESSOR_OPERATIONS"], _COMPONENT_ONLY_OPERATIONS)
        self.assertEqual(loaded["_CLOSURE_ERRORS"], ())
        self.assertFalse(
            loaded["PLANNABLE_OPERATIONS"] & _DISABLED_OPERATIONS
        )

    def test_real_review_components_are_not_planning_owners(self) -> None:
        for operation in _COMPONENT_ONLY_OPERATIONS:
            program = authority_transition_registry.SUCCESSOR_PROGRAMS[operation]
            self.assertEqual(program.result_kind, "read-replay-components")
            self.assertTrue(callable(program.factory) and callable(program.kernel_factory))
            self.assertIsNone(program.plan_factory)
            self.assertNotIn(operation, authority_transition_registry.PLANNABLE_OPERATIONS)
            self.assertNotIn(operation, authority_transition_registry.SUCCESSOR_PLANNABLE_OPERATIONS)
            with self.assertRaises(ValueError):
                authority_transition_registry.successor_program(operation)

    def test_review_component_factories_and_kind_are_closed(self) -> None:
        for operation in _COMPONENT_ONLY_OPERATIONS:
            original = authority_successor_programs.PROGRAMS[operation]
            for change, diagnostic in (({"kernel_factory": None}, "kernel-factory"),
                    ({"plan_factory": original.factory}, "plan-factory"),
                    ({"result_kind": "read-acquisition"}, "result-kind")):
                with self.subTest(operation=operation, change=change):
                    changed = {**authority_successor_programs.PROGRAMS,
                        operation: replace(original, **change)}
                    with patch.object(authority_successor_programs, "PROGRAMS", changed):
                        with self.assertRaisesRegex(RuntimeError,
                                rf"invalid successor program {operation}=\[{diagnostic}\]"):
                            runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))

    def test_existing_successor_cannot_be_relabelled_as_component_only(self) -> None:
        operation = "oidc.session.activate"
        original = authority_successor_programs.PROGRAMS[operation]
        changed = {**authority_successor_programs.PROGRAMS,
            operation: replace(original, result_kind="read-replay-components",
                kernel_factory=original.factory, plan_factory=None)}
        with patch.object(authority_successor_programs, "PROGRAMS", changed):
            with self.assertRaisesRegex(RuntimeError,
                    rf"invalid successor program {operation}=\[result-kind, kernel-factory, plan-factory\]"):
                runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))

    def test_missing_kernels_are_named_in_sorted_order(self) -> None:
        kernels = self._kernels()
        missing = (
            "webauthn.counter.cas",
            "webauthn.trust.error",
        )
        for operation in missing:
            kernels.pop(operation)
        with self.assertRaises(RuntimeError) as caught:
            self._load_registry(kernels)
        self.assertIn(
            "missing transition kernels=[" + ", ".join(missing) + "]",
            str(caught.exception),
        )
        self.assertIn(
            "uncovered operation contracts=[" + ", ".join(missing) + "]",
            str(caught.exception),
        )

    def test_unknown_kernel_is_rejected_without_contract_lookup_error(self) -> None:
        kernels = self._kernels()
        kernels["unknown.operation"] = SimpleNamespace()
        with self.assertRaisesRegex(
            RuntimeError,
            r"unexpected transition kernels=\[unknown.operation\]",
        ):
            self._load_registry(kernels)

    def test_kernel_identity_and_empty_mutation_type_remain_closed(self) -> None:
        operation = "webauthn.counter.cas"
        for attribute, value, diagnostic in (
            ("operation", "webauthn.trust.error", "operation"),
            ("handler", "different_handler", "handler"),
            ("program_id", "different-program", "program-id"),
            ("permits_empty_mutation", 1, "permits-empty-mutation"),
        ):
            with self.subTest(attribute=attribute):
                kernels = self._kernels()
                original = kernels[operation]
                fields = {name: getattr(original, name) for name in
                    ("operation", "handler", "program_id", "permits_empty_mutation")}
                kernels[operation] = SimpleNamespace(**{**fields, attribute: value})
                with self.assertRaisesRegex(
                    RuntimeError,
                    rf"invalid transition kernel {operation}=\[{diagnostic}\]",
                ):
                    self._load_registry(kernels)

    def test_disabled_operation_cannot_be_registered(self) -> None:
        for operation in sorted(_DISABLED_OPERATIONS):
            with self.subTest(operation=operation):
                kernels = self._kernels()
                kernels[operation] = SimpleNamespace(
                    operation=operation,
                    handler=authority_contract.operation_spec(operation)["handler"],
                    program_id=authority_contract.transition_program_id(operation),
                    permits_empty_mutation=False,
                )
                with self.assertRaises(RuntimeError) as caught:
                    self._load_registry(kernels)
                self.assertIn(
                    f"unexpected transition kernels=[{operation}]",
                    str(caught.exception),
                )
                self.assertIn(
                    f"disabled operations are plannable=[{operation}]",
                    str(caught.exception),
                )

    def test_planning_modes_remain_closed(self) -> None:
        for operation in (
            "webauthn.counter.cas",
            "webauthn.challenge.create",
            "jit.consume",
        ):
            with self.subTest(operation=operation):
                kernels = self._kernels()
                specs = dict(authority_contract.OPERATIONS)
                specs[operation] = {
                    **specs[operation],
                    "planningMode": "unrecognized-planning-mode",
                }
                with patch.object(authority_contract, "OPERATIONS", specs):
                    with self.assertRaisesRegex(RuntimeError, operation):
                        self._load_registry(kernels)

    def test_challenge_operation_cannot_also_be_a_transition_kernel(self) -> None:
        kernels = self._kernels()
        operation = "webauthn.challenge.create"
        kernels[operation] = SimpleNamespace(
            operation=operation,
            handler=authority_contract.operation_spec(operation)["handler"],
            program_id=authority_contract.transition_program_id(operation),
            permits_empty_mutation=False,
        )
        with self.assertRaisesRegex(
            RuntimeError,
            r"unexpected transition kernels=\[webauthn.challenge.create\]",
        ):
            self._load_registry(kernels)

    def test_special_operation_contract_cannot_disappear(self) -> None:
        for operation in ("webauthn.challenge.create", "jit.consume"):
            with self.subTest(operation=operation):
                kernels = self._kernels()
                operations = dict(authority_contract.OPERATION_REGISTRY)
                operations.pop(operation)
                with patch.object(
                    authority_contract, "OPERATION_REGISTRY", operations
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        rf"missing operation contract=\[{operation}\]",
                    ):
                        self._load_registry(kernels)

    def test_overlapping_registries_name_the_operation(self) -> None:
        kernels = self._kernels()
        operation = "webauthn.counter.cas"
        with self.assertRaisesRegex(
            RuntimeError,
            r"authority transition kernel registries overlap: webauthn.counter.cas",
        ):
            self._load_registry(
                kernels,
                quota_kernels={operation: kernels[operation]},
            )


class JitRequestDependencyContractTests(unittest.TestCase):
    """Real contract/kernel checks; no synthetic registry or admitted transition."""

    def _arguments(self) -> dict:
        policy = {"schema": "serverware.jitApproverPolicy/v1", "requireWebAuthn": True,
                  "threshold": 1, "requiredRoles": ["approver"], "roleMatch": "any",
                  "allowedApproverIds": ["reviewer"], "allowAnyApproverId": False,
                  "credentialPolicy": {
                      "allowedCredentialRecordIds": [], "allowedAuthenticatorClasses": ["hardware", "yubikey"],
                      "allowedAaguids": [], "requireAttestationTrusted": True,
                      "requiredTrustBundleDigest": None, "minimumTrustBundleSequence": None,
                      "rpId": "fixture.test", "origins": ["https://fixture.test"],
                      "requireUserPresence": True, "requireUserVerification": True,
                      "counterPolicy": "strict-or-zero", "maxAssertionAgeSeconds": 30,
                  }}
        digest = "sha256:" + "1" * 64
        arguments = {
            "route_id": "route:fixture", "method": "GET", "url": "https://fixture.test/resource",
            "principal_id": "principal:fixture", "credential_id": "", "credential_version": 0,
            "policy_hash": digest, "request_digest": digest, "operation_digest": None,
            "canonical_request": {"request": {"method": "GET"}},
            "redacted_display": {"summary": "synthetic dependency fixture"},
            "pending_ttl_seconds": 60, "grant_ttl_seconds": 30, "grant_max_uses": 1,
            "required_approver_roles": {"$authorityType": "set", "items": ["approver"]},
            "allowed_approver_ids": {"$authorityType": "set", "items": ["reviewer"]},
            "require_approver_webauthn": True, "approval_threshold": 1,
            "approver_credential_policy": policy["credentialPolicy"],
        }
        arguments["businessIntent"] = authority_contract.synthesize_business_intent("jit.request", arguments)
        return arguments

    def test_jit_request_reads_routes_not_a_fictitious_policies_relation(self) -> None:
        spec = authority_contract.operation_spec("jit.request")
        self.assertNotIn("policies", authority_contract._AUTHORIZATION_SOURCE_TABLES)
        for operation in authority_contract.OPERATIONS.values():
            self.assertNotIn("policies", operation["reads"])
            self.assertNotIn("policies", operation["writes"])
        self.assertIn("routes", spec["businessWrites"])
        self.assertIn("routes", spec["businessReadBeforeWrite"])
        self.assertTrue(spec["approverPolicyRequired"])
        self.assertIn("key-custody-seal/v1", spec["externalEvidenceTypes"])
        self.assertIn("opaque-value-receipt", spec["proofPrimitives"])
        kernel = authority_transition_quota.KERNELS["jit.request"]
        queries = kernel.queries(arguments=self._arguments(),
                                 database_now=datetime(2026, 1, 1, tzinfo=timezone.utc),
                                 request_digest="sha256:" + "2" * 64)
        self.assertIn("routes", {query.table for query in queries})
        self.assertLessEqual({query.table for query in queries}, set(spec["reads"]))
        projected = authority_jit_request.normalize(self._arguments(), request_digest="sha256:" + "2" * 64)
        self.assertEqual([query.absent_key for query in queries
            if query.table == "policy_authority_opaque_values"], [
                {"opaque_id": projected["canonical_request_opaque_id"]},
                {"opaque_id": projected["redacted_display_opaque_id"]}])

    def test_real_jit_approver_policy_guards_remain_before_missing_custody_denial(self) -> None:
        kernel = authority_transition_quota.KERNELS["jit.request"]

        def context(arguments: dict) -> core.KernelContext:
            return core.KernelContext(
                operation="jit.request", arguments=arguments, selected_rows=(),
                database_now=datetime(2026, 1, 1, tzinfo=timezone.utc),
                request_digest="sha256:" + "2" * 64,
            )

        arguments = self._arguments()
        # Valid policy reaches real missing-custody rejection, not a fabricated
        # successful transition. No registry or evidence primitive is patched.
        with self.assertRaisesRegex(core.TransitionKernelError,
                                    "^authority transition exact row is absent or ambiguous$"):
            kernel.transition(context(arguments))
        for field, value in (("require_approver_webauthn", False), ("approval_threshold", 0), ("approval_threshold", True)):
            changed = {key: item for key, item in arguments.items() if key != "businessIntent"}
            changed[field] = value
            changed["businessIntent"] = authority_contract.synthesize_business_intent("jit.request", changed)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                core.TransitionKernelError, "^JIT request facade projection is invalid$"
            ):
                kernel.transition(context(changed))
        # Precomputed caller commitments are no longer a public facade field.
        changed = {**arguments, "approver_policy_digest": "sha256:" + "3" * 64}
        with self.assertRaisesRegex(core.TransitionKernelError, "^JIT request arguments are not the exact facade fields$"):
            kernel.transition(context(changed))


if __name__ == "__main__":
    unittest.main()
