#!/usr/bin/env python3
"""Exercise the registry guard with synthetic metadata, never authority execution.

These tests do not assert that the real operation implementation is complete.
The source-root control-plane startup test remains the integration gate for it.
"""
from __future__ import annotations

import runpy
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract  # noqa: E402
from serverware import authority_transition_core as core  # noqa: E402
from serverware import authority_transition_policy  # noqa: E402
from serverware import authority_transition_quota  # noqa: E402
from serverware import authority_transition_release  # noqa: E402


_CHALLENGE_OPERATIONS = frozenset(
    {
        "webauthn.challenge.create",
        "webauthn.challenge.claim",
        "webauthn.challenge.consume",
    }
)
_DISABLED_OPERATIONS = frozenset({"jit.consume"})


class AuthorityTransitionRegistryTests(unittest.TestCase):
    def _kernels(self) -> dict[str, SimpleNamespace]:
        return {
            operation: SimpleNamespace(
                operation=operation,
                handler=authority_contract.operation_spec(operation)["handler"],
                program_id=authority_contract.transition_program_id(operation),
                permits_empty_mutation=False,
            )
            for operation in authority_contract.OPERATION_REGISTRY
            if operation not in _CHALLENGE_OPERATIONS | _DISABLED_OPERATIONS
        }

    def _load_registry(
        self,
        kernels: dict[str, SimpleNamespace],
        *,
        quota_kernels: dict[str, SimpleNamespace] | None = None,
    ) -> dict[str, object]:
        with (
            patch.object(authority_transition_policy, "KERNELS", kernels),
            patch.object(
                authority_transition_quota,
                "KERNELS",
                quota_kernels if quota_kernels is not None else {},
            ),
            patch.object(authority_transition_release, "KERNELS", {}),
        ):
            return runpy.run_path(
                str(ROOT / "serverware" / "authority_transition_registry.py")
            )

    def test_exact_metadata_partition_is_accepted(self) -> None:
        kernels = self._kernels()
        loaded = self._load_registry(kernels)
        self.assertEqual(set(loaded["KERNELS"]), set(kernels))
        self.assertEqual(
            loaded["PLANNABLE_OPERATIONS"],
            set(kernels) | _CHALLENGE_OPERATIONS,
        )
        self.assertEqual(loaded["_CLOSURE_ERRORS"], ())
        self.assertFalse(
            loaded["PLANNABLE_OPERATIONS"] & _DISABLED_OPERATIONS
        )

    def test_missing_kernels_are_named_in_sorted_order(self) -> None:
        kernels = self._kernels()
        missing = (
            "webauthn.credential.revoke",
            "webauthn.registration.finalize",
            "webauthn.trust.complete",
            "webauthn.trust.stage",
        )
        for operation in missing:
            kernels.pop(operation)
        with self.assertRaises(RuntimeError) as caught:
            self._load_registry(kernels)
        self.assertEqual(
            str(caught.exception),
            "authority transition registry is not closed: "
            "missing transition kernels=[" + ", ".join(missing) + "]",
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
                setattr(kernels[operation], attribute, value)
                with self.assertRaisesRegex(
                    RuntimeError,
                    rf"invalid transition kernel {operation}=\[{diagnostic}\]",
                ):
                    self._load_registry(kernels)

    def test_disabled_operation_cannot_be_registered(self) -> None:
        kernels = self._kernels()
        operation = "jit.consume"
        kernels[operation] = SimpleNamespace(
            operation=operation,
            handler=authority_contract.operation_spec(operation)["handler"],
            program_id=authority_contract.transition_program_id(operation),
            permits_empty_mutation=False,
        )
        with self.assertRaises(RuntimeError) as caught:
            self._load_registry(kernels)
        self.assertIn(
            "unexpected transition kernels=[jit.consume]",
            str(caught.exception),
        )
        self.assertIn(
            "disabled operations are plannable=[jit.consume]",
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
                      "counterPolicy": "strict-or-zero", "maxAssertionAgeSeconds": 60,
                  }}
        digest = "sha256:" + "1" * 64
        return {
            "route_id": "route:fixture", "method": "GET", "url_commitment": digest,
            "principal_id": "principal:fixture", "credential_id": "", "credential_version": 0,
            "policy_hash": digest, "request_digest": digest, "operation_digest": None,
            "canonical_request_digest": digest, "canonical_request_opaque_id": "canonical-value",
            "redacted_display_digest": digest, "redacted_display_opaque_id": "display-value",
            "pending_ttl_seconds": 60, "grant_ttl_seconds": 30, "grant_max_uses": 1,
            "approver_policy": policy,
            "approver_policy_digest": core.framed_digest(
                "serverware.jitApproverPolicy/v1", core.canonical_bytes(policy)
            ),
        }

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
        for field, value in (("requireWebAuthn", False), ("threshold", 0), ("threshold", True)):
            changed = {**arguments, "approver_policy": {**arguments["approver_policy"], field: value}}
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                core.TransitionKernelError, "^JIT approver policy is not closed$"
            ):
                kernel.transition(context(changed))
        changed = {**arguments, "approver_policy_digest": "sha256:" + "3" * 64}
        with self.assertRaisesRegex(core.TransitionKernelError, "^JIT approver policy digest differs$"):
            kernel.transition(context(changed))


if __name__ == "__main__":
    unittest.main()
