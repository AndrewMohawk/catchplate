#!/usr/bin/env python3
"""Exercise the registry guard with synthetic metadata, never authority execution.

These tests do not assert that the real operation implementation is complete.
The source-root control-plane startup test remains the integration gate for it.
"""
from __future__ import annotations

import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
