"""Focused public-only sealed-import and strict tooling-identity controls."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_launcher as launcher


class AgentTrustImportIdentity(unittest.TestCase):
    def sealed_package(self):
        raw = (ROOT / "serverware_agent_trust/__init__.py").read_bytes()
        fd = launcher._seal_bytes("public-agent-trust-init", raw)
        self.addCleanup(os.close, fd)
        loader = launcher._SealedSourceLoader("serverware_agent_trust", fd,
            "source/serverware_agent_trust/__init__.py")
        spec = importlib.util.spec_from_loader("serverware_agent_trust", loader, is_package=True)
        module = importlib.util.module_from_spec(spec)
        # Actual measured SourceLoader, but no admission/signature/service claim.
        with mock.patch("pathlib.Path.resolve", side_effect=AssertionError("metadata lookup at import")), \
                mock.patch("importlib.metadata.packages_distributions", side_effect=AssertionError("distribution scan at import")):
            loader.exec_module(module)
        self.assertEqual(module._tooling_identity.cache_info().currsize, 0)
        return module

    def test_sealed_import_does_not_require_tooling_metadata(self):
        module = self.sealed_package()
        with mock.patch.object(module, "_project_identity", side_effect=RuntimeError("metadata unavailable")) as identity:
            with self.assertRaises(AttributeError):
                getattr(module, "unknown_identity")
            identity.assert_not_called()
            for name in ("DISTRIBUTION_NAME", "__version__", "ENROLLMENT_CLI_COMMAND"):
                with self.assertRaises(RuntimeError):
                    getattr(module, name)
            with self.assertRaises(RuntimeError):
                module.enrollment_tooling_contract()
            self.assertEqual(identity.call_count, 4)
            self.assertEqual(module._tooling_identity.cache_info().currsize, 0)

    def test_identity_exports_and_contract_cache_only_success(self):
        module = self.sealed_package()
        with mock.patch.object(module, "_project_identity", return_value=("actual-tool", "1.2.3")) as identity:
            self.assertEqual(module.DISTRIBUTION_NAME, "actual-tool")
            self.assertEqual(module.ENROLLMENT_CLI_COMMAND, "actual-tool")
            self.assertEqual(module.__version__, "1.2.3")
            contract = module.enrollment_tooling_contract()
            module.validate_enrollment_tooling({"tooling": contract})
            self.assertEqual(contract["expectedVersionOutput"], "actual-tool 1.2.3")
            with self.assertRaises(ValueError):
                module.validate_enrollment_tooling({"tooling": dict(contract, version="wrong")})
            identity.assert_called_once_with()

    def test_normal_source_identity_remains_actual_and_strict(self):
        import serverware_agent_trust as package
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        self.assertEqual(package._project_identity(), (project["name"], project["version"]))
        self.assertEqual((package.DISTRIBUTION_NAME, package.ENROLLMENT_CLI_COMMAND, package.__version__),
            (project["name"], project["name"], project["version"]))
        package.validate_enrollment_tooling({"tooling": package.enrollment_tooling_contract()})
        with self.assertRaises(RuntimeError):
            package._validate_project_identity("bad name", project["version"])


if __name__ == "__main__":
    unittest.main()
