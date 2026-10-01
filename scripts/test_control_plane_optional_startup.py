#!/usr/bin/env python3
"""Real isolated import controls; no admitted custody owner is synthesized."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    ("control_plane_data_plane_audit", "SERVERWARE_MEASURED_AUDIT_CONFIG_FD"),
    ("control_plane_policy_canary_startup", "SERVERWARE_POLICY_CANARY_INTAKE_CONFIG_FD"),
)
PRELUDE = """
import importlib
import sys
sys.path.insert(0, sys.argv[1])
module = importlib.import_module('serverware.' + sys.argv[2])

def refuses(call):
    try:
        call()
    except Exception as error:
        return error
    raise AssertionError('closed startup operation unexpectedly succeeded')
"""
DISABLED = """
assert 'serverware.control_plane_custody_client' not in sys.modules
assert 'serverware.authority_service' not in sys.modules
module.initialize_from_environment()
assert module._state == 'disabled' and module._owner is None
assert module.selected() is False
assert module.configure_tls(None) is None
assert 'serverware.control_plane_custody_client' not in sys.modules
assert 'serverware.authority_service' not in sys.modules
refuses(module.initialize_from_environment)
assert module._state == 'disabled'
module.close()
assert module._state == 'closed'
refuses(module.selected)
"""
CONFIGURED_REFUSAL = """
error = refuses(module.initialize_from_environment)
assert isinstance(error, RuntimeError)
assert str(error) == 'authority service process mode is not closed'
assert module._state == 'poisoned' and module._owner is None
refuses(module.selected)
refuses(module.initialize_from_environment)
assert module._state == 'poisoned'
module.close()
assert module._state == 'closed'
"""


class OptionalStartupTests(unittest.TestCase):
    def isolated(self, module, code, *, channel="dev", settings=None):
        # Fresh real processes preserve each startup module's one-shot globals.
        # No fake process mode, custody object or successful validator is used.
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="serverware-optional-startup-") as directory:
            environment.update({"SERVERWARE_RELEASE_CHANNEL": channel,
                                "SERVERWARE_DATA_DIR": directory})
            environment.update(settings or {})
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", PRELUDE + code, str(ROOT), module],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_absent_development_selectors_do_not_import_authority_client(self):
        for module, _ in MODULES:
            with self.subTest(module=module):
                self.isolated(module, DISABLED)

    def test_empty_or_unknown_configuration_still_poison_admission(self):
        for module, selector in MODULES:
            for name in (selector, selector.removesuffix("CONFIG_FD") + "UNKNOWN"):
                with self.subTest(module=module, setting=name):
                    self.isolated(module, CONFIGURED_REFUSAL, settings={name: ""})

    def test_unconfigured_production_audit_still_requires_admission(self):
        self.isolated(MODULES[0][0], CONFIGURED_REFUSAL, channel="production")

    def test_absent_canary_selector_preserves_existing_optional_route(self):
        # This route's existing absence-only opt-out is not a production grant.
        self.isolated(MODULES[1][0], DISABLED, channel="production")


if __name__ == "__main__":
    unittest.main()
