#!/usr/bin/env python3
"""Facade/guard controls, not admitted successor execution or owner evidence."""
from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, sentinel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OPERATION = "oidc.session.activation-delivery.consume"
HANDLER = "consume_oidc_session_activation_delivery"
ARGUMENTS = {
    "delivery_id": "delivery-test",
    "session_id": "session-test",
    "user_id": "user:test",
    "credential_id": "Y3JlZGVudGlhbA",
    "credential_record_id": "credential-test",
    "challenge_id": "challenge-test",
    "old_token_digest": "sha256:" + "1" * 64,
    "new_token_digest": "sha256:" + "2" * 64,
    "assertion_digest": "sha256:" + "3" * 64,
}


class DeliveryFacadeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="serverware-delivery-facade-")
        cls.addClassCleanup(temporary.cleanup)
        environment = patch.dict(os.environ, {
            "SERVERWARE_DATA_DIR": temporary.name,
            "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
            "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
            "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
            "SERVERWARE_RELEASE_CHANNEL": "dev",
            "SERVERWARE_PROCESS_MODE": "",
        })
        environment.start()
        cls.addClassCleanup(environment.stop)
        from serverware import db
        from serverware import authority_transition_registry as registry
        cls.db = db
        cls.registry = registry

    def test_actual_facade_import_installs_exact_closed_binding(self):
        handler = getattr(self.db, HANDLER)
        self.assertEqual(self.db.authority_contract.HANDLER_TO_OPERATION[HANDLER], OPERATION)
        registered_name, original, signature = self.db._POLICY_AUTHORITY_CONTROLLED_WRITER_HANDLERS[OPERATION]
        self.assertEqual(registered_name, HANDLER)
        self.assertIs(handler.__wrapped__, original)
        self.assertEqual(tuple(signature.parameters), tuple(ARGUMENTS))
        self.assertTrue(all(item.kind is inspect.Parameter.KEYWORD_ONLY
                            and item.default is inspect.Parameter.empty
                            for item in signature.parameters.values()))
        self.assertNotIn(OPERATION, self.registry.LEGACY_PLANNABLE_OPERATIONS)

    def test_unwrapped_facade_dispatches_only_original_semantic_locators(self):
        # A transport recorder, not a validator, execution result or fake owner.
        with patch.object(self.db, "dispatch_policy_authority_operation",
                          return_value=sentinel.transport_result) as dispatch:
            result = getattr(self.db, HANDLER).__wrapped__(**ARGUMENTS)
        self.assertIs(result, sentinel.transport_result)
        dispatch.assert_called_once_with(OPERATION, {
            "schema": "serverware.policyAuthorityControlledWriterInput/v1",
            "handler": HANDLER,
            "operationManifestDigest": self.db.authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": ARGUMENTS,
        })

    def test_invalid_or_caller_authoritative_arguments_never_dispatch(self):
        original = getattr(self.db, HANDLER).__wrapped__
        with patch.object(self.db, "dispatch_policy_authority_operation") as dispatch:
            for field, value in (("delivery_id", ""), ("user_id", " padded"),
                                 ("assertion_digest", "not-a-digest"),
                                 ("new_token_digest", ARGUMENTS["old_token_digest"]),
                                 ("credential_record_id", None)):
                with self.subTest(field=field), self.assertRaises(self.db.MetadataStoreError):
                    original(**{**ARGUMENTS, field: value})
            for name in ("businessIntent", "_connection", "authority_verifier_response"):
                with self.subTest(injected=name), self.assertRaises(TypeError):
                    original(**ARGUMENTS, **{name: {}})
            dispatch.assert_not_called()

    def test_legacy_wrapper_and_privileged_unwrapped_call_stay_closed(self):
        handler = getattr(self.db, HANDLER)
        with self.assertRaisesRegex(self.db.MetadataStoreError, "no exact typed transition program"):
            handler(**ARGUMENTS)
        with patch.dict(os.environ, {
            "SERVERWARE_PROCESS_MODE": self.db._POLICY_AUTHORITY_EXECUTOR_PROCESS_MODE,
        }), self.assertRaisesRegex(self.db.MetadataStoreError, "cannot run in a privileged process"):
            handler.__wrapped__(**ARGUMENTS)


if __name__ == "__main__":
    unittest.main()
