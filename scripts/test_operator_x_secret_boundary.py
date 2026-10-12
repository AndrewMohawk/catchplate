#!/usr/bin/env python3
"""Actual generic-owner refusals with synthetic read/cache/flow observations.

Source-select unchanged production functions using the maintained App boundary
harness. No provider, application admission or successful lease is substituted;
the connected X suite owns encrypted adoption and final scoped lease evidence.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import test_github_app_secret_boundary as helpers

SECRET = '{"access_token":"synthetic-access-canary","refresh_token":"synthetic-refresh-canary"}'
PUBLIC = {"id": "synthetic-x-id", "credential_version": 3, "kind": "oauth2",
    "metadata": {"oauth": True, "provider_id": "x"}}
MARKERS = (None, False, 0, "malformed", [], {}, {"schema": "serverware.operatorXAccountBinding/v1"})


def marked(marker):
    return {**deepcopy(PUBLIC), "metadata": {**PUBLIC["metadata"], "operator_x_account": marker}}


def injection(public, private):
    def read(_identifier, include_secret=False):
        return deepcopy(private if include_secret else public)
    return helpers.functions("serverware/policies.py", {"inject_credential", "_secret_for_injection"}, {
        "db": SimpleNamespace(get_credential=Mock(side_effect=read)),
        "github_app_boundary": helpers.boundary, "json": json,
        "SECRET_FIELD_PATH_RE": re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")})


class SecretBoundaryTests(unittest.TestCase):
    def test_every_marked_public_row_refuses_before_decrypt_claim_or_cache(self):
        for marker in MARKERS:
            for controlled in (False, True):
                state = helpers.runtime(marked(marker), {**marked(marker), "secret": SECRET})
                state["_credential_cache"][(PUBLIC["id"], 3)] = (time.monotonic() + 30, {**PUBLIC, "secret": SECRET})
                state["_credential_cache"][("other", 1)] = (time.monotonic() + 30, deepcopy(PUBLIC))
                options = {"request_authority": {}, "expected_release_identity": object()} if controlled else {}
                self.assertIsNone(state["get_credential"](PUBLIC["id"], **options))
                self.assertIsNone(state["get_control_plane_credential"](PUBLIC["id"]))
                self.assertEqual(set(state["_credential_cache"]), {("other", 1)})
                self.assertFalse(any(call.kwargs.get("include_secret") for call in state["db"].get_credential.call_args_list))
                state["_claim_release_controlled_credential"].assert_not_called()
                state["start_runtime_workers"].assert_not_called()

    def test_poisoned_cache_and_changed_private_marker_never_project(self):
        for marker in MARKERS:
            private = {**marked(marker), "secret": SECRET}
            state = helpers.runtime(PUBLIC, private)
            state["_credential_cache"][(PUBLIC["id"], 3)] = (time.monotonic() + 30, private)
            self.assertIsNone(state["get_credential"](PUBLIC["id"]))
            self.assertEqual(state["_credential_cache"], {})
            self.assertIsNone(state["get_control_plane_credential"](PUBLIC["id"]))
            self.assertIsNone(state["_project_credential_for_data_plane"](private))
            state = helpers.runtime(PUBLIC, private)
            self.assertIsNone(state["get_credential"](PUBLIC["id"]))
            self.assertEqual(state["_credential_cache"], {})

    def test_legacy_injection_refuses_before_secret_open_or_header_change(self):
        route = {"credential_id": PUBLIC["id"], "injection": {"type": "bearer", "field": "refresh_token"}}
        for marker in MARKERS:
            state = injection(marked(marker), {**marked(marker), "secret": SECRET})
            flow = SimpleNamespace(request=SimpleNamespace(headers={"Authorization": "unchanged-public-dummy"}))
            self.assertEqual(state["inject_credential"](flow, route), "X accounts require the dedicated lease owner")
            self.assertEqual(flow.request.headers, {"Authorization": "unchanged-public-dummy"})
            state["db"].get_credential.assert_called_once_with(PUBLIC["id"], include_secret=False)
            state = injection(PUBLIC, {**marked(marker), "secret": SECRET})
            self.assertEqual(state["inject_credential"](flow, route), "X accounts require the dedicated lease owner")
            self.assertEqual(flow.request.headers, {"Authorization": "unchanged-public-dummy"})

    def test_unmarked_google_static_and_legacy_x_behavior_is_unchanged(self):
        for provider in ("google", "x"):
            public = {**PUBLIC, "metadata": {"oauth": True, "provider_id": provider}}
            private = {**public, "secret": SECRET}
            state = helpers.runtime(public, private)
            self.assertEqual(state["get_control_plane_credential"](PUBLIC["id"]), private)
            projected = state["get_credential"](PUBLIC["id"])
            self.assertEqual(json.loads(projected["secret"]), {"access_token": "synthetic-access-canary"})
            self.assertNotIn("synthetic-refresh-canary", projected["secret"])
        public = {**PUBLIC, "kind": "bearer", "metadata": {}}
        private = {**public, "secret": "synthetic-static"}
        state = helpers.runtime(public, private)
        self.assertEqual(state["get_credential"](PUBLIC["id"]), private)
        flow = SimpleNamespace(request=SimpleNamespace(headers={}))
        state = injection(public, private)
        state["inject_credential"](flow, {"credential_id": PUBLIC["id"], "injection": {"type": "bearer"}})
        self.assertEqual(flow.request.headers, {"Authorization": "Bearer synthetic-static"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
