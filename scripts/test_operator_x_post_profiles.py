"""Pure independent vector controls; no SDK, provider, proxy or network calls."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import operator_x_post_profiles as profiles


class XPostProfileTests(unittest.TestCase):
    def test_literal_sdk_bodies_preserve_identical_text_without_reserialization(self):
        for case in profiles.CASES:
            for client in profiles.CLIENTS:
                body = profiles.post_body(client, case)
                self.assertIs(type(body), bytes)
                self.assertEqual(json.loads(body), {"text": profiles.post_text(case)})
                self.assertLess(len(body), 32768)
        self.assertEqual(len(set(profiles.post_body(client) for client in profiles.CLIENTS)), 3)
        self.assertIn(b"\\u00e9", profiles.post_body("python"))
        self.assertIn(b"\\u0026 \\u003cverified\\u003e", profiles.post_body("go"))
        self.assertIn(b"caf\xc3\xa9 & <verified>", profiles.post_body("node"))
        self.assertTrue(profiles.TEXT.endswith("\n"))

    def test_headers_bind_each_literal_body_without_credentials_or_discarded_fields(self):
        for case in profiles.CASES:
            for client in profiles.CLIENTS:
                value = profiles.provider_headers(client, case)
                self.assertEqual(value, profiles.canonical_headers(client, case))
                self.assertEqual(value["content-length"], str(len(profiles.post_body(client, case))))
                self.assertEqual(value["host"], "api.x.com")
                self.assertEqual(value["content-type"], "application/json")
                self.assertEqual(value["user-agent"], profiles.USER_AGENTS[client])
                self.assertEqual(value["accept"], profiles.MEDIA[client])
                self.assertFalse({"authorization", "proxy-authorization", "connection", "accept-encoding"} & value.keys())
                value["host"] = "mutated.invalid"
                self.assertEqual(profiles.provider_headers(client, case)["host"], "api.x.com")

    def test_closed_client_phase_and_result_rosters(self):
        self.assertEqual(len(profiles.PHASES), len(set(profiles.PHASES)))
        self.assertEqual(len(profiles.PHASES), 19)
        self.assertEqual(sum(phase.endswith((":first", ":refreshed")) for phase in profiles.PHASES), 6)
        self.assertEqual([phase for phase in profiles.PHASES if phase.endswith(":reflected")], ["node:reflected"])
        for phase in profiles.PHASES:
            self.assertEqual(":".join(profiles.split_phase(phase)), phase)
        for client in ("NODE", "probe", "", None, []):
            with self.assertRaises(ValueError):
                profiles.post_body(client)
        for case in ("reflected", "", None, []):
            with self.assertRaises(ValueError):
                profiles.post_body("node", case)
        for phase in ("node:retry", "go:reflected", None, []):
            with self.assertRaises(ValueError):
                profiles.split_phase(phase)
        for identifier in (1, True, "", "-1", "1" * 21, "١", "1\n"):
            with self.assertRaises(ValueError):
                profiles.expected_output(identifier)
        self.assertEqual(profiles.expected_output("9000000000000000001"), {"status": 201, "id": "9000000000000000001"})

    def test_actual_entrypoints_and_literal_dependency_pins_are_declared(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(len(profiles.SOURCE_FILES), len(set(profiles.SOURCE_FILES)))
        self.assertTrue(all((root / name).is_file() for name in profiles.SOURCE_FILES))
        package = json.loads((root / "examples/x-post-node/package.json").read_bytes())
        self.assertEqual(package["dependencies"], profiles.NODE_DEPENDENCIES)
        requirements = (root / "examples/x-post-python/requirements.txt").read_text().splitlines()
        self.assertEqual(dict(line.split("==") for line in requirements), profiles.PYTHON_DEPENDENCIES)
        self.assertEqual(profiles.COMMANDS["python"][-1], "/app/examples/x-post-python/post.py")
        self.assertEqual(profiles.COMMANDS["go"], (profiles.GO_TARGET,))


if __name__ == "__main__":
    unittest.main()
