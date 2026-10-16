"""Focused pure/in-memory age fixture checks; not SDK/Rust/TLS acceptance."""
from contextlib import contextmanager
from copy import deepcopy
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_operator_gmail_sdk_age as check
from scripts import operator_gmail_sdk_age_fixture as fixture
from scripts import test_operator_gmail_sdk_fixture as receiver
from scripts import test_operator_gmail_sdk_recipe as old_recipe
from scripts import prepare_operator_gmail_sdk_fixture as recipe


@contextmanager
def captured():
    with receiver.clock(0):
        provider = fixture.GmailAgeFixture(Path("/synthetic-unopened"))
    provider.replies = []
    with patch.object(fixture.sdk.base.GoogleFixture, "_send_json",
            lambda self, handler, status, payload: self.replies.append((status, deepcopy(payload)))), \
         patch.object(fixture.sdk.base.GoogleFixture, "_send_redirect",
            lambda self, handler, location: self.replies.append((302, location))):
        yield provider


def request(spec, after, token):
    path, query = fixture.target(spec, after)
    value = receiver.request(path + "?" + query, token=token)
    for name in receiver.PUBLIC_HEADERS:
        if name != "host":
            del value.headers[name]
    headers = fixture.PROBE_HEADERS if spec["kind"] == "probe" else fixture.CLIENT_HEADERS
    for name, item in headers.items():
        if name != "host":
            value.headers[name] = item
    value.wfile, value.response_headers = io.BytesIO(), {}
    value.send_response = lambda status: setattr(value, "status", status)
    value.send_header = lambda name, item: value.response_headers.update({name: item})
    value.end_headers = lambda: None
    return value


def document():
    with captured() as provider, receiver.clock(0):
        tokens = receiver.authorize(provider)
        assert receiver.send(provider, receiver.request("/v1/userinfo", host="openidconnect.googleapis.com",
            token=tokens["access_token"]))[0] == 200
        for index, spec in enumerate(provider.plan):
            seconds = 1 if spec["generation"] == 1 else 91
            with receiver.clock(seconds):
                if index == 10:
                    status, tokens = receiver.refresh(provider, tokens)
                    assert status == 200
                # Deliberately identical queries across negative runs; no delay
                # manufactured to make canonical digests unique.
                after = (provider.anchor + seconds * 1000 - fixture.DAY_MS + 999) // 1000
                handler = request(spec, after, tokens["access_token"])
                provider.note_arrival(handler); provider._handle_get(handler)
                if index == 5:
                    body = fixture.sdk._json_bytes(spec["body"])
                    assert handler.status == 200
                    assert handler.response_headers["Transfer-Encoding"] == "chunked"
                    assert "Content-Length" not in handler.response_headers
                    assert handler.wfile.getvalue() == format(len(body), "x").encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
                else:
                    assert provider.replies[-1] == (200, spec["body"])
        with receiver.clock(91):
            return provider.observations()


SCOPES = {name: ("principal-" + name, "route-" + name, "sha256:" + "a" * 64)
    for name in ("unrestricted", "recent")}
CREDENTIAL = "synthetic-credential"


def audit_rows(value):
    rows = []
    def append(kind, event):
        rows.append({"id": "event-" + str(len(rows)), "event_hash": check.sdk.digest(str(len(rows)).encode()),
            "prev_event_hash": rows[-1]["event_hash"] if rows else None,
            "event_type": kind, "event": event})
    for row in value["gmailAge"]["attempts"]:
        if row["kind"] == "probe":
            continue
        scope = SCOPES["unrestricted" if row["phase"] == "unrestricted" else "recent"]
        request_digest, operation_digest = check.canonical(row, scope, CREDENTIAL)
        common = dict(zip(("principal_id", "route_id", "policy_hash"), scope),
            credential_ref=CREDENTIAL, credential_version=row["tokenGeneration"], method="GET",
            request_digest=request_digest, operation_digest=operation_digest, attempt_id="attempt-" + str(row["ordinal"]))
        append(check.sdk.START, {**common, "outcome": "release_started"})
        blocked = row["phase"] in check.ERRORS and (row["phase"].endswith("-list") or row["kind"] == "get")
        validation = {"ok": False, "error": check.ERRORS[row["phase"]]} if blocked else {
            "ok": True, "age_policy": "recent_internal_date_v1", "max_age_days": 1,
            "metadata_probes": int(row["kind"] == "list"), "body_bytes_preserved": True}
        append("data_plane.response.blocked" if blocked else check.sdk.RELEASE, {**common,
            "outcome": "blocked" if blocked else "released", "upstream_status": 200, "response_validation": validation,
            "response_body_sha256": row["responseBodySha256"], "response_body_bytes": row["responseBodyBytes"]})
    append("credential.oauth_refreshed", {"credential_id": CREDENTIAL, "previous_credential_version": 1,
        "credential_version": 2, "refresh_token_rotated": True})
    return rows


def audit_fake(rows):
    return SimpleNamespace(settled_audit=lambda: list(reversed(rows)),
        control_json=lambda *args, **kwargs: {"ok": True, "complete": True})


class GmailAgeTests(unittest.TestCase):
    def test_closed_plan_and_real_in_memory_oauth_generations(self):
        value = document()
        attempts = value["gmailAge"]["attempts"]
        self.assertEqual(len(attempts), 31)
        self.assertEqual(sum(row["kind"] == "probe" for row in attempts), 11)
        fake = SimpleNamespace(upstream=None, upstream_ca=None, json_request=lambda *a, **k: (200, value))
        self.assertEqual(check.observe(fake, 31), value)
        self.assertEqual([row["tokenGeneration"] for row in attempts], [1] * 10 + [2] * 21)
        self.assertEqual([row["responseFraming"] for row in attempts].count("chunked"), 1)
        self.assertEqual(value["counts"]["google"]["refresh_exchanges"], 1)

    def test_exact_probe_query_and_no_client_query_rewriting(self):
        specs = fixture.plan(receiver.EPOCH_MS)
        for row in specs:
            if row["kind"] == "probe":
                self.assertEqual(fixture.target(row)[1], "fields=id%2CinternalDate&format=metadata")
        with captured() as provider, receiver.clock(0):
            tokens = receiver.authorize(provider)
            handler = request(provider.plan[0], None, tokens["access_token"])
            handler.path += "&q=after%3A1"
            self.assertEqual(receiver.send(provider, handler)[0], 400)
            observed = provider.observations()["gmailAge"]["attempts"][0]
            self.assertIsNone(observed["path"])
            self.assertFalse(observed["authorized"])

    def test_repeated_digests_use_unique_attempt_ids_and_durable_order(self):
        value = document(); rows = audit_rows(value)
        starts = [row["event"] for row in rows if row["event_type"] == check.sdk.START]
        self.assertLess(len({event["request_digest"] for event in starts}), len(starts))
        result = check.audit(audit_fake(rows), value, SCOPES, CREDENTIAL)
        self.assertEqual((result["released"], result["blocked"], result["metadataProbes"]), (14, 6, 11))
        for mutate in (lambda r: r[3]["event"].update(attempt_id=r[1]["event"]["attempt_id"]),
                lambda r: r[3]["event"].update(policy_hash="sha256:" + "b" * 64),
                lambda r: r[3]["event"].update(credential_version=9),
                lambda r: r[3]["event"].update(response_body_bytes=0),
                lambda r: r[9]["event"]["response_validation"].update(metadata_probes=2),
                lambda r: r[25]["event"]["response_validation"].update(error="wrong_error"),
                lambda r: r[3].update(prev_event_hash=r[1]["event_hash"])):
            bad = deepcopy(rows); mutate(bad)
            with self.assertRaises(check.sdk.CheckFailure):
                check.audit(audit_fake(bad), value, SCOPES, CREDENTIAL)

    def test_provider_oracle_rejects_retry_generation_query_or_byte_drift(self):
        value = document()
        for mutate in (lambda v: v["counts"]["google"].update(token_requests=3),
                lambda v: v["gmailAge"]["attempts"][5].update(tokenGeneration=2),
                lambda v: v["gmailAge"]["attempts"][7].update(rawQuery="changed"),
                lambda v: v["gmailAge"]["attempts"][5].update(responseFraming="content-length"),
                lambda v: v["gmailAge"]["attempts"][0].update(responseBodySha256="sha256:" + "0" * 64)):
            bad = deepcopy(value); mutate(bad)
            fake = SimpleNamespace(upstream=None, upstream_ca=None, json_request=lambda *a, **k: (200, bad))
            with self.assertRaises(check.sdk.CheckFailure): check.observe(fake, 31)

    def test_opt_in_changes_only_two_commands_not_lifecycle_or_mounts(self):
        kwargs = {"expected_binary_sha256": "a" * 64, "expected_go_sha256": None, "sdk_pair": True,
            "node": Path("/synthetic/node"), "node_modules": Path("/synthetic/node_modules"),
            "python_runtime": Path("/synthetic/python"), "python_packages": Path("/synthetic/site-packages"),
            "expected_dependencies_sha256": "b" * 64}
        args = (*old_recipe.ARGS[:4], None)
        baseline = recipe.build(*args, **kwargs)
        selected = recipe.build(*args, **kwargs, age_profile=True)
        for name in ("provider", "check"):
            self.assertEqual(selected["services"][name]["command"].pop(), "--age-profile")
        self.assertEqual(selected, baseline)
        with self.assertRaises(ValueError): recipe.build(*old_recipe.ARGS, **old_recipe.PINS, age_profile=True)

    def test_configuration_paths_use_actual_private_writable_recipe_tmpfs(self):
        service = recipe.build(*old_recipe.ARGS, **old_recipe.PINS)["services"]["check"]
        self.assertTrue(service["read_only"])
        self.assertEqual(service["user"], "10001:10001")
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700", service["tmpfs"])
        self.assertFalse(any(item["target"] == "/client-work" for item in service["volumes"]))
        app = {"id": "00000000-0000-4000-8000-000000000001", "token_expires_at_epoch_ms": 2000000000000}
        token = "a" * 43
        environment = check.sdk.client_environment(app["id"], token, "first")
        for name in ("unrestricted", "recent"):
            path = Path("/tmp/gmail-age-" + name + ".json")
            # Stop at each actual filesystem/process boundary; this is a
            # path/recipe regression, not a file write or SDK execution.
            with patch.object(check.os, "open", side_effect=RuntimeError("captured open")) as opened:
                with self.assertRaisesRegex(RuntimeError, "captured open"):
                    check.configuration(app, token, {"id": app["id"]}, name)
            opened.assert_called_once_with(path,
                check.os.O_WRONLY | check.os.O_CREAT | check.os.O_EXCL | check.os.O_NOFOLLOW, 0o600)
            with patch.object(check.sdk.subprocess, "Popen", side_effect=RuntimeError("captured process")) as process:
                with self.assertRaisesRegex(RuntimeError, "captured process"):
                    check.sdk.run_example(environment, 5, command=check.sdk.profiles.COMMANDS["python"], config_file=path)
            self.assertEqual(process.call_args.args[0], (*check.sdk.profiles.COMMANDS["python"], "--config", str(path)))
        with self.assertRaises(check.sdk.CheckFailure):
            check.sdk.run_example(environment, 5, command=check.sdk.profiles.COMMANDS["python"],
                config_file=Path("/client-work/gmail-age-recent.json"))


if __name__ == "__main__":
    unittest.main()
