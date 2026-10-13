"""Finite offline tests: real local files, synthetic HTTP, no provider requests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import managed_client as client


class Crash(BaseException):
    pass


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="serverware-managed-client-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "private"
        self.token_file = Path(self.temporary.name) / "bootstrap-token"
        self.token_file.write_text("old-private-proxy-token\n")
        self.token_file.chmod(0o600)
        self.now = 1_800_000_000_000
        self.calls = []
        self.committed = None
        self.manager = client.ManagedClient(self.directory, transport=self.http, clock_ms=lambda: self.now)
        public = self.manager.initialize()
        self.setup = {"schema": client.SETUP_SCHEMA,
            "application_id": "11111111-1111-4111-8111-111111111111",
            "enrollment_id": "22222222-2222-4222-8222-222222222222",
            "audience": "https://proxy.example.test/v1/workload/renew",
            "public_key_fingerprint": client.sha256(bytes.fromhex(public)),
            "token_generation": 1, "token_expires_at_epoch_ms": self.now + 3_600_000,
            "enrollment_expires_at_epoch_ms": self.now + 86_400_000,
            "token_lifetime_seconds": 3600, "overlap_seconds": 300}
        self.manager.configure(self.setup, self.token_file)
        self.addCleanup(lambda: self.manager.close())

    def response(self, request):
        receipt = {"operation_id": request["operation_id"], "request_sha256": client.sha256(client.signing_bytes(request)),
            "application_id": request["application_id"], "enrollment_id": request["enrollment_id"],
            "previous_generation": request["expected_token_generation"], "token_generation": request["expected_token_generation"] + 1,
            "token_sha256": request["token_sha256"], "issued_at_epoch_ms": request["issued_at_epoch_ms"],
            "rotated_at_epoch_ms": self.now, "expires_at_epoch_ms": request["token_expires_at_epoch_ms"],
            "previous_accept_until_epoch_ms": (min(self.manager._state["current"]["expires_at_epoch_ms"], self.now + 300_000)
                if self.manager._state["current"]["expires_at_epoch_ms"] > self.now else None)}
        enrollment = {"version": 1, "enrollment_id": self.setup["enrollment_id"],
            "expires_at_epoch_ms": self.setup["enrollment_expires_at_epoch_ms"],
            "public_key_fingerprint": self.setup["public_key_fingerprint"],
            "token_lifetime_seconds": 3600, "overlap_seconds": 300,
            "audience": self.setup["audience"], "status": "active"}
        return {"operation": receipt, "revision": 2,
            "application": {"id": self.setup["application_id"], "name": "Synthetic reader",
                "created_at": "2027-01-01T00:00:00+00:00", "status": "active", "version": 2,
                "principal_id": "agent:operator-demo:" + self.setup["application_id"],
                "proxy_authentication": "basic_and_bearer_v1", "token_generation": receipt["token_generation"],
                "token_expires_at_epoch_ms": receipt["expires_at_epoch_ms"], "token_status": "valid",
                "access_status": "active", "active_rule_count": 1, "client_renewal": enrollment},
            "policy": {"policy_hash": "sha256:" + "a" * 64, "sequence": 2,
                "loaded_policy_hash": "sha256:" + "a" * 64, "activation": "active"}}

    def http(self, audience, raw):
        # The actual durable journal must exist before the first network byte.
        disk = json.loads((self.directory / "state.json").read_bytes())
        self.assertEqual(disk["pending"]["request_original"].encode("ascii"), raw)
        self.assertEqual(audience, self.setup["audience"])
        self.assertNotIn(disk["pending"]["candidate_token"].encode(), raw)
        self.assertNotIn(disk["current"]["token"].encode(), raw)
        self.calls.append(raw)
        if self.committed is None:
            self.committed = self.response(json.loads(raw))
        return client.canonical(self.committed)

    def reopen(self, transport=None):
        self.manager.close()
        self.manager = client.ManagedClient(self.directory, transport=transport or self.http, clock_ms=lambda: self.now)

    def leave_unknown(self):
        def lost(audience, raw):
            self.http(audience, raw)
            raise TimeoutError("not exposed")
        self.manager._transport = lost
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.renew()

    def test_key_initialization_is_stable_and_public_only(self):
        public = self.manager.initialize()
        self.assertEqual(len(public), 64)
        self.assertNotEqual(public, (self.directory / "ed25519.key").read_bytes().hex())
        self.assertEqual(public, self.manager.initialize())
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for path in self.directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_one_process_owner(self):
        with self.assertRaises(client.ClientError):
            client.ManagedClient(self.directory)

    def test_one_thread_owner(self):
        failures = []
        def attempt():
            for operation in (self.manager.renew, self.manager.close):
                try:
                    operation()
                except client.ClientError:
                    failures.append(True)
        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [True, True])
        self.assertEqual(self.calls, [])

    def test_symlink_directory_refused(self):
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(client.ClientError):
            client.ManagedClient(alias)

    def test_insecure_directory_refused_without_chmod(self):
        self.manager.close()
        self.directory.chmod(0o755)
        with self.assertRaises(client.ClientError):
            client.ManagedClient(self.directory)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)

    def test_insecure_state_and_link_refused(self):
        self.manager.close()
        state = self.directory / "state.json"
        state.chmod(0o644)
        with self.assertRaises(client.ClientError):
            client.ManagedClient(self.directory)
        state.chmod(0o600)
        os.link(state, self.directory / "state-alias")
        with self.assertRaises(client.ClientError):
            client.ManagedClient(self.directory)

    def test_bootstrap_token_must_be_private_file(self):
        self.token_file.chmod(0o644)
        with self.assertRaises(client.ClientError):
            client._private_file(self.token_file, 8193)

    def test_valid_response_installs_candidate_after_durable_journal(self):
        lease = self.manager.renew()
        self.assertEqual(lease.generation, 2)
        self.assertEqual(lease.pool_refresh_by_epoch_ms, self.now + 300_000)
        self.assertNotIn(lease.token, repr(lease))
        self.assertIsNone(json.loads((self.directory / "state.json").read_bytes())["pending"])
        self.reopen()
        self.assertEqual(self.manager.lease(), lease)
        self.assertEqual(len(self.calls), 1)

    def test_lost_response_replays_exact_bytes_after_restart_and_expired_request(self):
        self.leave_unknown()
        journal = (self.directory / "state.json").read_bytes()
        candidate = json.loads(journal)["pending"]["candidate_token"]
        self.now += 120_000  # Proof window passed; only exact committed replay is valid.
        self.reopen()
        lease = self.manager.renew()
        self.assertEqual(lease.token, candidate)
        self.assertEqual(self.calls[0], self.calls[1])
        self.assertEqual(self.manager._state["last_receipt"], self.committed["operation"])

    def test_crash_after_dispatch_recovers_same_operation(self):
        def crash(audience, raw):
            self.http(audience, raw)
            raise Crash()
        self.manager._transport = crash
        with self.assertRaises(Crash):
            self.manager.renew()
        self.reopen()
        self.manager.renew()
        self.assertEqual(self.calls[0], self.calls[1])

    def test_crash_before_candidate_install_keeps_pending(self):
        original_save = self.manager._save
        def save(value):
            if value["pending"] is None:
                raise Crash()
            original_save(value)
        self.manager._save = save
        with self.assertRaises(Crash):
            self.manager.renew()
        self.reopen()
        self.manager.renew()
        self.assertEqual(self.calls[0], self.calls[1])

    def test_failed_journal_write_never_dispatches(self):
        with patch.object(self.manager, "_write", side_effect=OSError("private data omitted")):
            with self.assertRaises(client.ClientError):
                self.manager.renew()
        self.assertEqual(self.calls, [])
        with self.assertRaises(client.ClientError):
            self.manager.lease()

    def test_fsync_failure_after_replace_requires_restart(self):
        original_fsync = os.fsync
        def fsync(fd):
            if fd == self.manager._directory_fd:
                raise OSError("directory persistence unknown")
            original_fsync(fd)
        with patch.object(client.os, "fsync", side_effect=fsync):
            with self.assertRaises(client.ClientError):
                self.manager.renew()
        self.assertEqual(self.calls, [])
        pending = json.loads((self.directory / "state.json").read_bytes())["pending"]["request_original"]
        self.reopen()
        self.manager.renew()
        self.assertEqual(self.calls[0], pending.encode())

    def test_policy_pending_keeps_candidate_uninstalled(self):
        self.leave_unknown()
        self.committed["policy"]["activation"] = "pending"
        self.committed["application"]["access_status"] = "unassigned"
        self.committed["application"]["active_rule_count"] = 0
        self.manager._transport = self.http
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.renew()
        self.assertEqual(self.manager.status()["token_generation"], 1)
        self.assertTrue(self.manager.status()["recovery_pending"])
        self.committed["policy"]["activation"] = "active"
        self.committed["application"]["access_status"] = "active"
        self.committed["application"]["active_rule_count"] = 1
        self.manager.renew()
        self.assertEqual(len(set(self.calls)), 1)

    def test_unknown_outcome_old_token_stops_before_overlap(self):
        self.leave_unknown()
        self.now += 294_999
        self.assertEqual(self.manager.lease().generation, 1)
        self.now += 1
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.lease()
        self.assertEqual(len(set(self.calls)), 1)

    def test_expired_candidate_is_never_installed(self):
        self.leave_unknown()
        self.now += 3_600_000
        self.reopen()
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.renew()
        self.assertEqual(self.manager.status()["token_generation"], 1)

    def test_no_renewal_can_extend_enrollment(self):
        self.setup["enrollment_expires_at_epoch_ms"] = self.now + 120_000
        self.manager._state["setup"]["enrollment_expires_at_epoch_ms"] = self.now + 120_000
        self.manager._state["current"]["expires_at_epoch_ms"] = self.now + 120_000
        self.manager._state["current"]["pool_refresh_by_epoch_ms"] = self.now + 120_000
        lease = self.manager.lease()
        self.assertEqual(lease.generation, 2)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.manager.lease(), lease)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(lease.expires_at_epoch_ms, self.now + 120_000)
        self.now += 120_000
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.lease()

    def test_first_lease_renews_a_long_manual_token_even_when_clipped_to_grant(self):
        self.manager._state["current"]["expires_at_epoch_ms"] = self.setup["enrollment_expires_at_epoch_ms"]
        self.manager._state["current"]["pool_refresh_by_epoch_ms"] = self.setup["enrollment_expires_at_epoch_ms"]
        lease = self.manager.lease()
        self.assertEqual(lease.generation, 2)
        self.assertEqual(lease.expires_at_epoch_ms, self.now + 3_600_000)
        self.assertEqual(len(self.calls), 1)

    def test_clock_rollback_refused(self):
        self.now -= 1
        with self.assertRaises(client.ClientError):
            self.manager.lease()
        with self.assertRaises(client.ClientError):
            self.reopen()

    def test_cannot_overwrite_existing_configuration_or_pending(self):
        self.leave_unknown()
        before = (self.directory / "state.json").read_bytes()
        with self.assertRaises(client.ClientError):
            self.manager.configure(self.setup, self.token_file)
        self.assertEqual(before, (self.directory / "state.json").read_bytes())

    def test_expired_bootstrap_token_renews_without_previous_slot_and_restarts(self):
        self.manager.close()
        self.directory = Path(self.temporary.name) / "expired-private"
        self.manager = client.ManagedClient(self.directory, transport=self.http, clock_ms=lambda: self.now)
        public = self.manager.initialize()
        self.setup = {**self.setup, "public_key_fingerprint": client.sha256(bytes.fromhex(public)),
            "token_expires_at_epoch_ms": self.now - 1}
        self.manager.configure(self.setup, self.token_file)
        lease = self.manager.lease()
        self.assertEqual(lease.generation, 2)
        self.assertEqual(lease.pool_refresh_by_epoch_ms, self.now)
        self.assertIsNone(self.manager._state["last_receipt"]["previous_accept_until_epoch_ms"])
        self.reopen()
        self.assertEqual(self.manager.lease(), lease)
        self.committed = None
        self.assertEqual(self.manager.renew().generation, 3)

    def test_null_previous_cutoff_is_refused_when_previous_token_was_live(self):
        self.leave_unknown()
        self.committed["operation"]["previous_accept_until_epoch_ms"] = None
        self.manager._transport = self.http
        with self.assertRaises(client.RenewalUnavailable):
            self.manager.renew()

    def test_key_fsync_failure_poisoned_until_restart(self):
        directory = Path(self.temporary.name) / "new-private"
        with client.ManagedClient(directory) as manager:
            original_fsync = os.fsync
            def fsync(fd):
                if fd == manager._directory_fd:
                    raise OSError("directory persistence unknown")
                original_fsync(fd)
            with patch.object(client.os, "fsync", side_effect=fsync):
                with self.assertRaises(client.ClientError):
                    manager.initialize()
            with self.assertRaises(client.ClientError):
                manager.initialize()
        persisted_key = (directory / "ed25519.key").read_bytes()
        with client.ManagedClient(directory) as manager:
            self.assertEqual(len(manager.initialize()), 64)
        self.assertEqual((directory / "ed25519.key").read_bytes(), persisted_key)

    def test_pending_tampering_refused_on_restart(self):
        self.leave_unknown()
        state = self.manager._state
        state["pending"]["candidate_token"] = "different"
        self.manager._write("state.json", client.canonical(state))
        with self.assertRaises(client.ClientError):
            self.reopen()

    def test_response_binding_rejections_preserve_journal(self):
        self.leave_unknown()
        original = copy.deepcopy(self.committed)
        mutations = [
            ("operation", "token_sha256", "sha256:" + "b" * 64),
            ("operation", "request_sha256", "sha256:" + "b" * 64),
            ("operation", "operation_id", self.setup["enrollment_id"]),
            ("operation", "previous_generation", True),
            ("operation", "rotated_at_epoch_ms", self.now + 60_000),
            ("operation", "previous_accept_until_epoch_ms", self.now + 300_001),
            ("operation", "expires_at_epoch_ms", self.now + 3_600_001),
            ("application", "token_generation", 3),
            ("application", "principal_id", "other"),
            ("application", "status", "revoked"),
            ("application", "access_status", "unassigned"),
            ("application", "access_status", "pending"),
            ("application", "active_rule_count", 0),
            ("policy", "loaded_policy_hash", "sha256:" + "b" * 64),
            ("policy", "sequence", True),
        ]
        self.manager._transport = self.http
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                self.committed = copy.deepcopy(original)
                self.committed[section][field] = value
                with self.assertRaises(client.RenewalUnavailable):
                    self.manager.renew()
                self.assertEqual(self.manager.status()["token_generation"], 1)
                self.assertTrue(self.manager.status()["recovery_pending"])
        self.assertEqual(len(set(self.calls)), 1)

    def test_response_extra_fields_duplicate_json_and_size_refused(self):
        self.leave_unknown()
        for body in [b'{"operation":{},"operation":{}}', b'x' * 8193,
                client.canonical({**self.committed, "client_token": "must-never-return"})]:
            self.manager._transport = lambda *_: body
            with self.assertRaises(client.RenewalUnavailable):
                self.manager.renew()
        self.assertTrue(self.manager.status()["recovery_pending"])

    def test_wire_parity_with_frozen_server_contract(self):
        # Test-only import. The copied standalone client never imports serverware.
        root = str(Path(__file__).resolve().parents[2])
        sys.path.insert(0, root)
        try:
            from serverware import operator_workload_renewal as wire
            self.leave_unknown()
            raw = self.calls[0]
            parsed = wire.RenewalRequest.model_validate_json(raw)
            self.assertEqual(parsed.signing_bytes(), client.signing_bytes(json.loads(raw)))
            self.assertEqual(parsed.request_digest(), self.committed["operation"]["request_sha256"])
            self.assertEqual(wire.canonical(parsed.model_dump()), raw)
            parsed.verify(self.manager.initialize(), self.setup["audience"])
            self.assertEqual(wire.DOMAIN, client.DOMAIN)
            self.assertEqual(wire.MAX_REQUEST_BYTES, client.MAX_REQUEST_BYTES)
            self.assertEqual(wire.MAX_RESPONSE_BYTES, client.MAX_RESPONSE_BYTES)
        finally:
            sys.path.remove(root)


class TransportTests(unittest.TestCase):
    def test_https_isolated_process_has_fixed_deadline_and_no_ambient_credentials(self):
        process = unittest.mock.Mock()
        process.communicate.return_value = (b'{}', None)
        process.returncode = 0
        with patch.object(client.subprocess, "Popen", return_value=process) as popen:
            self.assertEqual(client.https_post("https://proxy.example.test/v1/workload/renew", b'{}'), b'{}')
        self.assertEqual(popen.call_args.kwargs["env"], {})
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(process.communicate.call_args.kwargs["timeout"], 15)
        self.assertEqual(popen.call_args.args[0][-1], "_http")

    def test_timeout_kills_child_and_reports_unknown(self):
        process = unittest.mock.Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired("child", 15), (b'', None)]
        with patch.object(client.subprocess, "Popen", return_value=process):
            with self.assertRaises(client.RenewalUnavailable):
                client.https_post("https://proxy.example.test/v1/workload/renew", b'{}')
        process.kill.assert_called_once()
        self.assertEqual(process.communicate.call_count, 2)

    def test_https_no_redirects_or_auth_headers(self):
        connection = unittest.mock.Mock()
        response = connection.getresponse.return_value
        response.status = 302
        response.headers.get_all.side_effect = lambda name, default: ["application/json"] if name == "Content-Type" else []
        with patch.object(client.http.client, "HTTPSConnection", return_value=connection) as create:
            with self.assertRaises(client.ClientError):
                client._https_exchange("https://proxy.example.test/v1/workload/renew", b'{}')
        context = create.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        request = connection.request.call_args
        self.assertEqual(request.args, ("POST", "/v1/workload/renew"))
        self.assertEqual(set(request.kwargs["headers"]), {"Content-Type", "Accept", "Connection"})
        connection.close.assert_called_once()

    def test_bad_audience_rejected_before_network(self):
        with patch.object(client.subprocess, "Popen") as popen:
            for audience in ("http://proxy.example.test/v1/workload/renew", "https://a:b@proxy.example.test/v1/workload/renew",
                    "https://proxy.example.test/v1/workload/renew?x=1", "https://proxy.example.test/other"):
                with self.assertRaises(client.ClientError):
                    client.https_post(audience, b'{}')
            popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
