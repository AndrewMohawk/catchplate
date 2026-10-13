"""Stock Requests construction and pool lifecycle; no network/provider calls."""
from contextlib import nullcontext
import io
from importlib.metadata import version
from pathlib import Path
import re
import time
import unittest
from unittest.mock import Mock, patch

import github_read_loop as example
from managed_client import TokenLease, RenewalUnavailable


class PoolTests(unittest.TestCase):
    def lease(self, generation):
        now = time.time_ns() // 1_000_000
        return TokenLease("private-test-token", generation, now + 3_600_000, now + 300_000)

    def test_repeated_generation_reuses_pool_and_change_closes_old_first(self):
        old, new = Mock(), Mock()
        calls = []
        def factory(lease):
            if calls:
                old.close.assert_called_once()
            calls.append(lease.generation)
            return old if len(calls) == 1 else new
        pool = example.SessionPool(factory)
        self.assertIs(pool.for_lease(self.lease(1)), old)
        self.assertIs(pool.for_lease(self.lease(1)), old)
        self.assertIs(pool.for_lease(self.lease(2)), new)
        self.assertEqual(calls, [1, 2])
        pool.close()
        new.close.assert_called_once()

    def test_failed_replacement_does_not_keep_old_pool(self):
        old = Mock()
        pool = example.SessionPool(Mock(side_effect=[old, ValueError("unavailable")]))
        pool.for_lease(self.lease(1))
        with self.assertRaises(ValueError):
            pool.for_lease(self.lease(2))
        old.close.assert_called_once()
        self.assertIsNone(pool.session)

    def test_stock_session_has_explicit_tls_proxy_and_no_transport_retries(self):
        manager = Mock(proxy_origin="https://proxy.example.test", application_id="client-id")
        session = example.new_session(manager, self.lease(1), "/public/ca.pem")
        try:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.verify, "/public/ca.pem")
            self.assertEqual(session.proxies, {"https": "https://client-id:private-test-token@proxy.example.test"})
            self.assertEqual(session.headers["Authorization"], "token " + example.PLACEHOLDER)
            self.assertEqual(session.adapters["https://"].max_retries.total, 0)
        finally:
            session.close()

    def test_exact_real_dependency_closure_matches_hash_lock_and_server_pins(self):
        directory = Path(__file__).resolve().parent
        inputs = dict(line.split("==") for line in (directory / "requirements.txt").read_text().splitlines()
            if line and not line.startswith("#"))
        locked = dict(re.findall(r"^([a-z0-9-]+)==([^\s]+) \\\n(?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+",
            (directory / "requirements.lock").read_text(), re.M))
        self.assertEqual(inputs, locked)
        self.assertEqual({name: version(name) for name in locked}, locked)
        production = dict(re.findall(r"^([a-z0-9-]+)==([^\s]+)",
            (directory.parents[1] / "requirements.lock").read_text(), re.M))
        self.assertEqual({name: production[name] for name in locked if name in production},
            {name: locked[name] for name in locked if name in production})

    def test_loop_handoff_and_failure_never_call_provider_without_lease(self):
        manager, first, second = Mock(), Mock(), Mock()
        manager.lease.side_effect = [self.lease(1), self.lease(2), RenewalUnavailable("no token")]
        stop = Mock()
        stop.is_set.return_value = False
        with patch.object(example, "new_session", side_effect=[first, second]) as create, \
                patch.object(example, "read_once", return_value={"issues_observed": 0}) as read, \
                patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
            example.run(manager, "owner/repo", "/ca.pem", interval=30, iterations=3, stop=stop)
        self.assertEqual(create.call_count, 2)
        self.assertEqual(read.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_called_once()
        self.assertEqual(stop.wait.call_count, 2)

    def test_read_is_one_get_no_redirect_and_bounded_body(self):
        response = Mock(status_code=200)
        response.iter_content.return_value = [b'[{"number":42}]']
        session = Mock()
        session.get.return_value = nullcontext(response)
        with patch.object(example, "read_deadline", return_value=nullcontext()):
            result = example.read_once(session, "owner/repo", self.lease(1))
        self.assertEqual(result, {"issues_observed": 1, "token_generation": 1})
        session.get.assert_called_once()
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        response.iter_content.return_value = [b'x' * (example.MAX_BODY_BYTES + 1)]
        with patch.object(example, "read_deadline", return_value=nullcontext()):
            with self.assertRaises(ValueError):
                example.read_once(session, "owner/repo", self.lease(1))

    def test_redirect_is_not_followed(self):
        response = Mock(status_code=302)
        session = Mock()
        session.get.return_value = nullcontext(response)
        with patch.object(example, "read_deadline", return_value=nullcontext()):
            with self.assertRaises(ValueError):
                example.read_once(session, "owner/repo", self.lease(1))
        response.iter_content.assert_not_called()

    def test_interval_over_overlap_safety_budget_refused(self):
        with self.assertRaises(ValueError):
            example.run(Mock(), "owner/repo", "/ca.pem", interval=61, iterations=1)


if __name__ == "__main__":
    unittest.main()
