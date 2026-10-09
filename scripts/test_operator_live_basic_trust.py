#!/usr/bin/env python3
"""Memory-only trust-selection tests, not certificate/handshake acceptance.

The in-memory PEM-shaped payloads are NOT X.509 roots. Their input hash replaces
the installed-file pin only within each test; SHA-256 and production validation
remain real. The production installed-file pin has a separate literal control.
No files, clients, subprocesses or network connections are opened.
"""
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_operator_live_basic as checker


SYSTEM_PEM = b"-----BEGIN CERTIFICATE-----\nc3lzdGVt\n-----END CERTIFICATE-----\n"
INNER_PEM = b"-----BEGIN CERTIFICATE-----\naW5uZXI=\n-----END CERTIFICATE-----\n"


class MemoryPath:
    def __init__(self, name, data):
        self.name, self.data = name, data
        self.absolute = self.regular = self.resolved = True
        self.reported_size = None

    def __str__(self):
        return self.name

    def is_absolute(self):
        return self.absolute

    def resolve(self):
        return self if self.resolved else object()

    def is_file(self):
        return self.regular

    def stat(self):
        return SimpleNamespace(st_size=len(self.data) if self.reported_size is None else self.reported_size)

    def read_bytes(self):
        return self.data


class LiveBasicTrustTests(unittest.TestCase):
    def fixture(self):
        system = MemoryPath("/etc/ssl/certs/ca-certificates.crt", SYSTEM_PEM * 121)
        inner = MemoryPath("/memory/inner-ca.pem", INNER_PEM)
        combined = MemoryPath("/memory/requests-ca.pem", system.data + inner.data)
        return system, SimpleNamespace(ca_file=inner, requests_ca_file=combined)

    def evaluate(self, system, args, *, pin=None):
        expected = hashlib.sha256(SYSTEM_PEM * 121).hexdigest() if pin is None else pin
        with patch.object(checker, "SYSTEM_CA", system), patch.object(checker, "SYSTEM_CA_SHA256", expected):
            return checker.trust_bundle(args)

    def rejected(self, system, args, *, pin=None):
        with self.assertRaises(checker.smoke.CheckFailure):
            self.evaluate(system, args, pin=pin)

    def test_production_installed_path_and_diagnostic_hash_are_exact(self):
        self.assertEqual(str(checker.SYSTEM_CA), "/etc/ssl/certs/ca-certificates.crt")
        self.assertEqual(checker.SYSTEM_CA_SHA256,
            "ecd9dc38bc3efb7dbd6431f57e29d2f8d6a0f0d211e1464b3fef2cbfe266fcd2")

    def test_explicit_bundle_does_not_require_a_default_cafile(self):
        system, args = self.fixture()
        with patch.object(checker.ssl, "get_default_verify_paths",
                          return_value=SimpleNamespace(cafile=None, capath="/usr/lib/ssl/certs")) as defaults:
            result = self.evaluate(system, args)
        defaults.assert_not_called()
        self.assertEqual(result, {
            "systemRootsSha256": "sha256:" + hashlib.sha256(system.data).hexdigest(),
            "innerCaSha256": "sha256:" + hashlib.sha256(INNER_PEM).hexdigest(),
            "outerTrustSource": "explicit-pinned-installed-system-ca-bundle",
            "outerTrustBundle": "/etc/ssl/certs/ca-certificates.crt",
            "requestsTrustStores": "one-scoped-explicit-system-bundle-plus-inner-ca"})

    def test_changed_system_bytes_refused_even_with_matching_combined_bundle(self):
        system, args = self.fixture()
        system.data += b"\n"
        args.requests_ca_file.data = system.data + args.ca_file.data
        self.rejected(system, args)

    def test_system_certificate_count_is_independently_closed(self):
        for count in (0, 120, 122):
            system, args = self.fixture()
            system.data = SYSTEM_PEM * count
            args.requests_ca_file.data = system.data + args.ca_file.data
            with self.subTest(count=count):
                self.rejected(system, args, pin=hashlib.sha256(system.data).hexdigest())

    def test_combined_bundle_must_be_exact_system_then_one_inner_root(self):
        system, args = self.fixture()
        for value in (system.data, INNER_PEM, INNER_PEM + system.data,
                      system.data + INNER_PEM * 2, system.data + INNER_PEM + b"\n"):
            with self.subTest(length=len(value)):
                args.requests_ca_file.data = value
                self.rejected(system, args)

    def test_inner_root_must_be_one_separate_public_pem(self):
        for value in (INNER_PEM * 2, SYSTEM_PEM, b"-----BEGIN PRIVATE KEY-----\nsecret\n", b"not-pem"):
            system, args = self.fixture()
            args.ca_file.data = value
            args.requests_ca_file.data = system.data + value
            with self.subTest(length=len(value)):
                self.rejected(system, args)

    def test_all_paths_require_resolved_bounded_regular_public_files(self):
        for selected, maximum in (("system", 1024 * 1024), ("inner", 16384), ("combined", 2 * 1024 * 1024)):
            for attribute, value in (("absolute", False), ("regular", False), ("resolved", False),
                                     ("reported_size", 0), ("reported_size", maximum + 1)):
                system, args = self.fixture()
                path = {"system": system, "inner": args.ca_file, "combined": args.requests_ca_file}[selected]
                setattr(path, attribute, value)
                with self.subTest(path=selected, attribute=attribute, value=value):
                    self.rejected(system, args)


if __name__ == "__main__":
    unittest.main()
