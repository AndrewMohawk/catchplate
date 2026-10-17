"""UNRUN inert configuration joins, not measured/native producer admission.

Synthetic signed-configuration commitments, real Ed25519 keys and the actual
page configuration/liveness mechanics are used. The private caller shell has
no measured-process or descriptor provenance; these controls assert factory
consistency only. The positive constructor requires the actual producer source
and cannot run until it exists. No substitute producer, SQL, transport, replay
result or successful custody DTO is supplied.
"""
from __future__ import annotations

import copy
import os
import threading
import unittest
from unittest import mock

from catchplate import authority_jit_compound_configuration as source
from catchplate.authority_query_read_work import QueryReadWorkError
from test_authority_jit_original_configuration import Fixture as PageFixture, digest, work
from test_authority_jit_original_authorization import WINDOW, EPOCH, MONOTONIC, clocks


READ_DSN = "host=synthetic.invalid dbname=synthetic"


class Fixture(PageFixture):
    def __init__(self):
        super().__init__()
        self.payload["webauthn"] = dict(rpId="synthetic.invalid", origin="https://synthetic.invalid",
            challengeLifetimeNs=300_000_000_000, maximumChallengeAgeNs=30_000_000_000,
            allowedAuthenticatorClasses=["platform"], requireAttestationTrusted=True)
        self.seal()

    def caller(self, *, role="planner", window=WINDOW, check=lambda current_work: None):
        configured = self.capture(role)
        result = object.__new__(source.page_service._PageCaller)
        object.__setattr__(result, "_configured", configured)
        object.__setattr__(result, "_check_owner", check)
        object.__setattr__(result, "_window", window)
        object.__setattr__(result, "_held", (configured, check, window))
        object.__setattr__(result, "_identity", (os.getpid(), threading.get_ident()))
        return result

    def arguments(self, *, caller=None, meter=None):
        return dict(payload=self.payload, configuration_digest=self.digest,
            generation=self.generation, runtime_role_identities=self.runtime,
            read_dsn=READ_DSN, page_caller=self.caller() if caller is None else caller,
            work=work() if meter is None else meter)


class JitCompoundConfigurationControls(unittest.TestCase):
    def test_actual_inert_producer_joins_read_identity_policy_and_retained_page_owner(self):
        from catchplate.authority_jit_compound_production import _JitCompoundProducer

        fixture = Fixture()
        caller, meter = fixture.caller(), work()
        actual = source._selection
        selections = []

        def capture(**arguments):
            value = actual(**arguments)
            selections.append(value)
            return value

        with clocks(), mock.patch.object(source, "_selection", side_effect=capture), \
                mock.patch.object(source.planning.physical, "_connect", side_effect=AssertionError("native read opened")):
            result = source._producer_from_configuration_on_work(**fixture.arguments(caller=caller, meter=meter))
        self.assertIs(type(result), _JitCompoundProducer)
        self.assertEqual(len(selections), 1)
        settings, policy, _check = selections[0]
        role = fixture.payload["roles"]["planner"]
        identity = (role["plannerSessionIdentityDigest"], role["measurementDigest"],
            fixture.runtime["roles"]["planner"]["attestationReceiptDigest"])
        self.assertEqual(settings, (READ_DSN, 2, (role["databaseRole"], role["tlsClientDn"],
            role["tlsClientSerial"], role["tlsIssuerDn"], *identity)))
        self.assertEqual(policy, {"rp_id": "synthetic.invalid", "origin": "https://synthetic.invalid",
            "maximum_assertion_age_seconds": 30})
        self.assertEqual(settings[2][4:], caller._configured.planner_identity)
        self.assertIs(caller._window, WINDOW)
        self.assertIs(caller._configured.private_key, fixture.private)
        self.assertGreater(meter.input_bytes, 0)
        self.assertGreater(meter.hash_work, 0)

    def test_assertion_age_is_derived_from_original_signed_policy_without_default(self):
        for nanoseconds, expected in ((300_000_000_000, 30), (30_000_000_000, 30),
                (5_999_999_999, 5), (1_000_000_000, 1)):
            fixture = Fixture()
            fixture.payload["webauthn"]["maximumChallengeAgeNs"] = nanoseconds
            fixture.seal()
            with clocks():
                _settings, policy, _check = source._selection(**fixture.arguments())
            self.assertEqual(policy["maximum_assertion_age_seconds"], expected)
        for value in (999_999_999, 0, -1, True, 1.0):
            fixture = Fixture()
            fixture.payload["webauthn"]["maximumChallengeAgeNs"] = value
            fixture.seal()
            arguments = fixture.arguments()
            with self.subTest(value=value), clocks(), \
                    mock.patch.object(source.configuration, "_key", side_effect=AssertionError("invalid policy reached key")), \
                    self.assertRaises(ValueError):
                source._producer_from_configuration_on_work(**arguments)

    def test_config_runtime_generation_query_and_enabled_originals_are_mandatory(self):
        for kind in ("commitment", "runtime", "generation", "query", "disabled", "missing-policy", "rp", "origin"):
            fixture = Fixture()
            caller = fixture.caller()
            if kind == "commitment": fixture.payload["roles"]["planner"]["tlsClientDn"] = "CN=other"
            if kind == "runtime": fixture.runtime["roles"]["planner"]["measurementDigest"] = digest(b"other")
            if kind == "generation": fixture.generation["digest"] = digest(b"other generation")
            if kind == "query": fixture.payload["queryManifestDigest"] = digest(b"other query")
            if kind == "disabled": fixture.payload["roles"]["planner"]["enabledOperations"] = []
            if kind == "missing-policy": del fixture.payload["webauthn"]
            if kind == "rp": fixture.payload["webauthn"]["rpId"] = ""
            if kind == "origin": fixture.payload["webauthn"]["origin"] = False
            if kind in ("query", "disabled", "missing-policy", "rp", "origin"):
                fixture.seal()
            arguments = fixture.arguments(caller=caller)
            refusal = (source.planning.acquisition.core.TransitionKernelError
                if kind in ("rp", "origin") else ValueError)
            with self.subTest(kind=kind), clocks(), \
                    mock.patch.object(source.configuration, "_key", side_effect=AssertionError("invalid original reached key")), \
                    mock.patch.object(source.planning.acquisition, "_policy",
                        wraps=source.planning.acquisition._policy) as policy, \
                    self.assertRaises(refusal) as caught:
                source._producer_from_configuration_on_work(**arguments)
            if kind in ("rp", "origin"):
                self.assertIs(type(caught.exception), refusal)
                policy.assert_called_once()
                self.assertEqual(str(caught.exception),
                    ("rp_id" if kind == "rp" else "origin") + " is invalid")

    def test_page_role_and_original_identity_generation_and_read_descriptor_cannot_drift(self):
        fixture = Fixture()
        for role in ("verifier", "planner-writer"):
            with self.subTest(role=role), clocks(), self.assertRaises(ValueError):
                source._producer_from_configuration_on_work(**fixture.arguments(caller=fixture.caller(role=role)))
        for field, replacement in (("planner_identity", (digest(b"other"),) * 3),
                ("configuration_digest", digest(b"other config")), ("generation_digest", digest(b"other generation")),
                ("private_key", fixture.verifier_private)):
            caller = fixture.caller()
            object.__setattr__(caller._configured, field, replacement)
            with self.subTest(field=field), clocks(), self.assertRaises(ValueError):
                source._producer_from_configuration_on_work(**fixture.arguments(caller=caller))
        for dsn in (READ_DSN + "\n", "", None):
            arguments = fixture.arguments()
            arguments["read_dsn"] = dsn
            with clocks(), self.assertRaises(ValueError):
                source._producer_from_configuration_on_work(**arguments)
        arguments = fixture.arguments()
        arguments["planner_private_key"] = fixture.private
        with self.assertRaises(TypeError):
            source._producer_from_configuration_on_work(**arguments)

    def test_all_source_scalar_selections_are_owned_before_native_key_callback(self):
        fixture = Fixture()
        caller = fixture.caller()
        before = copy.deepcopy(fixture.payload)
        actual = source.configuration._key

        def key(*arguments, **keywords):
            fixture.payload["webauthn"].update(rpId="caller.invalid", origin="https://caller.invalid", maximumChallengeAgeNs=1)
            fixture.payload["roles"]["planner"]["tlsClientDn"] = "CN=caller"
            fixture.runtime["roles"]["planner"]["attestationReceiptDigest"] = digest(b"caller attestation")
            return actual(*arguments, **keywords)

        with clocks(), mock.patch.object(source.configuration, "_key", side_effect=key):
            settings, policy, _check = source._selection(**fixture.arguments(caller=caller))
        self.assertEqual(settings[2][1], before["roles"]["planner"]["tlsClientDn"])
        self.assertEqual(settings[2][4:], caller._configured.planner_identity)
        self.assertEqual(policy["rp_id"], before["webauthn"]["rpId"])
        self.assertEqual(policy["maximum_assertion_age_seconds"], 30)

    def test_original_window_maxima_and_page_callback_ownership_never_reset(self):
        fixture = Fixture()
        maximum = fixture.capture().maximum_age_ns
        too_wide = (*WINDOW[:5], maximum + 1, WINDOW[6])
        with clocks(), self.assertRaises(ValueError):
            source._selection(**fixture.arguments(caller=fixture.caller(window=too_wide)))
        shorter = (EPOCH, MONOTONIC, MONOTONIC + 10, EPOCH + 1000, MONOTONIC + 1000, 1000, 0)
        caller = fixture.caller(window=shorter)
        with clocks():
            source._selection(**fixture.arguments(caller=caller))
        self.assertIs(caller._window, shorter)
        for kind in ("limits", "spend", "window", "configured"):
            meter = work()
            caller = None

            def check(active_work):
                self.assertIs(active_work, meter)
                if kind == "limits": active_work.limits = work().limits
                if kind == "spend": active_work.charge(input_bytes=1)
                if kind == "window": object.__setattr__(caller, "_window", tuple(list(WINDOW)))
                if kind == "configured": object.__setattr__(caller._configured, "planner_spki_digest", digest(b"changed"))
                return None

            caller = fixture.caller(check=check)
            with self.subTest(kind=kind), clocks(), self.assertRaises(ValueError):
                source._selection(**fixture.arguments(caller=caller, meter=meter))

    def test_original_work_reservation_and_cancellation_precede_or_survive_callbacks(self):
        fixture = Fixture()
        meter = work(max_input_bytes=16383)
        # Construct the real page caller before intercepting production's
        # configuration capture; its fixture setup calls the same helper.
        arguments = fixture.arguments(meter=meter)
        with mock.patch.object(source.configuration, "_capture_configuration_on_work") as capture:
            with self.assertRaises(source.JitCompoundConfigurationError) as caught:
                source._producer_from_configuration_on_work(**arguments)
            capture.assert_not_called()
        self.assertIs(type(caught.exception.__cause__), QueryReadWorkError)
        self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), (0, 0, 0))

        class Cancel(BaseException):
            pass

        failure = Cancel()

        def check(_work):
            raise failure

        with clocks(), self.assertRaises(Cancel) as caught:
            source._selection(**fixture.arguments(caller=fixture.caller(check=check)))
        self.assertIs(caught.exception, failure)


if __name__ == "__main__":
    unittest.main()
