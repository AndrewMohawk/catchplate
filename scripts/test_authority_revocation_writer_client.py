#!/usr/bin/env python3
"""Genuine client preflight/replay/ACK verification over an OS stream model.

The configuration is an independently constructed committed fixture, not a
root-admitted MeasuredConfiguration or active planner. The socket supplies
bytes and peer observations only; no DB, registry, proof or launch success is
substituted. A genuine fixture-writer signature is cryptographic evidence,
not evidence that the modeled peer committed a database transaction. Original
request expectations are derived before transport and never learned from ACKs.
Source preparation only: these controls have not been executed.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as authority
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_writer_ack_expectation as expectation
from serverware import authority_revocation_writer_acknowledgment as acknowledgment
from serverware import authority_revocation_writer_client as client
import test_authority_revocation_plan as oracle
import test_authority_revocation_persistence as codec_oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_verifier as verifier_oracle
import test_authority_revocation_writer_acknowledgment as ack_oracle
import test_authority_revocation_writer_commitment as commitment_oracle
import test_authority_revocation_writer_composition as composition_oracle
import test_authority_revocation_writer_transport as transport_oracle


class ClientFixture(composition_oracle.CompositionFixture):
    def __init__(self):
        super().__init__()
        roles = self.action.configuration.payload["roles"]
        roles["planner"].update(serviceUid=1101, serviceGid=1102, requestTimeoutSeconds=1.25)
        roles["planner-writer"].update(serviceUid=1001, serviceGid=1002,
            peerUid=1101, peerGid=1102, socketPath="/fixture/writer.sock", requestTimeoutSeconds=1.0,
            responseSigningPublicKeyBase64Url=oracle.encoded(self.writer_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)))
        # Every new field changes the configured verifier session and both
        # receipt/plan originals; rebuild that genuine chain and its controls.
        self.refresh_configuration()

    def arguments(self):
        return {"payload": self.action.configuration.payload,
            "configuration_digest": self.configuration_digest,
            "generation": self.action.configuration.generation, **self.originals()}

    def helper_arguments(self):
        roles = self.action.configuration.payload["roles"]
        return {**self.receiver_arguments(),
            "maximum_age_ns": min(roles["planner"]["maximumInternalAgeNs"],
                roles["planner-writer"]["maximumInternalAgeNs"]),
            "expected_planner_identity": copy.deepcopy(self.plan.identity),
            "expected_verifier_identity": copy.deepcopy(self.plan.semantic.receipt.identity),
            "maximum_assertion_age_ns": self.plan.maximum_assertion_age_ns,
            "maximum_plan_age_ns": self.plan.maximum_plan_age_ns}


def expected_request(fixture):
    args = fixture.action.arguments
    header = record_oracle.record_header(fixture.plan, args["envelope_bytes"], args["evaluation_context_bytes"])
    return {"intent_envelope_id": fixture.intent_id, "relay_envelope_id": fixture.relay_id,
        "execution_envelope_id": args["envelope_id"], "planner_transaction_id": args["planner_transaction_id"],
        "plan_protocol": "revocation-v4",
        "retained_record_digest": oracle.framed(record_oracle.RECORD_SCHEMA, oracle.wire(header)),
        "configuration_digest": fixture.configuration_digest, "generation_sequence": fixture.generation_sequence,
        "generation_digest": fixture.generation_digest,
        "exact_intent_bytes_digest": oracle.sha(fixture.intent_bytes), "exact_intent_byte_count": len(fixture.intent_bytes),
        "exact_relay_bytes_digest": oracle.sha(fixture.relay_bytes), "exact_relay_byte_count": len(fixture.relay_bytes),
        "historical_expectations_bytes_digest": oracle.sha(fixture.history_bytes),
        "historical_expectations_byte_count": len(fixture.history_bytes),
        "planner_key_digest": header["plannerKeyDigest"], "verifier_key_digest": header["verifierKeyDigest"],
        "planned_at_epoch_ns": args["planned_at_epoch_ns"], "source_revision": authority.SOURCE_REVISION}


def expected_ack(fixture, **changes):
    return ack_oracle.expected_wire({**expected_request(fixture), **changes},
        fixture.writer_spki_digest, fixture.writer_key)


def independent_expectation_work(fixture):
    add = oracle.add
    identities = oracle.graph_cost({"expectedPlannerIdentity": fixture.plan.identity,
        "expectedVerifierIdentity": fixture.plan.semantic.receipt.identity}, 1, 1)
    controls = commitment_oracle.independent_work(fixture)["receiver"]["total"]
    policies = tuple(fixture.action.expectations[name] for name in
        ("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns"))
    policy = oracle.canonical_comparison(policies, policies)
    record = record_oracle.independent_record_metrics(fixture.plan)
    hashes = (3, len(fixture.intent_bytes) + len(fixture.relay_bytes) + len(fixture.history_bytes), 0)
    prefix = add(identities, controls, policy)
    total = add(prefix, record["total"], hashes)
    replay_peak = add(prefix, record["admission"])
    return {"identities": identities, "controls": controls, "policy": policy, "record": record,
        "hashes": hashes, "prefix": prefix, "total": total,
        "admission": tuple(max(values) for values in zip(total, replay_peak))}


def independent_client_work(fixture):
    add, payload = oracle.add, fixture.action.configuration.payload
    planner, writer = payload["roles"]["planner"], payload["roles"]["planner-writer"]
    capture = oracle.graph_cost(payload, 1, 1)
    topology = oracle.canonical_comparison((writer["peerUid"], writer["peerGid"]),
        (planner["serviceUid"], planner["serviceGid"]))
    factory = verifier_oracle.independent_factory_work(fixture.action.configuration.verifier)["total"]
    writer_key = add(codec_oracle.codec_decode(bytes(32)), (1, 88, 0),
        oracle.canonical_comparison(fixture.writer_spki_digest, fixture.writer_spki_digest))
    proof = independent_expectation_work(fixture)
    ack = ack_oracle.independent_ack_work(expected_request(fixture), fixture.writer_spki_digest,
        expected_ack(fixture))["verify"]["total"]
    prefix = add(capture, topology, factory, writer_key)
    pre_socket = add(prefix, proof["total"])
    total = add(pre_socket, ack)
    replay_peak = add(prefix, proof["admission"])
    return {"capture": capture, "topology": topology, "factory": factory, "writer_key": writer_key,
        "expectation": proof, "ack": ack, "prefix": prefix, "pre_socket": pre_socket, "total": total,
        "admission": tuple(max(values) for values in zip(total, replay_peak))}


@contextmanager
def exchange(fixture, *, raw=None, hook=None, fail_at=None, failure=None):
    raw = expected_ack(fixture) if raw is None else raw
    clock = transport_oracle.ClockRecorder(fixture.now_mono)
    connection = transport_oracle.SocketRecorder(transport_oracle.ack_segments(raw),
        fragment_size=127, hook=hook, fail_at=fail_at, failure=failure)
    with transport_oracle.socket_scope(connection, clock) as (opened, _clock), \
            patch.object(client.time, "time_ns", return_value=fixture.now_epoch):
        yield connection, opened, clock


@contextmanager
def observed_keys(callback):
    actual = Ed25519PublicKey.from_public_bytes
    keys = []

    def construct(raw):
        role = ("planner", "verifier", "writer")[len(keys)]
        key = actual(raw)
        callback(role + ".constructor")
        wrapped = ack_oracle._PublicKey(key, callback, role=role)
        keys.append(wrapped)
        return wrapped

    with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=construct):
        yield keys


class RevocationWriterClientTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def send(self, fixture, meter=None, **changes):
        return client._send_on_configuration(work=self.work() if meter is None else meter,
            **{**fixture.arguments(), **changes})

    def test_helper_genuinely_replays_originals_and_derives_all_nineteen_fields_before_transport(self):
        fixture, meter = ClientFixture(), self.work()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            fields = expectation._expected_ack_request_on_work(work=meter, **fixture.helper_arguments())
        self.assertEqual(fields, expected_request(fixture))
        self.assertEqual(set(fields), ack_oracle.REQUEST_FIELDS)
        self.assertEqual((replay.call_count, proof.call_count), (1, 1))
        self.assertIs(replay.call_args.kwargs["work"], meter)
        self.assertIs(replay.call_args.kwargs["envelope_bytes"], fixture.action.arguments["envelope_bytes"])
        self.assertIs(replay.call_args.kwargs["evaluation_context_bytes"], fixture.action.arguments["evaluation_context_bytes"])
        self.assertEqual(replay.call_args.kwargs["expected_planner_identity"], fixture.plan.identity)
        self.assertEqual(replay.call_args.kwargs["expected_verifier_identity"], fixture.plan.semantic.receipt.identity)
        self.assertEqual(oracle.units(meter.metrics), independent_expectation_work(fixture)["total"])

    def test_real_configured_client_preflights_before_open_and_verifies_original_ack_after_eof(self):
        fixture, meter = ClientFixture(), self.work()
        expected, stages = independent_client_work(fixture), []
        original_replay, original_verify = retention._verify_record_on_work, acknowledgment._verify_on_work

        def replay(**arguments):
            self.assertNotIn("open", stages)
            result = original_replay(**arguments)
            stages.append("replay")
            return result

        def peer_event(connection, event, *_arguments):
            if event == "connect":
                self.assertEqual(stages, ["replay", "open"])

        def verify(**arguments):
            self.assertEqual(stages, ["replay", "open"])
            self.assertEqual(connection.close_count, 1)
            self.assertEqual(arguments["request_fields"], expected_request(fixture))
            self.assertIs(arguments["work"], meter)
            stages.append("ack")
            return original_verify(**arguments)

        with exchange(fixture, hook=peer_event) as (connection, opened, _clock), \
                patch.object(retention, "_verify_record_on_work", side_effect=replay) as retained, \
                patch.object(acknowledgment, "_verify_on_work", side_effect=verify) as verified, \
                patch.object(acknowledgment, "_sign_on_work", side_effect=AssertionError("client must not sign")), \
                patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys:
            def open_after_preflight(*_arguments):
                self.assertEqual(stages, ["replay"])
                self.assertEqual(oracle.units(meter.metrics), expected["pre_socket"])
                stages.append("open")
                return connection
            opened.side_effect = open_after_preflight
            result = self.send(fixture, meter)
        self.assertEqual(result, expected_ack(fixture))
        self.assertIs(type(result), bytes)
        self.assertEqual(stages, ["replay", "open", "ack"])
        self.assertEqual((retained.call_count, verified.call_count, keys.call_count), (1, 1, 3))
        opened.assert_called_once()
        self.assertEqual(b"".join(connection.sent), b"".join(transport_oracle.request_segments(
            tuple(fixture.originals()[name] for name in transport_oracle.NAMES))))
        self.assertEqual(oracle.units(meter.metrics), expected["total"])
        self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_measured_endpoint_role_key_and_generation_denials_precede_socket(self):
        cases = (("planner", "serviceUid", False), ("planner", "serviceGid", 0),
            ("planner-writer", "peerUid", 1102), ("planner-writer", "peerGid", True),
            ("planner-writer", "serviceUid", 0), ("planner-writer", "serviceGid", 1 << 32),
            ("planner-writer", "processMode", "policy-authority-verifier"),
            ("planner-writer", "socketPath", "relative"), ("planner-writer", "socketPath", "/bad\x00path"),
            ("planner-writer", "socketPath", "/" + "雪" * 36),
            ("planner", "requestTimeoutSeconds", 0.049), ("planner-writer", "requestTimeoutSeconds", 30.001),
            ("planner", "requestTimeoutSeconds", True), ("planner-writer", "maximumInternalAgeNs", False))
        for role, field, value in cases:
            fixture = ClientFixture()
            fixture.action.configuration.payload["roles"][role][field] = value
            with self.subTest(role=role, field=field, value=value), exchange(fixture) as (connection, opened, _clock), \
                    patch.object(client.verifier, "_verifier_from_configuration_on_work",
                        wraps=client.verifier._verifier_from_configuration_on_work) as factory:
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            factory.assert_not_called()
            opened.assert_not_called()
            self.assertEqual(connection.events, [])
        for mode in ("raw", "wrong_key", "alias", "generation"):
            fixture = ClientFixture()
            writer = fixture.action.configuration.payload["roles"]["planner-writer"]
            if mode == "raw": writer["responseSigningPublicKeyBase64Url"] = "!not-base64"
            elif mode == "wrong_key": writer["responseSigningPublicKeyBase64Url"] = oracle.encoded(
                fixture.planner_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            elif mode == "alias": writer["responseSigningSpkiDigest"] = fixture.other_response_spki_digests[0]
            fixture.refresh_configuration()
            if mode == "generation": fixture.action.configuration.generation["digest"] = oracle.sha(b"foreign generation")
            with self.subTest(mode=mode), exchange(fixture) as (connection, opened, _clock), \
                    patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys:
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            self.assertEqual(keys.call_count, {"raw": 2, "wrong_key": 3, "alias": 0, "generation": 0}[mode])
            opened.assert_not_called()
            self.assertEqual(connection.events, [])

    def test_current_local_age_and_timeout_minima_do_not_replace_historical_policy(self):
        for stricter in ("planner", "planner-writer"):
            fixture = ClientFixture()
            role = fixture.action.configuration.payload["roles"][stricter]
            role["maximumInternalAgeNs"], role["requestTimeoutSeconds"] = 25_000_000_000, 0.75
            fixture.refresh_configuration()
            with self.subTest(stricter=stricter), exchange(fixture) as (connection, _opened, _clock), \
                    patch.object(expectation, "_expected_ack_request_on_work",
                        wraps=expectation._expected_ack_request_on_work) as preflight:
                self.assertEqual(self.send(fixture), expected_ack(fixture))
            self.assertEqual(preflight.call_args.kwargs["maximum_age_ns"], 25_000_000_000)
            self.assertEqual(preflight.call_args.kwargs["maximum_plan_age_ns"], 30_000_000_000)
            self.assertTrue(all(value == 0.75 for value in connection.timeouts))
        for mode in ("expired", "historical_policy"):
            fixture = ClientFixture()
            if mode == "expired":
                fixture.now_epoch += 20_000_000_000
                fixture.now_mono += 20_000_000_000
            else:
                fixture.action.expectations["maximum_plan_age_ns"] -= 1
                fixture.rebuild()
            with self.subTest(mode=mode), exchange(fixture) as (_connection, opened, _clock), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            opened.assert_not_called()
            replay.assert_not_called()

    def test_genuinely_authenticated_false_plan_and_receipt_are_denied_by_real_preflight_replay(self):
        for mode in ("false_result", "false_receipt"):
            fixture = ClientFixture()
            if mode == "false_result":
                fixture.plan.payload["expectedResult"] = {"false": "correctly signed and committed"}
            else:
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureBase64url"] = oracle.encoded(bytes(64))
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureDigest"] = oracle.sha(bytes(64))
                fixture.plan.payload["authorizationProjection"]["assertionEvidenceDigest"] = oracle.framed(
                    "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", oracle.wire(fixture.plan.payload["webauthnEvidence"]))
            fixture.plan.rehash()
            fixture.action.arguments["envelope_bytes"] = oracle.wire(fixture.plan.envelope)
            fixture.rebuild()
            with self.subTest(mode=mode), exchange(fixture) as (_connection, opened, _clock), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(oracle.assertion, "_verify_receipt_signature",
                        wraps=oracle.assertion._verify_receipt_signature) as receipt, \
                    patch.object(oracle.candidate.WebAuthnCredentialRevokeKernel, "_transition",
                        wraps=oracle.candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            opened.assert_not_called()
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(receipt.call_count, 1)
            self.assertEqual(kernel.call_count, int(mode == "false_result"))

    def test_signed_ack_cannot_choose_expected_record_keys_ids_or_original_time(self):
        for name in ("retained_record_digest", "planner_key_digest", "verifier_key_digest",
                "intent_envelope_id", "configuration_digest", "generation_sequence", "planned_at_epoch_ns"):
            fixture = ClientFixture()
            original = expected_request(fixture)[name]
            changed = original + 1 if type(original) is int else oracle.sha(b"wrong independent " + name.encode("ascii"))
            raw = expected_ack(fixture, **{name: changed})
            with self.subTest(field=name), exchange(fixture, raw=raw) as (connection, opened, _clock), \
                    observed_keys(lambda _stage: None) as keys:
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            opened.assert_called_once()
            self.assertEqual(connection.close_count, 1)
            self.assertEqual([key.verifications for key in keys], [2, 2, 1])
        fixture = ClientFixture()
        for raw in (expected_ack(fixture) + b" ", b"{}", ack_oracle.expected_wire(
                expected_request(fixture), fixture.writer_spki_digest, fixture.planner_key)):
            with self.subTest(raw_length=len(raw)), exchange(fixture, raw=raw) as (connection, opened, _clock):
                with self.assertRaises(client.RevocationWriterClientError):
                    self.send(fixture)
            opened.assert_called_once()
            self.assertEqual(connection.close_count, 1)

    def test_helper_owns_independent_identities_and_holds_checked_links_across_retention_callbacks(self):
        fixture, meter, received = ClientFixture(), self.work(), []
        arguments, expected = fixture.helper_arguments(), expected_request(fixture)
        actual_receive = expectation.commitment._verify_commitments_on_work

        def receive(**inputs):
            result = actual_receive(**inputs)
            received.append(result)
            return result

        def mutate(stage):
            arguments["expected_planner_identity"].clear()
            arguments["expected_verifier_identity"].clear()
            if received:
                received[0].arguments.clear()
                received[0].intent_envelope.clear()
                received[0].relay_envelope.clear()
                received[0].expectations["expected_before"].clear()

        arguments["planner_public_key"] = ack_oracle._PublicKey(fixture.planner_key.public_key(), mutate, role="planner")
        arguments["verifier_public_key"] = ack_oracle._PublicKey(fixture.verifier_key.public_key(), mutate, role="verifier")
        with patch.object(expectation.commitment, "_verify_commitments_on_work", side_effect=receive):
            actual = expectation._expected_ack_request_on_work(work=meter, **arguments)
        self.assertEqual(actual, expected)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].arguments, {})
        self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_config_aliases_and_original_references_are_owned_before_actual_key_and_socket_callbacks(self):
        for target in ("planner.constructor", "verifier.der", "writer.constructor", "writer.der", "socket"):
            fixture, meter = ClientFixture(), self.work()
            arguments, expected = fixture.arguments(), expected_ack(fixture)
            originals = fixture.originals()
            mutated = []

            def mutate(stage):
                if stage != target or mutated:
                    return
                mutated.append(stage)
                arguments["payload"]["roles"].clear()
                arguments["generation"].clear()
                arguments.update({name: b"changed caller reference" for name in transport_oracle.NAMES})

            def socket_event(_connection, stage, *_arguments):
                if stage == "connect": mutate("socket")

            with self.subTest(target=target), exchange(fixture, raw=expected, hook=socket_event) as (connection, _opened, _clock), \
                    observed_keys(mutate):
                result = client._send_on_configuration(work=meter, **arguments)
            self.assertEqual(result, expected)
            self.assertEqual(mutated, [target])
            self.assertEqual(b"".join(connection.sent), b"".join(transport_oracle.request_segments(
                tuple(originals[name] for name in transport_oracle.NAMES))))

    def test_transport_cannot_spend_refund_retype_or_replace_the_original_work(self):
        for mode in ("spend", "refund", "type", "limits", "native"):
            fixture, meter, seen = ClientFixture(), self.work(), []
            original_limits = meter.limits
            error = OSError("native socket callback failed")

            def poison(_connection, stage, *_arguments):
                if stage != "connect": return
                if mode == "spend": meter.hash_work += 1
                elif mode == "refund": meter.input_bytes -= 1
                elif mode == "type": meter.json_nodes = False
                elif mode == "limits": meter.limits = accounting.QueryReadValidationLimits()
                seen.append((meter.hash_work, meter.input_bytes, meter.json_nodes, meter.limits))
                if mode == "native": raise error

            with self.subTest(mode=mode), exchange(fixture, hook=poison) as (connection, opened, _clock), \
                    patch.object(acknowledgment, "_verify_on_work", wraps=acknowledgment._verify_on_work) as verify:
                with self.assertRaises(OSError if mode == "native" else client.RevocationWriterClientError) as caught:
                    self.send(fixture, meter)
            if mode == "native": self.assertIs(caught.exception, error)
            opened.assert_called_once()
            verify.assert_not_called()
            self.assertEqual(connection.close_count, 1)
            self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), seen[0][:3])
            self.assertIs(meter.limits, seen[0][3])
            if mode != "limits": self.assertIs(meter.limits, original_limits)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_raw_bounds_aggregate_and_closed_api_reject_without_crypto_or_socket(self):
        class BytesSubclass(bytes):
            pass

        fixture = ClientFixture()
        for name in transport_oracle.NAMES:
            for value in (None, "{}", bytearray(b"{}"), BytesSubclass(b"{}"), b"", b"x"):
                meter = self.work()
                with self.subTest(name=name, kind=type(value).__name__), exchange(fixture) as (_connection, opened, _clock), \
                        patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys:
                    with self.assertRaises(client.RevocationWriterClientError):
                        self.send(fixture, meter, **{name: value})
                opened.assert_not_called()
                keys.assert_not_called()
                self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        meter = self.work()
        total = sum(map(len, fixture.originals().values()))
        # Negative-only source cap reduction isolates aggregate admission;
        # no decoder or successful transfer is claimed under a patched ceiling.
        with exchange(fixture) as (_connection, opened, _clock), patch.object(client.transport, "MAX_REQUEST_BYTES", total - 1):
            with self.assertRaises(client.transport.AuthorityTransportError):
                self.send(fixture, meter)
        opened.assert_not_called()
        self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        for name in ("writer_public_key", "request_fields", "verified_record", "transport", "clock",
                "maximum_age_ns", "persistence_dsn", "expected_planner_identity"):
            with self.subTest(extra=name), exchange(fixture) as (_connection, opened, _clock):
                with self.assertRaises(TypeError):
                    self.send(fixture, **{name: object()})
            opened.assert_not_called()

    def test_native_key_errors_propagate_and_callback_work_poison_has_no_success_result(self):
        for mode in ("key_error", "ack_error", "key_spend"):
            fixture, meter, seen = ClientFixture(), self.work(), []
            error = RuntimeError("native key observation failed")

            def failure(stage):
                target = "writer.verify" if mode == "ack_error" else "planner.constructor"
                if stage != target: return
                if mode == "key_spend":
                    meter.input_bytes += 1
                    seen.append((meter.hash_work, meter.input_bytes, meter.json_nodes, meter.limits))
                else:
                    raise error

            with self.subTest(mode=mode), exchange(fixture) as (connection, opened, _clock), observed_keys(failure):
                with self.assertRaises(client.RevocationWriterClientError if mode == "key_spend" else RuntimeError) as caught:
                    self.send(fixture, meter)
            if mode != "key_spend": self.assertIs(caught.exception, error)
            self.assertEqual(opened.call_count, int(mode == "ack_error"))
            self.assertEqual(connection.close_count, int(mode == "ack_error"))
            if mode == "key_spend":
                self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), seen[0][:3])
                self.assertIs(meter.limits, seen[0][3])
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_helper_and_client_exact_prior_and_each_short_budget_keep_the_genuine_clamped_child(self):
        fixture = ClientFixture()
        totals = {"helper": independent_expectation_work(fixture), "client": independent_client_work(fixture)}
        mixed, initialize = retention.plan.mixed, accounting._ValidationWork.__init__
        actual_mixed = mixed._verify
        for route in ("helper", "client"):
            expected = totals[route]
            for prior in ((0, 0, 0), (3, 17, 11)):
                for axis in (None, 0, 1, 2):
                    maximum = list(oracle.add(prior, expected["admission"]))
                    if axis is not None: maximum[axis] -= 1
                    meter = self.work(tuple(maximum))
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    original_limits, clamps, children = meter.limits, [], []

                    def observe_mixed(owned, ledger, raw_decode_bytes, captured):
                        self.assertIs(ledger.work, meter)
                        clamps.append(ledger.remaining())
                        return actual_mixed(owned, ledger, raw_decode_bytes, captured)

                    def child(instance, limits):
                        self.assertEqual(len(clamps), 1)
                        self.assertEqual(children, [])
                        self.assertIsNot(instance, meter)
                        self.assertEqual((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes), clamps[0])
                        initialize(instance, limits)
                        children.append(instance)

                    with self.subTest(route=route, prior=prior, axis=axis), exchange(fixture) as (_connection, opened, _clock), \
                            patch.object(mixed, "_verify", new=observe_mixed), \
                            patch.object(accounting._ValidationWork, "__init__", new=child):
                        if axis is None:
                            if route == "helper":
                                result = expectation._expected_ack_request_on_work(work=meter, **fixture.helper_arguments())
                                self.assertEqual(result, expected_request(fixture))
                            else:
                                self.assertEqual(self.send(fixture, meter), expected_ack(fixture))
                            self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, expected["total"]))
                            self.assertEqual((len(clamps), len(children)), (1, 1))
                            self.assertEqual(opened.call_count, int(route == "client"))
                        else:
                            with self.assertRaises(ValueError):
                                if route == "helper":
                                    expectation._expected_ack_request_on_work(work=meter, **fixture.helper_arguments())
                                else:
                                    self.send(fixture, meter)
                            self.assertLessEqual(len(children), 1)
                            self.assertTrue(all(start <= used <= limit for start, used, limit
                                in zip(prior, oracle.units(meter.metrics), maximum)))
                    self.assertIs(meter.limits, original_limits)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_repeated_client_replays_and_verifies_original_ack_again_without_resigning_or_reset(self):
        fixture = ClientFixture()
        expected = independent_client_work(fixture)
        required = oracle.add(expected["total"], expected["admission"])
        for axis in (None, 0, 1, 2):
            maximum = list(required)
            if axis is not None: maximum[axis] -= 1
            self.assertTrue(all(limit >= first for limit, first in zip(maximum, expected["admission"])))
            meter = self.work(tuple(maximum))
            original_limits = meter.limits
            with self.subTest(axis=axis), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay, patch.object(
                    acknowledgment, "_verify_on_work", wraps=acknowledgment._verify_on_work) as verify, patch.object(
                    acknowledgment, "_sign_on_work", side_effect=AssertionError("client retry signs")):
                with exchange(fixture) as (first, _opened, _clock):
                    original = self.send(fixture, meter)
                self.assertEqual(original, expected_ack(fixture))
                self.assertEqual(oracle.units(meter.metrics), expected["total"])
                with exchange(fixture) as (second, _opened, _clock):
                    if axis is None:
                        self.assertEqual(self.send(fixture, meter), original)
                        self.assertEqual(oracle.units(meter.metrics), oracle.add(expected["total"], expected["total"]))
                        self.assertEqual((replay.call_count, verify.call_count), (2, 2))
                        self.assertEqual(first.sent, second.sent)
                    else:
                        with self.assertRaises(ValueError):
                            self.send(fixture, meter)
                        self.assertTrue(all(used >= spent for used, spent in zip(oracle.units(meter.metrics), expected["total"])))
            self.assertIs(meter.limits, original_limits)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
