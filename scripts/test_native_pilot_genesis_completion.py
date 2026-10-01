#!/usr/bin/env python3
"""Pure result-bearing cold terminal controls, never live completion evidence.

The core fixture is synthetic association data, not native receipt admission.
No process, successful wait/reap, descriptor custody or executor is fabricated.
The actual owner alone releases completion_original after its real reap gate.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts.test_native_pilot_genesis_core import fixture as core_fixture
from serverware import native_pilot_genesis_process as process

p, g = process.p, process.core.g


def fixture():
    bundle, _, observation = core_fixture()
    bundle_raw, observation_raw = g.canonical(bundle), g.canonical(observation)
    scope = bundle["completion"]["prepared"]["core"]["genesis"]["scope"]
    boot = tuple(scope[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    configuration = dict(apiVersion=process.wire.HANDOFF_CONFIGURATION_API,
        window=dict(bootIdBase64url=boot[0], timeNamespaceDevice=boot[1], timeNamespaceInode=boot[2],
            issuedAtBoottimeNs="10", startupDeadlineBoottimeNs="100000000", lifetimeDeadlineBoottimeNs="1000000000",
            invocationId="1" * 32), expiresAtUnixNanos=2000, coreHandoff=dict(peerPid=42, peerUid=0, peerGid=0))
    configuration_raw = g.canonical(configuration)
    input_raw = g.canonical(dict(apiVersion=process.wire.ACTION_API, action="handoff-cold-core"))
    result_raw = g.canonical(dict(status="cold-core-custody-acknowledged", bundleSha256=p.sha(bundle_raw),
        observationSha256=p.sha(observation_raw), operationalAdoptionVerified=False))
    value = dict(apiVersion=process.replies.RENDEZVOUS_TERMINAL_API, status="cold-core-custody-acknowledged",
        jobsCompleted=66, bundleOriginal=bundle_raw.decode("ascii"), bundleSha256=p.sha(bundle_raw),
        pilotAcceptanceVerified=False, productionReleaseEligible=False, operationalAdoptionVerified=False,
        deadlineBoottimeNs="100", expiresAtUnixNanos=2000,
        configurationSha256=p.sha(configuration_raw), finalResult=dict(job="handoff-cold-core",
            inputSha256=p.sha(input_raw), resultOriginal=result_raw.decode("ascii"), resultSha256=p.sha(result_raw)))
    return dict(value=value, bundle_raw=bundle_raw, result_raw=result_raw, kwargs=dict(
        observation_raw=observation_raw, final_input_raw=input_raw, configuration_raw=configuration_raw,
        boot=boot, now_boottime_ns=80, now_unix_ns=1200))


class GenesisCompletionControls(unittest.TestCase):
    def test_selected_tail_retains_exact_literal_result_and_input_pin(self):
        f = fixture()
        value, bundle = process.completion_value(p.canonical(f["value"]), **f["kwargs"])
        self.assertEqual(value, f["value"])
        self.assertEqual(bundle, f["bundle_raw"])
        self.assertEqual(value["finalResult"]["resultOriginal"].encode("ascii"), f["result_raw"])
        self.assertIs(value["operationalAdoptionVerified"], False)

    def test_old_terminal_and_successor_are_explicitly_closed(self):
        f = fixture(); old = copy.deepcopy(f["value"])
        for name in ("configurationSha256", "finalResult", "deadlineBoottimeNs", "expiresAtUnixNanos"):
            old.pop(name)
        old["apiVersion"] = process.replies.HANDOFF_TERMINAL_API
        self.assertEqual(process.terminal_value(p.canonical(old),
            observation_raw=f["kwargs"]["observation_raw"])[1], f["bundle_raw"])
        with self.assertRaises(ValueError): process.completion_value(p.canonical(old), **f["kwargs"])
        with self.assertRaises(ValueError): process.terminal_value(p.canonical(f["value"]),
            observation_raw=f["kwargs"]["observation_raw"])

    def test_final_job_input_hash_and_literal_result_hash_are_mandatory(self):
        for update in (dict(job="cleanup"), dict(inputSha256=p.sha(b"other input")),
                dict(resultSha256=p.sha(b"other result")), dict(resultOriginal="{}"), dict(extra=True)):
            f = fixture(); f["value"]["finalResult"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.completion_value(p.canonical(f["value"]), **f["kwargs"])
        f = fixture()
        wrong_input = g.canonical(dict(apiVersion=process.wire.ACTION_API, action="cleanup"))
        f["value"]["finalResult"]["inputSha256"] = p.sha(wrong_input)
        with self.assertRaises(ValueError): process.completion_value(p.canonical(f["value"]),
            **(f["kwargs"] | {"final_input_raw": wrong_input}))

    def test_result_semantics_bind_bundle_observation_and_no_adoption_claim(self):
        for update in (dict(bundleSha256=p.sha(b"other bundle")), dict(observationSha256=p.sha(b"other observation")),
                dict(status="approved"), dict(operationalAdoptionVerified=True), dict(operationalAdoptionVerified=0)):
            f = fixture(); result = g.document(f["result_raw"], 4096); result.update(update)
            raw = g.canonical(result)
            f["value"]["finalResult"].update(resultOriginal=raw.decode("ascii"), resultSha256=p.sha(raw))
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.completion_value(p.canonical(f["value"]), **f["kwargs"])

    def test_configuration_original_and_core_boot_scope_cannot_be_rebound(self):
        f = fixture(); f["value"]["configurationSha256"] = p.sha(b"different execution")
        with self.assertRaises(ValueError): process.completion_value(p.canonical(f["value"]), **f["kwargs"])
        f = fixture(); config = g.document(f["kwargs"]["configuration_raw"], 4096)
        config["window"]["timeNamespaceInode"] += 1
        raw = g.canonical(config); f["value"]["configurationSha256"] = p.sha(raw)
        boot = (f["kwargs"]["boot"][0], f["kwargs"]["boot"][1], config["window"]["timeNamespaceInode"])
        with self.assertRaises(ValueError): process.completion_value(p.canonical(f["value"]),
            **(f["kwargs"] | dict(configuration_raw=raw, boot=boot)))

    def test_original_core_and_execution_clocks_never_renew(self):
        f = fixture()
        for update in (dict(now_boottime_ns=9), dict(now_boottime_ns=100), dict(now_unix_ns=999),
                dict(now_unix_ns=2000), dict(now_boottime_ns=True)):
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.completion_value(p.canonical(f["value"]), **(f["kwargs"] | update))
        config = g.document(f["kwargs"]["configuration_raw"], 4096); config["expiresAtUnixNanos"] = 1100
        raw = g.canonical(config); f["value"]["configurationSha256"] = p.sha(raw)
        with self.assertRaises(ValueError): process.completion_value(p.canonical(f["value"]),
            **(f["kwargs"] | dict(configuration_raw=raw)))
        for update in (dict(deadlineBoottimeNs="101"), dict(expiresAtUnixNanos=2001),
                dict(deadlineBoottimeNs="80"), dict(expiresAtUnixNanos=1200)):
            f = fixture(); f["value"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                process.completion_value(p.canonical(f["value"]), **f["kwargs"])


if __name__ == "__main__": unittest.main()
