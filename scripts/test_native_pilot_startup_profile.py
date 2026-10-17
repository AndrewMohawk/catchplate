#!/usr/bin/env python3
"""Pure three-role startup joins, not process/socket or independent authority proof.

The reusable policy fixture authenticates real-format signed synthetic sources
and tiny inert inventory trees. Process/socket rows here are explicitly test
observations, not invented live owners. No validator is replaced or mocked.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_approval_policy as policy_fixture
from scripts import run_native_pilot_lifecycle as lifecycle_cli
from scripts import run_native_pilot_approval_provider as provider_cli
from scripts import run_native_pilot_current_head_decisions as decision_cli
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from catchplate import native_pilot_startup_profile as profile

p = profile.p
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def fixture(parent):
    policy_source = policy_fixture.fixture(parent)
    clocks = policy_source["clocks"]
    inventory = policy_source["arguments"]["supervisor_inventory_original"]
    listener = policy_source["source"]["listener"]
    config = dict(apiVersion=profile.API, purpose=profile.PURPOSE,
        supervisorInventorySha256=p.sha(inventory), invocationId=p.sha(b"synthetic startup invocation"),
        directory=dict(device=20, inode=21), **dict(zip(profile.BOOT_FIELDS, clocks["boot"], strict=True)),
        issuedAtBoottimeNs="1", deadlineBoottimeNs=listener["window"]["lifetimeDeadlineBoottimeNs"],
        issuedAtUnixNanos=1, expiresAtUnixNanos=listener["expiresAtUnixNanos"])
    config_raw = p.canonical(config)
    peers = {role: dict(pid=300 + index * 50, uid=0, gid=0, startTimeTicks=1000 + index, parentPid=200)
        for index, role in enumerate(profile.ROLES)}
    hellos, ready, inode = {}, {}, 30
    for role in profile.ROLES:
        control = dict(device=20, inode=inode); inode += 1
        listeners = {}
        for edge in profile.ROLE_LISTENERS[role]:
            listeners[edge] = dict(device=20, inode=inode); inode += 1
        hellos[role] = profile.encode("hello", role, p.sha(config_raw),
            process=peers[role], control=control, listeners=listeners)
        sockets = {}
        for edge in profile.ROLE_SOCKETS[role]:
            sockets[edge] = dict(socket=dict(device=20, inode=inode),
                peer=peers[profile.PEER_ROLES[role][edge]]); inode += 1
        ready[role] = profile.encode("ready", role, p.sha(config_raw),
            peersSha256=p.sha(p.canonical(peers)), sockets=sockets)
    observed = profile.observation(config_raw, hellos, ready)
    public_peer = lambda role: {name: peers[role][name] for name in profile.policy.PEER_FIELDS}
    policy_value = copy.deepcopy(policy_source["value"])
    policy_value.update(lifecyclePeer=public_peer("lifecycle"), currentHeadPeer=public_peer("decisions"))
    decision_value = dict(apiVersion=profile.decisions.API, purpose=profile.decisions.PURPOSE,
        supervisorInventorySha256=p.sha(inventory), providerPeer=public_peer("provider"),
        directory=dict(device=20, inode=22), **dict(zip(profile.BOOT_FIELDS, clocks["boot"], strict=True)),
        issuedAtBoottimeNs=config["issuedAtBoottimeNs"], deadlineBoottimeNs=config["deadlineBoottimeNs"],
        issuedAtUnixNanos=config["issuedAtUnixNanos"], expiresAtUnixNanos=config["expiresAtUnixNanos"])
    sources = {"listener-configuration": p.canonical(listener),
        "provider-policy": profile.policy.canonical(policy_value),
        "recipe": policy_source["arguments"]["recipe_original"],
        "conductor-inventory": policy_source["arguments"]["conductor_inventory_original"],
        "authority-inventory": policy_source["arguments"]["authority_inventory_original"],
        "decision-configuration": p.canonical(decision_value)}
    approval = dict(apiVersion=profile.ADMISSION_API, configurationSha256=p.sha(config_raw),
        observationSha256=p.sha(observed), sources={name: p.sha(raw) for name, raw in sources.items()},
        deadlineBoottimeNs=config["deadlineBoottimeNs"], expiresAtUnixNanos=config["expiresAtUnixNanos"])
    return dict(configuration=config, configuration_raw=config_raw, inventory_raw=inventory,
        peers=peers, hellos=hellos, ready=ready, observation_raw=observed,
        sources=sources, admission=approval, clocks=clocks, policy_source=policy_source)


def admitted(source, value=None, **changes):
    args = dict(configuration_raw=source["configuration_raw"], observation_raw=source["observation_raw"],
        source_originals=source["sources"], supervisor_inventory_original=source["inventory_raw"],
        **source["clocks"])
    return profile.admission(p.canonical(source["admission"] if value is None else value), **(args | changes))


def admit_message(source, role):
    return profile.encode("admit", role, p.sha(source["configuration_raw"]),
        readySha256=p.sha(source["ready"][role]), observationSha256=p.sha(source["observation_raw"]),
        admissionSha256=p.sha(p.canonical(source["admission"])),
        sources=[dict(purpose=name, sha256=p.sha(source["sources"][name])) for name in profile.ROLE_SOURCES[role]],
        keys=[dict(family=family, purpose=purpose, index=len(profile.ROLE_SOURCES[role]) + index)
            for index, (family, purpose) in enumerate(profile.KEY_NAMES)] if role == "lifecycle" else [],
        deadlineBoottimeNs=source["admission"]["deadlineBoottimeNs"],
        expiresAtUnixNanos=source["admission"]["expiresAtUnixNanos"])


class StartupProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="startup-profile-")
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(policy_fixture.source_fixture.runtime_fixture.thaw, Path(directory.name))
        cls.source = fixture(Path(directory.name))

    def test_setup_is_closed_pinned_and_has_no_future_peer_fields(self):
        source = self.source
        value = profile.configuration(source["configuration_raw"], inventory_sha256=p.sha(source["inventory_raw"]),
            **source["clocks"])
        self.assertEqual(value["value"], source["configuration"])
        for change in ({"peerPid": 999}, {"directory": {"path": "/tmp/startup"}},
                {"supervisorInventorySha256": p.sha(b"other")}, {"purpose": "automatic-approval"}):
            with self.subTest(change=change), self.assertRaises(ERRORS):
                profile.configuration(p.canonical(source["configuration"] | change),
                    inventory_sha256=p.sha(source["inventory_raw"]), **source["clocks"])

    def test_abstract_names_are_fixed_bounded_and_invocation_scoped(self):
        names = profile.addresses(self.source["configuration"])
        self.assertEqual(set(names), {"control", "lifecycle", "heads"})
        self.assertEqual(len(set(names.values())), 3)
        self.assertTrue(all(name.startswith(b"\0catchplate.startup.") and len(name) <= 107 for name in names.values()))
        other = profile.addresses(self.source["configuration"] | {"invocationId": p.sha(b"other")})
        self.assertFalse(set(names.values()) & set(other.values()))
        self.assertEqual(profile.DIRECTORY, "/etc/catchplate/native-pilot-startup")
        self.assertEqual(set(profile.SOURCE_FILENAMES.values()), {name + ".json" for name in profile.SOURCE_NAMES})

    def test_original_clocks_and_namespace_are_required(self):
        source = self.source
        for change in ({"now_boottime_ns": p.ns(source["configuration"]["deadlineBoottimeNs"])},
                {"now_unix_ns": source["configuration"]["expiresAtUnixNanos"]},
                {"boot": (source["clocks"]["boot"][0], 1, 999)}, {"now_boottime_ns": True}):
            with self.subTest(change=change), self.assertRaises(ERRORS):
                profile.configuration(source["configuration_raw"], inventory_sha256=p.sha(source["inventory_raw"]),
                    **(source["clocks"] | change))
        with self.assertRaises(ERRORS):
            profile.configuration(b" " + source["configuration_raw"], inventory_sha256=p.sha(source["inventory_raw"]),
                **source["clocks"])

    def test_observation_preserves_literal_reports_and_exact_three_role_graph(self):
        value = profile.observation_value(self.source["observation_raw"], configuration_raw=self.source["configuration_raw"])
        self.assertEqual(value["processes"], self.source["peers"])
        for role in profile.ROLES:
            self.assertEqual(value["hellos"][role].encode("ascii"), self.source["hellos"][role])
            self.assertEqual(value["ready"][role].encode("ascii"), self.source["ready"][role])

    def test_ready_wrong_peer_source_parent_or_socket_alias_refuses(self):
        source = self.source
        for change in ("peer", "map", "parent", "socket"):
            hellos, ready = dict(source["hellos"]), dict(source["ready"])
            row = p.document(ready["lifecycle"], profile.MAX_MESSAGE)
            if change == "peer": row["sockets"]["lifecycle"]["peer"] = source["peers"]["decisions"]
            elif change == "map": row["peersSha256"] = p.sha(b"other map")
            elif change == "socket": row["sockets"]["lifecycle"]["socket"] = p.document(
                hellos["lifecycle"], profile.MAX_MESSAGE)["control"]
            else:
                hello = p.document(hellos["lifecycle"], profile.MAX_MESSAGE)
                hello["process"]["parentPid"] += 1; hellos["lifecycle"] = p.canonical(hello)
            ready["lifecycle"] = p.canonical(row)
            with self.subTest(change=change), self.assertRaises(ERRORS):
                profile.observation(source["configuration_raw"], hellos, ready)

    def test_fixed_rights_layout_has_lifecycle_only_159_key_purposes(self):
        source = self.source
        self.assertEqual((len(profile.KEY_NAMES), sum(family == "cold" for family, _ in profile.KEY_NAMES)), (159, 36))
        for role in profile.ROLES:
            value = profile.message(admit_message(source, role), "admit", role=role,
                configuration_sha256=p.sha(source["configuration_raw"]))
            self.assertEqual([row["purpose"] for row in value["sources"]], list(profile.ROLE_SOURCES[role]))
            self.assertEqual(len(value["keys"]), 159 if role == "lifecycle" else 0)
        for change in ("keyorder", "keyindex", "extra", "providerkey"):
            role = "provider" if change == "providerkey" else "lifecycle"
            value = p.document(admit_message(source, role), profile.MAX_MESSAGE)
            if change == "keyorder": value["keys"][0], value["keys"][1] = value["keys"][1], value["keys"][0]
            elif change == "keyindex": value["keys"][0]["index"] = True
            elif change == "extra": value["command"] = "arbitrary"
            else: value["keys"] = [dict(family="cold", purpose="any", index=4)]
            with self.subTest(change=change), self.assertRaises(ERRORS):
                profile.message(p.canonical(value), "admit", role=role, configuration_sha256=p.sha(source["configuration_raw"]))

    def test_generated_arguments_match_all_three_existing_closed_clis(self):
        source = self.source
        for role in profile.ROLES:
            sources = {name: 10 + index for index, name in enumerate(profile.ROLE_SOURCES[role])}
            sockets = {name: 30 + index for index, name in enumerate(profile.ROLE_SOCKETS[role])}
            keys = {family: {name: 50 for group, name in profile.KEY_NAMES if group == family}
                for family in ("cold", "adopted")} if role == "lifecycle" else None
            argv = profile.role_arguments(role, supervisor_inventory_fd=5,
                supervisor_inventory_sha256=p.sha(source["inventory_raw"]), source_fds=sources,
                source_pins={name: p.sha(source["sources"][name]) for name in sources}, socket_fds=sockets,
                peers=source["peers"], key_fds=keys)
            self.assertTrue(entrypoint.valid_arguments(argv))
            if role == "lifecycle":
                parsed = lifecycle_cli._arguments(argv, profile.policy.cold.jobs.KEY_PURPOSES,
                    profile.policy.adopted.profile.KEY_PURPOSES)
                self.assertEqual(parsed["approval_peer_pid"], source["peers"]["provider"]["pid"])
            else:
                parsed = (provider_cli if role == "provider" else decision_cli)._arguments(argv)
                self.assertEqual(parsed["supervisor_inventory_fd"], 5)
            sockets[next(iter(sockets))] = 5
            with self.assertRaises(ERRORS): profile.role_arguments(role, supervisor_inventory_fd=5,
                supervisor_inventory_sha256=p.sha(source["inventory_raw"]), source_fds=sources,
                source_pins={name: p.sha(source["sources"][name]) for name in sources}, socket_fds=sockets,
                peers=source["peers"], key_fds=keys)

    def test_complete_late_admission_authenticates_existing_signed_static_sources(self):
        source = self.source; before = copy.deepcopy(source["sources"])
        result = admitted(source)
        self.assertEqual(result["pins"], source["admission"]["sources"])
        self.assertEqual(result["peers"], source["peers"])
        self.assertEqual(source["sources"], before)
        self.assertLess(result["startupDeadline"], result["deadline"])

    def test_all_six_original_pins_and_observation_are_mandatory(self):
        source = self.source
        for name in profile.SOURCE_NAMES:
            value = copy.deepcopy(source["admission"]); value["sources"][name] = p.sha(b"other")
            with self.subTest(name=name), self.assertRaises(ERRORS): admitted(source, value)
        for name in ("configurationSha256", "observationSha256"):
            with self.subTest(name=name), self.assertRaises(ERRORS):
                admitted(source, source["admission"] | {name: p.sha(b"other")})
        missing = dict(source["sources"]); del missing["recipe"]
        with self.assertRaises(ERRORS): admitted(source, source_originals=missing)

    def test_rehashed_policy_and_receiver_peer_replacements_still_refuse(self):
        source = self.source
        for name, peer_name in (("provider-policy", "lifecyclePeer"), ("provider-policy", "currentHeadPeer"),
                ("decision-configuration", "providerPeer")):
            sources = dict(source["sources"])
            row = (profile.policy.shape(sources[name]) if name == "provider-policy"
                else p.document(sources[name], profile.SOURCE_LIMITS[name]))
            row[peer_name]["startTimeTicks"] += 1
            sources[name] = profile.policy.canonical(row) if name == "provider-policy" else p.canonical(row)
            value = copy.deepcopy(source["admission"]); value["sources"][name] = p.sha(sources[name])
            with self.subTest(name=name, peer=peer_name), self.assertRaises(ERRORS):
                admitted(source, value, source_originals=sources)

    def test_role_original_limits_must_fit_admission_and_original_setup(self):
        source = self.source
        for changes in ({"deadlineBoottimeNs": str(p.ns(source["admission"]["deadlineBoottimeNs"]) - 1)},
                {"expiresAtUnixNanos": source["admission"]["expiresAtUnixNanos"] - 1},
                {"deadlineBoottimeNs": str(p.ns(source["admission"]["deadlineBoottimeNs"]) + 1)},
                {"expiresAtUnixNanos": source["admission"]["expiresAtUnixNanos"] + 1}):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                admitted(source, source["admission"] | changes)

    def test_literal_listener_and_authenticated_recipe_cannot_be_substituted(self):
        source = self.source
        for name in ("listener-configuration", "recipe"):
            sources = dict(source["sources"])
            row = p.document(sources[name], profile.SOURCE_LIMITS[name])
            if name == "listener-configuration": row["expiresAtUnixNanos"] -= 1
            else: row["source"]["commitSha"] = "0" * 40
            sources[name] = p.canonical(row)
            value = copy.deepcopy(source["admission"]); value["sources"][name] = p.sha(sources[name])
            with self.subTest(name=name), self.assertRaises(ERRORS):
                admitted(source, value, source_originals=sources)


if __name__ == "__main__":
    unittest.main()
