#!/usr/bin/env python3
"""Finite local codecs/storage controls, NOT a hardware or SQL ceremony.

Signed fixtures exercise the actual root signature codec only. Their labelled
synthetic pins are not passed off as admitted grants, custody owners or a live
enrollment. The full producer continues to require the real original replay.
"""
import ast
import copy
import inspect
import os
from pathlib import Path
import stat
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from scripts.authority import local_registration_context as cli
from serverware import authority_local_registration_context as context
from serverware import control_plane_registration_execution_bootstrap as execution
from serverware import control_plane_registration_finalization_bootstrap as finalization

PIN = "sha256:" + "1" * 64
OTHER = "sha256:" + "2" * 64


def work():
    return context._ValidationWork(context.QueryReadValidationLimits())


def fixture(purpose="execution"):
    now, mono = time.time_ns(), time.monotonic_ns()
    key = Ed25519PrivateKey.from_private_bytes(b"R" * 32)
    value = dict(schema=context.SCHEMA, sourceRevision=context.roots.authority.SOURCE_REVISION,
        purpose=purpose, stage="reserve", configurationDigest=PIN, generationDigest=PIN,
        currentRootEnrollmentSha256=PIN, grantEnrollmentSha256=PIN, authorizationEnrollmentSha256=PIN,
        callerSpkiDigest=PIN, localDigest=PIN,
        subject=dict(localDigest=PIN, userId="synthetic-user", sessionId=None, challengeId="synthetic-challenge",
            mode="operator", requestDigest=PIN, operationId=PIN), originalsSha256=[PIN] * 10,
        reservationSha256=None, scope=dict(sequence=0, headDigest=PIN, nextFence=1), priorContextSha256=None,
        completionPacketDigest=None, completionAuthorizationDigest=None,
        bootIdDigest=context.local.configuration.launcher._boot_identity_digest(),
        issuedAtMonotonicNs=mono - 1_000_000_000, deadlineMonotonicNs=mono + 20_000_000_000,
        issuedAtUnixNanos=now - 1_000_000_000, expiresAtUnixNanos=now + 20_000_000_000)
    return value, key


def signed(value, key):
    return context.signer._sign(value, context.SIGNED_SCHEMA, context.MAX_CONTEXT, key, key.public_key(), work())


def successor(prior, raw):
    value = copy.deepcopy(prior)
    value.update(stage="execute", scope=dict(sequence=1, headDigest=OTHER, fence=1),
        priorContextSha256=context.sha(raw), reservationSha256=[OTHER] * 3,
        completionPacketDigest=OTHER, completionAuthorizationDigest=OTHER)
    return value


def nested(module):
    # Shape-only original containers, never admitted as enrollment originals.
    original = dict(base64Url="e30", byteCount=2)
    endpoint = lambda path: dict(socketPath=path, requestTimeoutSeconds=1, listenerUid=0, listenerGid=0)
    return dict(schema=module.LOCAL_SCHEMA,
        **{("executionCallerPrivateKeyFd" if module is execution else "finalizationCallerPrivateKeyFd"): module.CALLER_KEY_FD},
        currentRootEnrollment=original, grantEnrollment=original, authorizationEnrollment=original,
        authorizerEndpoint=endpoint(module.AUTHORIZER_SOCKET_PATH), reserverEndpoint=endpoint(module.RESERVER_SOCKET_PATH),
        sqlEndpoint=endpoint(module.SQL_SOCKET_PATH), completionEndpoint=endpoint(module.COMPLETION_SOCKET_PATH),
        contextDirectory=dict(path=context.DIRECTORY, device=1, inode=2))


class LocalRegistrationContextTests(unittest.TestCase):
    def test_actual_root_signatures_roundtrip_both_fixed_purposes_and_linked_stages(self):
        for purpose in context.PURPOSES:
            value, key = fixture(purpose)
            raw = signed(value, key)
            self.assertEqual(context._read(raw, key.public_key(), work()), value)
            following = successor(value, raw)
            following_raw = signed(following, key)
            self.assertEqual(context._read(following_raw, key.public_key(), work()), following)
            context._link(following, value, raw)

    def test_wrong_root_and_modified_original_never_admit(self):
        value, key = fixture()
        raw = signed(value, key)
        wrong = Ed25519PrivateKey.from_private_bytes(b"S" * 32)
        with self.assertRaises(InvalidSignature): context._read(raw, wrong.public_key(), work())
        changed = context.document(raw, context.MAX_CONTEXT)
        changed["payload"]["scope"]["headDigest"] = OTHER
        with self.assertRaises(InvalidSignature): context._read(context.canonical(changed), key.public_key(), work())
        with self.assertRaises(ValueError): context._read(raw + b"\n", key.public_key(), work())

    def test_link_refuses_replacement_identity_new_window_or_unrelated_pending(self):
        prior, key = fixture()
        raw = signed(prior, key)
        for field, item in (("configurationDigest", OTHER), ("localDigest", OTHER), ("priorContextSha256", OTHER),
                ("deadlineMonotonicNs", prior["deadlineMonotonicNs"] + 1),
                ("issuedAtUnixNanos", prior["issuedAtUnixNanos"] + 1),
                ("scope", dict(sequence=2, headDigest=OTHER, fence=1))):
            changed = successor(prior, raw); changed[field] = item
            with self.assertRaises(ValueError): context._link(changed, prior, raw)

    def test_closed_context_and_path_grammars_refuse_other_purposes_and_fake_caps(self):
        value, _ = fixture()
        for field, item in (("purpose", "activation"), ("stage", "recover"), ("deadlineMonotonicNs", True),
                ("originalsSha256", [PIN] * 9), ("completionPacketDigest", PIN), ("extra", 1)):
            changed = copy.deepcopy(value); changed[field] = item
            with self.assertRaises(ValueError): context._shape(changed)
        for purpose, digest, stage in (("../execution", PIN, "reserve"), ("execution", "../x", "reserve"),
                ("execution", PIN, "execute/else")):
            with self.assertRaises(ValueError): context.filename(purpose, digest, stage)
        with self.assertRaises(ValueError): context.directory(dict(path=context.DIRECTORY + "/x", device=1, inode=2))

    def test_new_nested_profiles_do_not_change_or_promote_legacy_cold_fields(self):
        for module, old in ((execution, execution.V3_SCHEMA), (finalization, finalization.V4_SCHEMA)):
            selected = nested(module)
            module._shape(selected)
            for field, item in (("statePredecessor", dict(sequence=0, headDigest=PIN, nextFence=1)),
                    ("currentPending", dict(sequence=1, headDigest=PIN, fence=1)), ("completionPacketDigest", PIN)):
                changed = copy.deepcopy(selected); changed[field] = item
                with self.assertRaises(ValueError): module._shape(changed)
            changed = copy.deepcopy(selected); changed["schema"] = old
            with self.assertRaises(ValueError): module._shape(changed)
            legacy = {name: item for name, item in selected.items() if name in module._FIELDS}
            legacy["schema"] = module.SCHEMA
            module._shape(legacy)

    def test_narrowing_preserves_original_opening_and_never_reissues_lifetime(self):
        from serverware import authority_webauthn_evidence_plan_clock as clock
        value, _ = fixture()
        window = clock._open_on_work(deadline_epoch_ns=time.time_ns() + 25_000_000_000,
            maximum_lifetime_ns=30_000_000_000, maximum_clock_skew_ns=0, work=work())
        result, bound = context._narrow(value, window, window[4])
        self.assertEqual(result[:3], window[:3])
        self.assertEqual(result[5:], window[5:])
        self.assertLessEqual(result[3], value["expiresAtUnixNanos"])
        self.assertLessEqual(bound, min(window[4], value["deadlineMonotonicNs"]))

    def test_no_fake_owner_or_unsigned_data_can_become_context_admission(self):
        with self.assertRaises(ValueError):
            context._admit_on_owner(object(), purpose="execution", local_digest=PIN, stage="reserve", common={},
                originals=(), reserved=None, subject={}, deadline_epoch_ns=1, deadline_ns=1, work=work())
        value, key = fixture()
        with self.assertRaises(ValueError): context._read(context.canonical(value), key.public_key(), work())
        with self.assertRaises(ValueError): context.prepare(context.canonical(value), root_public_key=key.public_key(), work=work())

    def test_actual_source_connects_packet_replay_and_original_consumers_not_unsigned_response_pins(self):
        # This is a structural order control, not runtime-client admission.
        # Read the real source without importing a separately gated app role.
        def function_source(module, name):
            raw = Path(context.__file__).with_name(module + ".py").read_text()
            tree = ast.parse(raw)
            functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
            self.assertEqual(len(functions), 1)
            return ast.get_source_segment(raw, functions[0])

        replay = inspect.getsource(context._replay)
        self.assertIn("receiving._verify_on_configuration", replay)
        self.assertIn("packets._prepare_on_work", replay)
        self.assertIn("live_window=checked.live_window", replay)
        self.assertIn("work=work, transport_deadline_ns=checked.deadline_ns", replay)
        reserve_source = function_source("control_plane_registration_execution", "_reserve_on_owner")
        self.assertLess(reserve_source.index("_admit_on_owner"), reserve_source.index("_claim_reservation_on_owner"))
        self.assertLess(reserve_source.index("_claim_reservation_on_owner"), reserve_source.index("_socket_request"))
        for module, function in (("control_plane_registration_handoff", "_execute_on_owner"),
                ("control_plane_registration_finalization_sql", "_request_on_owner")):
            source = function_source(module, function)
            self.assertLess(source.index("contexts._admit_on_owner"), source.index("claim_registration"))
            self.assertLess(source.index("claim_registration"), source.index("_socket_request"))
        completion_source = function_source("control_plane_registration_finalization_completion_subject", "_inspect_material_on_owner")
        self.assertIn('contexts._selected_scope(owner, "finalization", digest)', completion_source)
        self.assertIn('contexts._selected_scope(owner, "execution", evidence_digest)', completion_source)

    def test_fixed_cli_and_closed_independent_scope_selection(self):
        valid = ["--approval-fd", "3", "--approval-sha256", PIN, "--signing-key-fd", "4"]
        self.assertEqual(cli.arguments(valid), dict(approval_fd=3, approval_sha256=PIN, signing_key_fd=4))
        for changed in (valid + ["--scope", "latest"], valid[:-1] + ["3"], valid[:1] + ["03"] + valid[2:]):
            with self.assertRaises(ValueError): cli.arguments(changed)
        request_source = inspect.getsource(context._request_on_owner)
        self.assertNotIn('scope=', request_source)
        self.assertIn('scope=approval["scope"]', inspect.getsource(context.prepare))

    @unittest.skipUnless(os.environ.get("SERVERWARE_TEST_LOCAL_REGISTRATION_CONTEXT_SANDBOX") == "1"
        and os.getresuid() == os.getresgid() == (0, 0, 0) and sys.flags.isolated and sys.flags.dont_write_bytecode,
        "actual fixed-directory control requires isolated root -I -B, disposable /run, CAP_CHOWN")
    def test_real_fixed_directory_protected_file_identity_and_no_adoption(self):
        parent = Path("/run/serverware")
        created_parent = not parent.exists()
        if created_parent: parent.mkdir(mode=0o755)
        self.assertFalse(Path(context.DIRECTORY).exists())
        handles, names = [], []
        selected = context.prepare_directory()
        try:
            with self.assertRaises(FileExistsError): context.prepare_directory()
            info = os.stat(context.DIRECTORY, follow_symlinks=False)
            self.assertEqual((info.st_dev, info.st_ino), (selected["device"], selected["inode"]))
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 65532, 0o750))
            value, key = fixture()
            raw, name = signed(value, key), context.filename("execution", PIN, "reserve")
            path = Path(context.DIRECTORY) / name
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            names.append(name)
            try:
                self.assertEqual(os.write(fd, raw), len(raw))
                os.fchown(fd, 0, 65532); os.fchmod(fd, 0o440); os.fsync(fd)
            finally: os.close(fd)
            actual, identity = context._file(handles, selected, name)
            context._close(handles)
            self.assertEqual(actual, raw)
            self.assertEqual(identity[:2], (os.stat(path).st_dev, os.stat(path).st_ino))
            with self.assertRaises(ValueError):
                context._file(handles, dict(selected, inode=selected["inode"] + 1), name)
            context._close(handles)
            os.link(path, Path(context.DIRECTORY) / "owned-hardlink"); names.append("owned-hardlink")
            with self.assertRaises(ValueError): context._file(handles, selected, name)
            context._close(handles)
            os.symlink(name, Path(context.DIRECTORY) / "owned-symlink"); names.append("owned-symlink")
            with self.assertRaises(OSError): context._file(handles, selected, "owned-symlink")
        finally:
            context._close(handles)
            current = os.stat(context.DIRECTORY, follow_symlinks=False)
            self.assertEqual((current.st_dev, current.st_ino), (selected["device"], selected["inode"]))
            for name in names: os.unlink(Path(context.DIRECTORY) / name)
            # This exact empty task-owned directory was created above; restore
            # its owner only for cleanup, without DAC override or a host mount.
            os.chown(Path(context.DIRECTORY) / "requests", 0, 0, follow_symlinks=False)
            os.rmdir(Path(context.DIRECTORY) / "requests")
            os.rmdir(context.DIRECTORY)
            if created_parent: os.rmdir(parent)


if __name__ == "__main__": unittest.main()
