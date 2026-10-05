"""Real Unix peer/framing and signature controls with synthetic role bindings.

Execute the unchanged source methods without starting a measured authority.
Only business handlers and diagnostic output are recording doubles; socket
peer credentials, canonical framing, signatures and deadlines are genuine.
This is not launch, filesystem-DAC, configuration admission or DB evidence.
"""
from __future__ import annotations

import ast
import base64
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import socket
import time
from types import SimpleNamespace
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SOURCE = Path(__file__).resolve().parents[1] / "serverware/authority_service.py"
PIN = "sha256:" + "1" * 64


@cache
def source_component():
    tree = ast.parse(SOURCE.read_bytes(), filename=str(SOURCE))
    functions = {"_canonical", "_b64url_decode", "_b64url_encode", "_sha256",
        "_domain_digest", "_require_digest", "_peer_identity", "_send_message_until"}
    nodes = [node for node in tree.body if (
        isinstance(node, ast.FunctionDef) and node.name in functions
        or isinstance(node, ast.ClassDef) and node.name == "AuthorityServiceError")]
    if {node.name for node in nodes} != functions | {"AuthorityServiceError"}:
        raise AssertionError("actual source helpers are not exact")
    selected = {}
    for class_name, names in (("AuthorityProcess", {"handle", "_sign_internal", "_verify_internal_envelope"}),
            ("AuthorityServer", {"_serve_connection"})):
        original, = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
        methods = [node for node in original.body if isinstance(node, ast.FunctionDef) and node.name in names]
        if {node.name for node in methods} != names:
            raise AssertionError("actual source methods are not exact")
        selected[class_name] = methods
        nodes.append(ast.ClassDef(name=class_name, bases=[], keywords=[], body=methods,
            decorator_list=[], type_params=[]))
    references = {node.id for original in nodes for node in ast.walk(original) if isinstance(node, ast.Name)}
    imports = []
    for original in tree.body:
        if isinstance(original, ast.ImportFrom) and original.module == "serverware":
            aliases = [alias for alias in original.names if (alias.asname or alias.name) in references]
            if aliases:
                imports.append(ast.ImportFrom(module="serverware", names=aliases, level=0))
    imports.append(ast.ImportFrom(module="serverware", names=[ast.alias(name="authority_contract")], level=0))
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        *imports, *nodes], type_ignores=[])
    code = compile(ast.fix_missing_locations(module), str(SOURCE), "exec")
    served, = selected["AuthorityServer"]
    detached, = [node.value.comparators[0] for node in ast.walk(served)
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "detached"
            for target in node.targets) and isinstance(node.value, ast.Compare)]
    return code, compile(ast.Expression(body=detached), str(SOURCE), "eval")


class ObservedSocket:
    def __init__(self, original):
        self.original = original
        self.reads = []
        self.closed = False

    def getsockopt(self, *args):
        return self.original.getsockopt(*args)

    def settimeout(self, value):
        self.original.settimeout(value)

    def recv(self, size):
        self.reads.append(size)
        return self.original.recv(size)

    def sendall(self, value):
        return self.original.sendall(value)

    def close(self):
        self.closed = True
        self.original.close()


class Component:
    def __init__(self, *, peer="verifier", role="planner-writer", verifier_uid=None, verifier_gid=None):
        namespace = dict(base64=base64, hashlib=hashlib, json=json, socket=socket, time=time,
            InvalidSignature=InvalidSignature, Ed25519PublicKey=Ed25519PublicKey,
            _denial_diagnostics=lambda *_: None)
        code, magic_code = source_component()
        exec(code, namespace)
        namespace.update(INTERNAL_ENVELOPE_SCHEMA=namespace["authority_contract"].INTERNAL_ENVELOPE_SCHEMA,
            MAX_MESSAGE_BYTES=namespace["authority_contract"].MAX_RESULT_BYTES)
        self.namespace = namespace
        self.keys = {"verifier": Ed25519PrivateKey.from_private_bytes(b"V" * 32),
            "planner": Ed25519PrivateKey.from_private_bytes(b"P" * 32)}
        self.rows = {}
        for name, key in self.keys.items():
            selected_peer = name == peer
            self.rows[name] = dict(serviceUid=os.getuid() if selected_peer else os.getuid() + 1,
                serviceGid=os.getgid() if selected_peer else os.getgid() + 1,
                signingPublicKeyBase64Url=namespace["_b64url_encode"](key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
        if verifier_uid is not None:
            self.rows["verifier"]["serviceUid"] = verifier_uid
        if verifier_gid is not None:
            self.rows["verifier"]["serviceGid"] = verifier_gid
        configuration = SimpleNamespace(digest=PIN, role=lambda name: self.rows[name])
        self.process = namespace["AuthorityProcess"]()
        self.process.role_name, self.process.configuration = role, configuration
        self.process.role_config = dict(maximumInternalAgeNs=30_000_000_000)
        self.calls = []
        for purpose, method in (("reserve-execution-envelope", "_handle_reserve_execution_envelope"),
                ("persist-measured-plan", "_handle_persist_measured_plan"),
                ("read-persisted-plan", "_handle_read_persisted_plan")):
            def record(payload, purpose=purpose):
                self.calls.append((purpose, payload))
                return {"componentHandler": purpose}
            setattr(self.process, method, record)
        self.server = namespace["AuthorityServer"]()
        self.server.process = self.process
        self.server.peer_uid = self.rows["planner"]["serviceUid"]
        self.server.peer_gid = self.rows["planner"]["serviceGid"]
        self.server._serve_revocation_writer = lambda *args, **kwargs: self.calls.append(("detached-writer", None))
        from serverware import authority_public_revocation_transport as public
        self.detached_magics = set(eval(magic_code, namespace)) | set(public.REQUEST_MAGICS)

    def request(self, purpose="reserve-execution-envelope", *, signer="verifier", **changes):
        signing = self.namespace["AuthorityProcess"]()
        signing.configuration = self.process.configuration
        signing.role_config = self.process.role_config
        signing.signing_key = self.keys[signer]
        request = signing._sign_internal(purpose, {"componentInput": "synthetic"}, envelope_id=PIN, fence=1)
        request.update(changes)
        return request

    def serve(self, request=None, *, raw=None, prefix=None, deadline_ns=None):
        if prefix is None:
            raw = self.namespace["_canonical"](request) if raw is None else raw
            frame = len(raw).to_bytes(8, "big") + raw
        else:
            frame = prefix
        client, original = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        observed = ObservedSocket(original)
        client.settimeout(2)
        try:
            client.sendall(frame)
            client.shutdown(socket.SHUT_WR)
            self.server._serve_connection(observed,
                deadline_ns=time.monotonic_ns() + 2_000_000_000 if deadline_ns is None else deadline_ns)
            response = bytearray()
            while True:
                try:
                    chunk = client.recv(4096)
                except ConnectionResetError:
                    # A rejected peer/deadline closes with its input unread.
                    break
                if not chunk:
                    break
                response.extend(chunk)
            self.closed, self.reads = observed.closed, observed.reads
            if not response:
                return None
            if len(response) < 8 or int.from_bytes(response[:8], "big") != len(response) - 8:
                raise AssertionError("component response framing changed")
            return json.loads(response[8:])
        finally:
            client.close()
            original.close()


class WriterReservationPeerTests(unittest.TestCase):
    def denied(self, component, response):
        self.assertTrue(component.closed)
        self.assertEqual(component.calls, [])
        self.assertEqual(response["code"], "authority_denied")

    def test_exact_verifier_peer_reaches_only_actual_signed_reservation_dispatch(self):
        component = Component()
        response = component.serve(component.request())
        self.assertEqual(response, {"componentHandler": "reserve-execution-envelope"})
        self.assertEqual(component.calls, [("reserve-execution-envelope", {"componentInput": "synthetic"})])
        self.assertTrue(component.closed)

    def test_verifier_cannot_use_planner_canonical_purposes(self):
        for purpose in ("persist-measured-plan", "read-persisted-plan", "unknown"):
            with self.subTest(purpose=purpose):
                component = Component()
                self.denied(component, component.serve(component.request(purpose, signer="planner")))

    def test_verifier_detached_prefixes_close_before_any_body_read(self):
        for prefix in Component().detached_magics:
            with self.subTest(prefix=prefix):
                component = Component()
                self.assertIsNone(component.serve(prefix=prefix))
                self.assertEqual(component.reads, [8])
                self.assertEqual(component.calls, [])
                self.assertTrue(component.closed)

    def test_planner_retains_existing_protocols_but_cannot_relay_reservation(self):
        for purpose in ("persist-measured-plan", "read-persisted-plan"):
            with self.subTest(purpose=purpose):
                component = Component(peer="planner")
                self.assertEqual(component.serve(component.request(purpose, signer="planner")),
                    {"componentHandler": purpose})
        component = Component(peer="planner")
        self.denied(component, component.serve(component.request()))
        component = Component(peer="planner")
        self.assertIsNone(component.serve(prefix=component.namespace["writer_transport"].REQUEST_MAGIC))
        self.assertEqual(component.calls, [("detached-writer", None)])

    def test_wrong_uid_gid_or_service_role_refuses_before_intake(self):
        for arguments in (dict(verifier_uid=os.getuid() + 2), dict(verifier_gid=os.getgid() + 2),
                dict(role="issuer")):
            with self.subTest(arguments=arguments):
                component = Component(**arguments)
                self.denied(component, component.serve(component.request()))
                self.assertEqual(component.reads, [])

    def test_signature_original_deadline_configuration_and_canonical_guards_remain(self):
        for changes in (dict(signer="planner"), dict(signature="A" * 86),
                dict(configurationDigest="sha256:" + "2" * 64), dict(deadlineMonotonicNs=1)):
            with self.subTest(changes=changes):
                component = Component()
                self.denied(component, component.serve(component.request(**changes)))
        component = Component()
        request = component.request()
        self.denied(component, component.serve(raw=json.dumps(request, indent=2).encode("ascii")))
        component = Component()
        self.assertIsNone(component.serve(component.request(), deadline_ns=1))
        self.assertEqual(component.calls, [])
        self.assertEqual(component.reads, [])
        self.assertTrue(component.closed)


if __name__ == "__main__":
    unittest.main()
