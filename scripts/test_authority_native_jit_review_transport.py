#!/usr/bin/env python3
"""Local socket framing controls, not cold admission or signed authorizations."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_native_jit_review_transport as transport
from serverware import authority_native_jit_review_current_read as reads


DIGEST = "sha256:" + "a" * 64
SESSION = "12345678-1234-4234-8234-123456789abc"
TOKEN = b"Synthetic_public_test_token_".ljust(64, b"A")
RESPONSE = ('{ "authorization":1 }', '{"parent":2}', '{"child":3}', '{"pair":4}', '{"evidence":5}')


def bound():
    return time.monotonic_ns() + 3_000_000_000


def header(sizes):
    return DIGEST.encode("ascii") + (123456789).to_bytes(8, "big") + b"".join(n.to_bytes(8, "big") for n in sizes)


class NativeReviewTransportTests(unittest.TestCase):
    def serve(self, handler, client):
        errors, observations = [], []
        with tempfile.TemporaryDirectory(prefix="native-wire-") as directory:
            path = directory + "/service.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)
                def run():
                    try:
                        with listener.accept()[0] as connection:
                            connection.settimeout(3)
                            observations.append(handler(connection))
                    except BaseException as error:
                        errors.append(error)
                thread = threading.Thread(target=run, daemon=True)
                thread.start()
                try:
                    result = client(path)
                finally:
                    thread.join(4)
                    self.assertFalse(thread.is_alive(), "local transport fixture did not finish")
                if errors:
                    raise errors[0]
                return result, observations

    def exchange(self, path, **changes):
        return transport.exchange(path, **(dict(configuration_digest=DIGEST, deadline_epoch_ns=123456789,
            challenge_original='{ "challenge":1 }', session_id=SESSION, session_token_original=TOKEN,
            deadline_ns=bound(), expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()) | changes))

    def test_actual_unix_roundtrip_preserves_originals_and_inherited_deadline(self):
        deadline = bound()
        observed_bounds = []
        call = transport.io._call_until
        def record(connection, selected, operation):
            observed_bounds.append(selected)
            return call(connection, selected, operation)
        def handler(connection):
            prefix = transport.io._recv_prefix(connection, deadline_ns=deadline)
            request = transport.recv_request(connection, prefix=prefix, deadline_ns=deadline)
            transport.send_response(connection, RESPONSE, deadline_ns=deadline)
            return request
        with patch.object(transport.io, "_call_until", side_effect=record):
            result, observed = self.serve(handler, lambda path: transport.exchange(path,
                configuration_digest=DIGEST, deadline_epoch_ns=123456789,
                challenge_original='{ "challenge":1 }', session_id=SESSION, session_token_original=TOKEN,
                deadline_ns=deadline, expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()))
        self.assertEqual(result, RESPONSE)
        self.assertEqual(observed, [(DIGEST, 123456789, '{ "challenge":1 }', SESSION, TOKEN)])
        self.assertEqual(set(observed_bounds), {deadline})
        self.assertEqual(transport._TOKEN_CHARACTERS, reads._TOKEN_CHARACTERS)

    def test_wrong_peer_transmits_nothing_and_does_not_retry(self):
        def client(path):
            with self.assertRaises(transport.AuthorityTransportError):
                transport.exchange(path, configuration_digest=DIGEST, deadline_epoch_ns=123456789,
                    challenge_original="{}", session_id=SESSION, session_token_original=TOKEN,
                    deadline_ns=bound(), expected_peer_uid=os.getuid() + 1, expected_peer_gid=os.getgid())
        _, observed = self.serve(lambda connection: connection.recv(1), client)
        self.assertEqual(observed, [b""])

    def test_request_lengths_are_rejected_before_body_reads_and_exact_eof_is_required(self):
        for sizes in ((0, 36, 64), (transport.wire.MAX_NATIVE_ORIGINAL + 1, 36, 64),
                (2, 35, 64), (2, 36, 65), (2**64 - 1, 36, 64)):
            with self.subTest(sizes=sizes):
                left, right = socket.socketpair()
                try:
                    right.sendall(header(sizes))
                    with patch.object(transport.io, "_recv_exact_until", wraps=transport.io._recv_exact_until) as receive:
                        with self.assertRaises(transport.AuthorityTransportError):
                            transport.recv_request(left, prefix=transport.REQUEST_MAGIC, deadline_ns=bound())
                    self.assertEqual([call.args[1] for call in receive.call_args_list], [71, 8, 24])
                finally:
                    left.close()
                    right.close()
        for suffix in (b"trailing",):
            left, right = socket.socketpair()
            try:
                right.sendall(header((2, 36, 64)) + b"{}" + SESSION.encode() + TOKEN + suffix)
                right.shutdown(socket.SHUT_WR)
                with self.assertRaises(transport.AuthorityTransportError):
                    transport.recv_request(left, prefix=transport.REQUEST_MAGIC, deadline_ns=bound())
            finally:
                left.close()
                right.close()

    def test_malformed_response_lengths_ascii_and_eof_are_refused(self):
        for encoded in (
                transport.RESPONSE_MAGIC + (2**64 - 1).to_bytes(8, "big") + (2).to_bytes(8, "big") * 4,
                transport.RESPONSE_MAGIC + (2).to_bytes(8, "big") * 5 + b"\xffx" + b"{}" * 4,
                transport.RESPONSE_MAGIC + (2).to_bytes(8, "big") * 5 + b"{}" * 5 + b"extra",
                b"WRONG001"):
            def handler(connection):
                deadline = bound()
                transport.recv_request(connection, prefix=transport.io._recv_prefix(connection, deadline_ns=deadline),
                    deadline_ns=deadline)
                connection.sendall(encoded)
            def client(path):
                with self.assertRaises(transport.AuthorityTransportError):
                    self.exchange(path)
            with self.subTest(bytes=len(encoded)):
                self.serve(handler, client)

    def test_invalid_local_fields_fail_before_socket_creation(self):
        values = dict(configuration_digest=DIGEST, deadline_epoch_ns=123456789, challenge_original="{}",
            session_id=SESSION, session_token_original=TOKEN, deadline_ns=bound(),
            expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid())
        for changes in ({"session_id": SESSION.upper()}, {"session_id": "x" * 36},
                {"session_token_original": TOKEN[:-1]}, {"session_token_original": b"!" * 64},
                {"challenge_original": "éé"}, {"challenge_original": "x" * (transport.wire.MAX_NATIVE_ORIGINAL + 1)},
                {"configuration_digest": "sha256:" + "A" * 64}, {"deadline_epoch_ns": True},
                {"deadline_ns": 1}, {"expected_peer_uid": True}):
            with self.subTest(fields=tuple(changes)), patch.object(transport.socket, "socket") as create:
                with self.assertRaises(transport.AuthorityTransportError):
                    transport.exchange("/never-connected.sock", **(values | changes))
                create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
