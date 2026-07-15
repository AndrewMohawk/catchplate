#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ANCHOR="${AUDIT_ANCHOR_BASE:-http://localhost:9100}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
ANCHOR_TOKEN="${SERVERWARE_AUDIT_ANCHOR_TOKEN:-dev-audit-anchor-token}"

docker compose exec -T audit-anchor python - <<'PY'
import asyncio
import copy
import hashlib
import multiprocessing
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from scripts import audit_anchor_sink as sink


def append_worker(worker_id, start, results, records_per_worker):
    start.wait()
    try:
        response = sink.anchors(
            sink.AnchorBatch(
                records=[
                    {"kind": "multiprocess-append", "worker": worker_id, "record": index}
                    for index in range(records_per_worker)
                ]
            ),
            "test-anchor-token",
        )
        results.put({"worker": worker_id, "sequences": [item["sequence"] for item in response["anchors"]]})
    except BaseException as exc:
        results.put({"worker": worker_id, "error": repr(exc)})


def crash_append_worker():
    sink.anchors(
        sink.AnchorBatch(
            records=[
                {"kind": "kill-during-append", "index": 1},
                {"kind": "kill-during-append", "index": 2},
                {"kind": "kill-during-append", "index": 3},
            ]
        ),
        "test-anchor-token",
    )

original_path = sink.ANCHOR_PATH
original_cache = sink.ANCHOR_COUNT_CACHE
original_state_cache = sink.ANCHOR_STATE_CACHE
original_signing_key_path = sink.SIGNING_KEY_PATH
original_anchor_token = sink.ANCHOR_TOKEN
original_publish = sink.publish_external_checkpoint
original_line_limit = sink.MAX_ANCHOR_LINE_BYTES
original_checkpoint_command = sink.CHECKPOINT_COMMAND
original_checkpoint_required = sink.CHECKPOINT_REQUIRED
original_checkpoint_stdout_limit = sink.MAX_EXTERNAL_CHECKPOINT_BYTES
original_checkpoint_stderr_limit = sink.MAX_EXTERNAL_CHECKPOINT_STDERR_BYTES
original_checkpoint_timeout = sink.EXTERNAL_CHECKPOINT_TIMEOUT_SECONDS
original_checkpoint_mode = sink.CHECKPOINT_MODE
original_expected_checkpoint_log_id = sink.EXPECTED_CHECKPOINT_LOG_ID
original_external_checkpoint_log_path = sink.EXTERNAL_CHECKPOINT_LOG_PATH
original_external_checkpoint_key_path = sink.EXTERNAL_CHECKPOINT_KEY_PATH
original_append_anchor_batch = sink.append_anchor_batch_durably
trusted_key_environment = {
    name: os.environ.get(name)
    for name in (
        "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_TRANSPARENCY_TRUSTED_PUBLIC_KEY",
    )
}
original_json_limits = (
    sink.MAX_JSON_DEPTH,
    sink.MAX_JSON_KEYS,
    sink.MAX_JSON_KEY_BYTES,
    sink.MAX_JSON_STRING_BYTES,
    sink.MAX_JSON_AGGREGATE_STRING_BYTES,
    sink.MAX_JSON_NODES,
)
try:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "anchors.jsonl"
        sink.ANCHOR_PATH = path
        sink.SIGNING_KEY_PATH = Path(tmp) / "anchor-signing-key.pem"
        sink.ANCHOR_TOKEN = "test-anchor-token"
        sink.ANCHOR_COUNT_CACHE = None
        path.write_bytes(b"{}\n{}\n")
        assert sink.count_anchors() == 2
        path.write_bytes(b'"' + b"x" * sink.MAX_ANCHOR_LINE_BYTES + b'"\n')
        sink.ANCHOR_COUNT_CACHE = None
        try:
            list(sink.iter_anchors())
        except ValueError as exc:
            assert "exceeds 8 MiB" in str(exc), exc
        else:
            raise AssertionError("oversized anchor log line was accepted")
        try:
            sink.encode_anchor_line(
                {"value": "x" * (sink.MAX_ANCHOR_LINE_BYTES + 1)}
            )
        except sink.HTTPException as exc:
            assert exc.status_code == 413, exc
        else:
            raise AssertionError("oversized anchor log record was accepted for writing")

        exact_item = {"value": "x"}
        exact_size = len(sink.canonical_json(exact_item).encode("utf-8")) + 1
        sink.MAX_ANCHOR_LINE_BYTES = exact_size
        assert sink.encode_anchor_line(exact_item) == sink.canonical_json(exact_item)
        sink.MAX_ANCHOR_LINE_BYTES = exact_size - 1
        try:
            sink.encode_anchor_line(exact_item)
        except sink.HTTPException as exc:
            assert exc.status_code == 413, exc
        else:
            raise AssertionError("anchor writer excluded the newline from its byte limit")
        sink.MAX_ANCHOR_LINE_BYTES = original_line_limit

        async def exercise_body_limit(messages, *, content_length=None, limit=16):
            called = False
            received = None
            sent = []

            async def downstream(_scope, receive, send):
                nonlocal called, received
                called = True
                received = await receive()
                await send({"type": "http.response.start", "status": 204, "headers": []})
                await send({"type": "http.response.body", "body": b""})

            middleware = sink.AnchorBodyLimitMiddleware(downstream, max_body_bytes=limit)
            headers = [] if content_length is None else [(b"content-length", str(content_length).encode())]
            scope = {"type": "http", "method": "POST", "path": "/anchors", "headers": headers}
            pending = list(messages)

            async def receive():
                return pending.pop(0)

            async def send(message):
                sent.append(message)

            await middleware(scope, receive, send)
            return called, received, sent

        called, _received, sent = asyncio.run(
            exercise_body_limit(
                [{"type": "http.request", "body": b"", "more_body": False}],
                content_length=17,
            )
        )
        assert called is False and sent[0]["status"] == 413, sent
        called, _received, sent = asyncio.run(
            exercise_body_limit(
                [
                    {"type": "http.request", "body": b"x" * 10, "more_body": True},
                    {"type": "http.request", "body": b"y" * 7, "more_body": False},
                ]
            )
        )
        assert called is False and sent[0]["status"] == 413, sent
        called, received, sent = asyncio.run(
            exercise_body_limit(
                [{"type": "http.request", "body": b"x" * 16, "more_body": False}],
                content_length=16,
            )
        )
        assert called is True and received["body"] == b"x" * 16 and sent[0]["status"] == 204

        sink.MAX_JSON_DEPTH = 3
        sink.MAX_JSON_KEYS = 2
        sink.MAX_JSON_KEY_BYTES = 4
        sink.MAX_JSON_STRING_BYTES = 4
        sink.MAX_JSON_AGGREGATE_STRING_BYTES = 6
        sink.MAX_JSON_NODES = 20
        for invalid_records in (
            [{"a": {"b": {"c": {"d": True}}}}],
            [{"a": 1, "b": 2, "c": 3}],
            [{"abcde": 1}],
            [{"a": "12345"}],
            [{"a": "123", "b": "456"}],
        ):
            try:
                sink.AnchorBatch(records=invalid_records)
            except ValidationError:
                pass
            else:
                raise AssertionError(f"anchor JSON limits accepted {invalid_records!r}")
        (
            sink.MAX_JSON_DEPTH,
            sink.MAX_JSON_KEYS,
            sink.MAX_JSON_KEY_BYTES,
            sink.MAX_JSON_STRING_BYTES,
            sink.MAX_JSON_AGGREGATE_STRING_BYTES,
            sink.MAX_JSON_NODES,
        ) = original_json_limits

        dual_output = sink.run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import os; os.write(2, b'e' * 131072); os.write(1, b'o' * 131072)",
            ],
            input_data=b"",
            timeout=5,
            stdout_limit=256 * 1024,
            stderr_limit=256 * 1024,
        )
        assert dual_output.returncode == 0
        assert len(dual_output.stdout) == 131072 and len(dual_output.stderr) == 131072

        started = time.monotonic()
        try:
            sink.run_bounded_subprocess(
                [
                    sys.executable,
                    "-c",
                    "import os,time; os.write(1, b'x' * 4096); time.sleep(10)",
                ],
                input_data=b"",
                timeout=5,
                stdout_limit=128,
                stderr_limit=128,
            )
        except sink.SubprocessOutputLimitExceeded as exc:
            assert exc.stream == "stdout" and len(exc.stdout) == 128, exc
        else:
            raise AssertionError("checkpoint subprocess stdout overflow was accepted")
        assert time.monotonic() - started < 3

        try:
            sink.run_bounded_subprocess(
                [sys.executable, "-c", "import os; os.write(2, b'x' * 4096)"],
                input_data=b"",
                timeout=5,
                stdout_limit=128,
                stderr_limit=128,
            )
        except sink.SubprocessOutputLimitExceeded as exc:
            assert exc.stream == "stderr" and len(exc.stderr) == 128, exc
        else:
            raise AssertionError("checkpoint subprocess stderr overflow was accepted")

        started = time.monotonic()
        try:
            sink.run_bounded_subprocess(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                input_data=b"",
                timeout=0.2,
                stdout_limit=128,
                stderr_limit=128,
            )
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("checkpoint subprocess timeout was not preserved")
        assert time.monotonic() - started < 3

        descendant_marker = Path(tmp) / "checkpoint-descendant.pid"
        descendant_script = """
import os
import pathlib
import signal
import sys
import time

ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready_read)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
    os.write(ready_write, b"1")
    while True:
        time.sleep(1)
os.close(ready_write)
os.read(ready_read, 1)
os._exit(0)
"""
        try:
            sink.run_bounded_subprocess(
                [sys.executable, "-c", descendant_script, str(descendant_marker)],
                input_data=b"",
                timeout=0.3,
                stdout_limit=128,
                stderr_limit=128,
            )
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("forked checkpoint descendant did not hold the command open")
        descendant_pid = int(descendant_marker.read_text())

        def descendant_is_running(pid):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                return False
            return state != "Z"

        descendant_deadline = time.monotonic() + 3
        while descendant_is_running(descendant_pid) and time.monotonic() < descendant_deadline:
            time.sleep(0.05)
        assert not descendant_is_running(descendant_pid), (
            f"checkpoint descendant {descendant_pid} survived cleanup"
        )

        sink.CHECKPOINT_COMMAND = shlex.join(
            [sys.executable, "-c", "import os,sys; os.write(2, b'denied'); sys.exit(7)"]
        )
        sink.CHECKPOINT_REQUIRED = False
        denied = sink.publish_external_checkpoint(
            {
                "sequence": 1,
                "record_digest": "sha256:" + "1" * 64,
                "leaf_hash": "sha256:" + "2" * 64,
                "tree_size": 1,
                "tree_head_hash": "sha256:" + "3" * 64,
                "signed_tree_head": {},
                "record": {},
            }
        )
        assert denied == {"ok": False, "error": "external_checkpoint_denied", "exit": 7, "detail": "denied"}
        sink.CHECKPOINT_REQUIRED = True
        try:
            sink.publish_external_checkpoint(
                {
                    "sequence": 1,
                    "record_digest": "sha256:" + "1" * 64,
                    "leaf_hash": "sha256:" + "2" * 64,
                    "tree_size": 1,
                    "tree_head_hash": "sha256:" + "3" * 64,
                    "signed_tree_head": {},
                    "record": {},
                }
            )
        except sink.HTTPException as exc:
            assert exc.status_code == 502 and exc.detail["error"] == "external_checkpoint_denied", exc
        else:
            raise AssertionError("required checkpoint command failure was accepted")
        sink.CHECKPOINT_COMMAND = original_checkpoint_command
        sink.CHECKPOINT_REQUIRED = original_checkpoint_required

        path.write_bytes(b'{"a":1}\n')
        before_stat = path.stat()
        before_identity = sink.anchor_cache_identity()
        path.write_bytes(b'{"b":2}\n')
        os.utime(path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
        after_identity = sink.anchor_cache_identity()
        assert before_identity != after_identity, (before_identity, after_identity)

        sink.ANCHOR_STATE_CACHE = None
        original_verify_items = sink._verify_items

        def mutating_verify(items, expected_key_info=None, expected_checkpoint_key_info=None):
            result = original_verify_items(
                items,
                expected_key_info,
                expected_checkpoint_key_info,
            )
            current = path.read_bytes()
            current_stat = path.stat()
            path.write_bytes(current.replace(b'"b"', b'"c"', 1))
            os.utime(path, ns=(current_stat.st_atime_ns, current_stat.st_mtime_ns))
            return result

        sink._verify_items = mutating_verify
        try:
            sink.verified_anchor_state()
        except sink.HTTPException as exc:
            assert exc.status_code == 409, exc
        else:
            raise AssertionError("anchor mutation during cold verification was accepted")
        finally:
            sink._verify_items = original_verify_items

        path.unlink(missing_ok=True)
        sink.ANCHOR_COUNT_CACHE = None
        sink.ANCHOR_STATE_CACHE = None
        sink.SIGNING_KEY_PATH = Path(tmp) / "anchor-signing-key.pem"
        sink.ANCHOR_TOKEN = "test-anchor-token"
        sink.CHECKPOINT_REQUIRED = False
        sink.publish_external_checkpoint = lambda _item: {
            "ok": False,
            "error": "optional_checkpoint_failed",
        }
        response = sink.anchors(
            sink.AnchorBatch(records=[{"kind": "optional-checkpoint-test"}]),
            "test-anchor-token",
        )
        assert response["accepted"] == 1, response
        assert response["anchors"][0]["external_checkpoint"] is None, response
        persisted = list(sink.iter_anchors())
        assert len(persisted) == 1 and "external_checkpoint" not in persisted[0], persisted
        assert sink.verify_items(persisted)["ok"] is True

        signing_key_info = sink.configured_signing_key_info()
        substituted_key = Ed25519PrivateKey.generate()
        substituted_item = copy.deepcopy(persisted[0])
        substituted_item["signed_tree_head"] = sink.sign_tree_head(
            tree_size=substituted_item["tree_size"],
            tree_head_hash=substituted_item["tree_head_hash"],
            key=substituted_key,
        )
        substituted_verification = sink.verify_items([substituted_item])
        assert substituted_verification["ok"] is False, substituted_verification
        assert "configured signing key" in substituted_verification.get("detail", ""), substituted_verification

        mismatched_log_id_item = copy.deepcopy(persisted[0])
        mismatched_log_id_item["signed_tree_head"]["log_id"] = "sha256:" + "0" * 64
        mismatched_log_id_verification = sink.verify_items([mismatched_log_id_item])
        assert mismatched_log_id_verification["ok"] is False, mismatched_log_id_verification
        assert "SPKI digest" in mismatched_log_id_verification.get("detail", ""), mismatched_log_id_verification

        original_key_bytes = sink.SIGNING_KEY_PATH.read_bytes()
        sink.SIGNING_KEY_PATH.write_bytes(
            substituted_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        before_key_swap_append = path.read_bytes()
        try:
            sink.anchors(
                sink.AnchorBatch(records=[{"kind": "must-not-cross-key-substitution"}]),
                "test-anchor-token",
            )
        except sink.HTTPException as exc:
            assert exc.status_code == 409, exc
        else:
            raise AssertionError("cached anchor state allowed signing-key substitution")
        assert path.read_bytes() == before_key_swap_append
        sink.SIGNING_KEY_PATH.write_bytes(original_key_bytes)
        sink.ANCHOR_STATE_CACHE = None

        checkpoint_payload = sink.checkpoint_payload_for_item(persisted[0])
        receipt_key = Ed25519PrivateKey.generate()
        receipt_public_key = receipt_key.public_key()
        receipt_public_der = receipt_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        receipt_public_pem = receipt_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        receipt_log_id = sink.sha256_prefixed_bytes(receipt_public_der)
        request_digest = "sha256:" + "9" * 64
        receipt_payload = {
            "version": "serverware.externalTransparencyReceipt/v1",
            "provider": "test-managed-log",
            "log_id": receipt_log_id,
            "external_sequence": 7,
            "checkpoint_digest": sink.sha256_prefixed_json(checkpoint_payload),
            "request_digest": request_digest,
            "source_sequence": persisted[0]["sequence"],
            "tree_size": persisted[0]["tree_size"],
            "tree_head_hash": persisted[0]["tree_head_hash"],
            "record_digest": persisted[0]["record_digest"],
            "leaf_hash": persisted[0]["leaf_hash"],
        }
        receipt_signature = "ed25519:" + sink.b64e(
            receipt_key.sign(sink.canonical_json(receipt_payload).encode("utf-8"))
        )
        checkpoint_response = {
            "ok": True,
            "provider": "test-managed-log",
            "mode": "external-managed-transparency-log",
            "external_sequence": 7,
            "checkpoint_digest": sink.sha256_prefixed_json(checkpoint_payload),
            "request_digest": request_digest,
            "tree_size": persisted[0]["tree_size"],
            "tree_head_hash": persisted[0]["tree_head_hash"],
            "log_id": receipt_log_id,
            "receipt": {
                "kind": "ed25519-signed-checkpoint",
                "payload": receipt_payload,
                "signature": receipt_signature,
                "public_key_pem": receipt_public_pem,
            },
        }
        trusted_checkpoint_key_path = Path(tmp) / "trusted-checkpoint-public.pem"
        trusted_checkpoint_key_path.write_text(receipt_public_pem)
        sink.CHECKPOINT_MODE = "http"
        os.environ["SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY"] = str(
            trusted_checkpoint_key_path
        )
        os.environ.pop("SERVERWARE_TRANSPARENCY_TRUSTED_PUBLIC_KEY", None)
        sink.EXPECTED_CHECKPOINT_LOG_ID = receipt_log_id
        trusted_checkpoint_key_info = sink.configured_checkpoint_key_info(required=True)
        assert trusted_checkpoint_key_info["log_id"] == receipt_log_id
        conflicting_trust_path = Path(tmp) / "conflicting-checkpoint-public.pem"
        conflicting_trust_path.write_text(receipt_public_pem)
        os.environ["SERVERWARE_TRANSPARENCY_TRUSTED_PUBLIC_KEY"] = str(
            conflicting_trust_path
        )
        try:
            sink.configured_checkpoint_key_info(required=True)
        except ValueError as exc:
            assert "conflicts" in str(exc), exc
        else:
            raise AssertionError("conflicting checkpoint trust variables were accepted")
        os.environ.pop("SERVERWARE_TRANSPARENCY_TRUSTED_PUBLIC_KEY")
        assert sink.validate_external_checkpoint_response(
            checkpoint_response,
            checkpoint_payload,
            persisted[0],
            trusted_checkpoint_key_info,
        ) is None

        successful_response_path = Path(tmp) / "successful-checkpoint-response.json"
        successful_response_path.write_text(sink.canonical_json(checkpoint_response))
        successful_descendant_marker = Path(tmp) / "successful-checkpoint-descendant.pid"
        successful_descendant_script = """
import os
import pathlib
import signal
import sys
import time

ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready_read)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
    os.write(ready_write, b"1")
    while True:
        time.sleep(1)
os.close(ready_write)
os.read(ready_read, 1)
sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())
sys.stdout.flush()
"""
        sink.CHECKPOINT_COMMAND = shlex.join(
            [
                sys.executable,
                "-c",
                successful_descendant_script,
                str(successful_response_path),
                str(successful_descendant_marker),
            ]
        )
        sink.CHECKPOINT_REQUIRED = True
        sink.publish_external_checkpoint = original_publish
        successful_publication = sink.publish_external_checkpoint(persisted[0])
        assert successful_publication["ok"] is True, successful_publication
        successful_descendant_pid = int(successful_descendant_marker.read_text())
        successful_descendant_deadline = time.monotonic() + 3
        while (
            descendant_is_running(successful_descendant_pid)
            and time.monotonic() < successful_descendant_deadline
        ):
            time.sleep(0.05)
        assert not descendant_is_running(successful_descendant_pid), (
            f"successful checkpoint descendant {successful_descendant_pid} survived cleanup"
        )
        sink.CHECKPOINT_REQUIRED = False
        sink.CHECKPOINT_COMMAND = original_checkpoint_command
        sink.publish_external_checkpoint = lambda _item: {
            "ok": False,
            "error": "optional_checkpoint_failed",
        }

        tampered_receipt = copy.deepcopy(checkpoint_response)
        tampered_receipt["receipt"]["payload"]["record_digest"] = "sha256:" + "0" * 64
        assert sink.validate_external_checkpoint_response(
            tampered_receipt,
            checkpoint_payload,
            persisted[0],
            trusted_checkpoint_key_info,
        ) == "external_checkpoint_receipt_record_digest_mismatch"
        bad_signature_receipt = copy.deepcopy(checkpoint_response)
        encoded_signature = bad_signature_receipt["receipt"]["signature"]
        signature_prefix = "ed25519:"
        signature_body = encoded_signature[len(signature_prefix) :]
        bad_signature_receipt["receipt"]["signature"] = signature_prefix + (
            ("A" if signature_body[0] != "A" else "B") + signature_body[1:]
        )
        assert sink.validate_external_checkpoint_response(
            bad_signature_receipt,
            checkpoint_payload,
            persisted[0],
            trusted_checkpoint_key_info,
        ) == "external_checkpoint_receipt_signature_mismatch"

        attacker_key = Ed25519PrivateKey.generate()
        attacker_public_key = attacker_key.public_key()
        attacker_der = attacker_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        attacker_pem = attacker_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        attacker_log_id = sink.sha256_prefixed_bytes(attacker_der)
        substituted_receipt = copy.deepcopy(checkpoint_response)
        substituted_receipt["log_id"] = attacker_log_id
        substituted_receipt["receipt"]["public_key_pem"] = attacker_pem
        substituted_receipt["receipt"]["payload"]["log_id"] = attacker_log_id
        substituted_receipt["receipt"]["signature"] = "ed25519:" + sink.b64e(
            attacker_key.sign(
                sink.canonical_json(substituted_receipt["receipt"]["payload"]).encode("utf-8")
            )
        )
        assert sink.validate_external_checkpoint_response(
            substituted_receipt,
            checkpoint_payload,
            persisted[0],
            trusted_checkpoint_key_info,
        ) == "external_checkpoint_receipt_untrusted_key"

        persisted_with_receipt = copy.deepcopy(persisted[0])
        persisted_with_receipt["external_checkpoint"] = checkpoint_response
        persisted_receipt_verification = sink.verify_items([persisted_with_receipt])
        assert persisted_receipt_verification["ok"] is True, persisted_receipt_verification
        persisted_with_substitution = copy.deepcopy(persisted[0])
        persisted_with_substitution["external_checkpoint"] = substituted_receipt
        persisted_substitution_verification = sink.verify_items([persisted_with_substitution])
        assert persisted_substitution_verification["ok"] is False, persisted_substitution_verification
        assert (
            persisted_substitution_verification["error"]
            == "external_checkpoint_receipt_untrusted_key"
        ), persisted_substitution_verification

        publication_response_path = Path(tmp) / "substituted-checkpoint-response.json"
        publication_response_path.write_text(sink.canonical_json(substituted_receipt))
        sink.CHECKPOINT_COMMAND = shlex.join(
            [
                sys.executable,
                "-c",
                "import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())",
                str(publication_response_path),
            ]
        )
        sink.CHECKPOINT_REQUIRED = True
        sink.publish_external_checkpoint = original_publish
        try:
            sink.publish_external_checkpoint(persisted[0])
        except sink.HTTPException as exc:
            assert exc.status_code == 502, exc
            assert exc.detail["error"] == "external_checkpoint_receipt_untrusted_key", exc
        else:
            raise AssertionError("publication accepted a receipt-embedded substitute key")
        sink.CHECKPOINT_REQUIRED = False
        sink.CHECKPOINT_COMMAND = original_checkpoint_command
        sink.publish_external_checkpoint = lambda _item: {
            "ok": False,
            "error": "optional_checkpoint_failed",
        }

        stable_verification, stable_accumulator = sink._verify_items(
            iter(persisted), signing_key_info
        )
        stable_identity = sink.anchor_cache_identity()
        stable_bytes = path.read_bytes()
        stable_stat = path.stat()
        path.write_bytes(stable_bytes.replace(b"optional-checkpoint-test", b"optional-checkpoint-tesU"))
        os.utime(path, ns=(stable_stat.st_atime_ns, stable_stat.st_mtime_ns))
        sink.cache_verified_anchor_state(
            stable_verification,
            stable_accumulator,
            stable_identity,
            signing_key_info["log_id"],
            stable_accumulator.checkpoint_log_id,
        )
        poisoned_verification, _poisoned_accumulator, _poisoned_identity = sink.verified_anchor_state(
            signing_key_info
        )
        assert poisoned_verification["ok"] is False, poisoned_verification
        path.write_bytes(stable_bytes)
        sink.ANCHOR_STATE_CACHE = None

        checkpoint_calls = 0

        def fail_second_checkpoint(_item):
            nonlocal_checkpoint_calls[0] += 1
            if nonlocal_checkpoint_calls[0] == 2:
                raise sink.HTTPException(status_code=502, detail="checkpoint failed")
            return None

        nonlocal_checkpoint_calls = [checkpoint_calls]
        sink.publish_external_checkpoint = fail_second_checkpoint
        before_failed_batch = path.read_bytes()
        try:
            sink.anchors(
                sink.AnchorBatch(
                    records=[
                        {"kind": "atomic-batch", "index": 1},
                        {"kind": "atomic-batch", "index": 2},
                        {"kind": "atomic-batch", "index": 3},
                    ]
                ),
                "test-anchor-token",
            )
        except sink.HTTPException as exc:
            assert exc.status_code == 502, exc
        else:
            raise AssertionError("failed checkpoint left a successful batch response")
        assert nonlocal_checkpoint_calls[0] == 2
        assert path.read_bytes() == before_failed_batch, "failed batch durably committed a prefix"
        assert sink.verify_items(list(sink.iter_anchors()))["count"] == 1

        path.unlink()
        sink.SIGNING_KEY_PATH.unlink()
        sink.ANCHOR_COUNT_CACHE = None
        sink.ANCHOR_STATE_CACHE = None
        sink.publish_external_checkpoint = lambda _item: None
        workers = 6
        records_per_worker = 3
        context = multiprocessing.get_context("fork")
        start = context.Event()
        results = context.Queue()
        processes = [
            context.Process(
                target=append_worker,
                args=(worker, start, results, records_per_worker),
            )
            for worker in range(workers)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(20)
            assert not process.is_alive(), f"append worker {process.pid} hung"
            assert process.exitcode == 0, (process.pid, process.exitcode)
        worker_results = [results.get(timeout=5) for _ in processes]
        assert all("error" not in result for result in worker_results), worker_results
        emitted_sequences = sorted(
            sequence for result in worker_results for sequence in result["sequences"]
        )
        expected_count = workers * records_per_worker
        assert emitted_sequences == list(range(1, expected_count + 1)), emitted_sequences
        multiprocess_items = list(sink.iter_anchors())
        assert len(multiprocess_items) == expected_count
        multiprocess_verification = sink.verify_items(multiprocess_items)
        assert multiprocess_verification["ok"] is True, multiprocess_verification
        assert multiprocess_verification["count"] == expected_count, multiprocess_verification
        assert {
            item["signed_tree_head"]["log_id"] for item in multiprocess_items
        } == {sink.configured_signing_key_info()["log_id"]}

        committed_before_crash = path.read_bytes()

        def kill_after_committed_prefix(encoded_batch):
            first_record_end = encoded_batch.index(b"\n") + 1
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                written = os.write(descriptor, encoded_batch[:first_record_end])
                assert written == first_record_end
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.kill(os.getpid(), signal.SIGKILL)

        sink.append_anchor_batch_durably = kill_after_committed_prefix
        crash_process = context.Process(target=crash_append_worker)
        crash_process.start()
        crash_process.join(20)
        assert not crash_process.is_alive(), "kill-during-append worker hung"
        assert crash_process.exitcode == -signal.SIGKILL, crash_process.exitcode
        sink.append_anchor_batch_durably = original_append_anchor_batch
        assert sink.anchor_transaction_path().exists(), "killed append did not leave durable intent"
        assert path.read_bytes().startswith(committed_before_crash)
        assert len(path.read_bytes()) > len(committed_before_crash), "killed append wrote no prefix"

        recovered_verification = sink.anchors_verify("test-anchor-token")
        assert recovered_verification["ok"] is True, recovered_verification
        assert recovered_verification["count"] == expected_count, recovered_verification
        assert path.read_bytes() == committed_before_crash
        assert not sink.anchor_transaction_path().exists(), "recovery left append intent behind"

        post_recovery = sink.anchors(
            sink.AnchorBatch(records=[{"kind": "post-recovery", "index": 1}]),
            "test-anchor-token",
        )
        assert post_recovery["anchors"][0]["sequence"] == expected_count + 1, post_recovery
        assert sink.anchors_verify("test-anchor-token")["count"] == expected_count + 1

        for count in range(1, 65):
            items = [
                {"leaf_hash": "sha256:" + hashlib.sha256(str(index).encode()).hexdigest()}
                for index in range(count)
            ]
            leaves = [item["leaf_hash"] for item in items]
            expected_root = sink.merkle_root(leaves)
            for index in range(count):
                proof, target = sink.streaming_inclusion_proof(iter(items), count, index)
                assert target is items[index]
                assert proof == sink.inclusion_proof(leaves, index), (count, index, proof)
                assert sink.verify_inclusion(target["leaf_hash"], proof, expected_root), (count, index)
finally:
    sink.ANCHOR_PATH = original_path
    sink.ANCHOR_COUNT_CACHE = original_cache
    sink.ANCHOR_STATE_CACHE = original_state_cache
    sink.SIGNING_KEY_PATH = original_signing_key_path
    sink.ANCHOR_TOKEN = original_anchor_token
    sink.publish_external_checkpoint = original_publish
    sink.MAX_ANCHOR_LINE_BYTES = original_line_limit
    sink.CHECKPOINT_COMMAND = original_checkpoint_command
    sink.CHECKPOINT_REQUIRED = original_checkpoint_required
    sink.CHECKPOINT_MODE = original_checkpoint_mode
    sink.EXPECTED_CHECKPOINT_LOG_ID = original_expected_checkpoint_log_id
    sink.EXTERNAL_CHECKPOINT_LOG_PATH = original_external_checkpoint_log_path
    sink.EXTERNAL_CHECKPOINT_KEY_PATH = original_external_checkpoint_key_path
    sink.append_anchor_batch_durably = original_append_anchor_batch
    sink.MAX_EXTERNAL_CHECKPOINT_BYTES = original_checkpoint_stdout_limit
    sink.MAX_EXTERNAL_CHECKPOINT_STDERR_BYTES = original_checkpoint_stderr_limit
    sink.EXTERNAL_CHECKPOINT_TIMEOUT_SECONDS = original_checkpoint_timeout
    (
        sink.MAX_JSON_DEPTH,
        sink.MAX_JSON_KEYS,
        sink.MAX_JSON_KEY_BYTES,
        sink.MAX_JSON_STRING_BYTES,
        sink.MAX_JSON_AGGREGATE_STRING_BYTES,
        sink.MAX_JSON_NODES,
    ) = original_json_limits
    for name, value in trusted_key_environment.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
PY

python3 - "$BASE" "$ANCHOR" "$ADMIN_TOKEN" "$ANCHOR_TOKEN" <<'PY'
import json
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
anchor = sys.argv[2].rstrip("/")
admin_token = sys.argv[3]
anchor_token = sys.argv[4]


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> dict:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


admin_headers = {"X-Serverware-Admin-Token": admin_token}
anchor_headers = {"X-Serverware-Audit-Anchor-Token": anchor_token}

flush = request_json(f"{base}/api/audit/anchors/flush", method="POST", headers=admin_headers, timeout=60)
assert flush["enabled"] is True, flush
assert flush["exported"] is True, flush
local = flush["verification"]
assert local["ok"] is True and local["complete"] is True, local

anchor_response = flush.get("anchor_response") or {}
assert anchor_response.get("ok") is True, anchor_response
accepted = anchor_response.get("anchors") or []
assert len(accepted) == 1, anchor_response
sequence = accepted[0]["sequence"]

status = request_json(f"{base}/api/audit/anchors/status", headers=admin_headers)
assert status["enabled"] is True, status
assert (status.get("last_exported") or {}).get("count", 0) >= local["count"], status
proof = request_json(f"{anchor}/anchors/inclusion/{sequence}", headers=anchor_headers, timeout=60)
assert proof["verified"] is True, proof
assert (proof["item"].get("record") or {}).get("audit_head") == local["head"], proof
assert (proof["item"].get("record") or {}).get("audit_count") == local["count"], proof
external = (proof["item"].get("external_checkpoint") or {})
item_signed_head = proof["item"].get("signed_tree_head") or {}
assert external.get("ok") is True, proof
assert external.get("mode") == "external-managed-transparency-log", proof
assert external.get("tree_head_hash") == item_signed_head.get("tree_head_hash"), proof
assert external.get("tree_size") == item_signed_head.get("tree_size"), proof
print(json.dumps({"ok": True, "audit_anchor": "pass", "backend": anchor_response["mode"], "external_checkpoint": external.get("provider"), "local_count": local["count"], "anchor_sequence": sequence, "inclusion_verified": True}, sort_keys=True))
PY
