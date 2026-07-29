from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SERVERWARE_DATA_DIR", str(Path(".tmp/test-codebase-attestation/data").resolve()))
os.environ.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY", None)
os.environ.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import serverware.response_identity as response_identity
from serverware.response_identity import (
    canonical_json,
    response_headers_binding,
    response_public_key_info,
    response_signature_headers,
    response_statement,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_codebase_attestation as verifier  # noqa: E402


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def expect_publication_failure(label: str) -> None:
    response_identity._PUBLICATION_CACHE = None
    try:
        response_identity.response_public_key_info()
    except response_identity.ResponseIdentityPublicationError:
        return
    raise AssertionError(f"response identity publication accepted {label}")


def stop_publishers(*publishers: subprocess.Popen[str]) -> None:
    for publisher in publishers:
        if publisher.poll() is None:
            publisher.kill()
        publisher.communicate()


def exercise_response_identity_publication() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    base_env = dict(os.environ)
    base_env.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY", None)
    base_env.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", None)
    for setting_name in (
        "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
        "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH",
    ):
        env = dict(base_env)
        env[setting_name] = "/tmp/serverware-unpaired-response-identity"
        probe = subprocess.run(
            [sys.executable, "-c", "import serverware.config"],
            cwd=repository_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode == 0 or "must be configured together" not in probe.stderr:
            raise AssertionError(
                f"config accepted unpaired {setting_name}: {probe.stderr.strip()}"
            )

    original_key_path = response_identity.RESPONSE_SIGNING_KEY_PATH
    original_public_path = response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH
    original_key_id_path = response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH
    original_data_dir = response_identity.DATA_DIR
    original_snapshot = response_identity._target_snapshot
    original_cleanup = response_identity._cleanup_publication
    original_process_lock = response_identity._acquire_publication_process_lock
    try:
        with tempfile.TemporaryDirectory() as tmp_raw:
            root = Path(tmp_raw).resolve()
            private_key = Ed25519PrivateKey.generate()
            private_path = root / "response-private.pem"
            private_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            private_path.write_bytes(private_pem)
            private_path.chmod(0o600)
            response_identity.RESPONSE_SIGNING_KEY_PATH = private_path

            unset_parent = root / "unset-publication"
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = None
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = None
            before_unset = set(root.iterdir())
            unset_info = response_identity.response_public_key_info()
            if unset_parent.exists() or set(root.iterdir()) != before_unset:
                raise AssertionError("unset response identity publication created output")

            expected_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            expected_der = private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            expected_id = sha256_prefixed(expected_der)
            if unset_info != {"pem": expected_pem.decode("ascii"), "spki_sha256": expected_id}:
                raise AssertionError("unset publication changed response public-key info")

            alias_root = root / "private-path-alias"
            alias_root.mkdir()
            aliased_public_path = alias_root / "public.pem"
            aliased_id_path = alias_root / "key-id"
            private_alias = root / "private-key-alias.pem"
            private_alias.symlink_to(aliased_public_path)
            response_identity.RESPONSE_SIGNING_KEY_PATH = private_alias
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = aliased_public_path
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = aliased_id_path
            expect_publication_failure("a public output aliased by the private-key path")
            if aliased_public_path.exists() or aliased_id_path.exists():
                raise AssertionError("response identity publication exposed a generated private key")
            response_identity.RESPONSE_SIGNING_KEY_PATH = private_path

            publication_root = root / "custody" / "response-identity"
            public_path = publication_root / "response-signing.pub.pem"
            key_id_path = publication_root / "response-signing.spki-sha256"
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = public_path
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = key_id_path
            legacy_data_dir = root / "legacy-data"
            legacy_data_dir.mkdir()
            legacy_key_path = legacy_data_dir / "response-signing-ed25519.pem"
            legacy_key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            response_identity.DATA_DIR = legacy_data_dir
            key_info = response_identity.response_public_key_info()
            if legacy_key_path.exists():
                raise AssertionError("published replacement identity did not retire the legacy response key")
            published_pem = public_path.read_bytes()
            published_id = key_id_path.read_bytes()
            if published_pem != expected_pem:
                raise AssertionError("published response key was not the exact canonical SPKI PEM")
            if published_id != (expected_id + "\n").encode("ascii"):
                raise AssertionError("published response key ID was not canonical newline-terminated text")
            if key_info["pem"].encode("ascii") != published_pem or key_info["spki_sha256"] != expected_id:
                raise AssertionError("returned and published response identities diverged")
            loaded_public = serialization.load_pem_public_key(published_pem)
            loaded_der = loaded_public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if sha256_prefixed(loaded_der) + "\n" != published_id.decode("ascii"):
                raise AssertionError("published response PEM and SPKI ID did not agree")
            raw_private = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            for path, payload in ((public_path, published_pem), (key_id_path, published_id)):
                if b"PRIVATE KEY" in payload or raw_private in payload or private_pem in payload:
                    raise AssertionError(f"published response identity exposed private bytes: {path}")
                file_stat = path.lstat()
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_uid != os.getuid()
                    or file_stat.st_nlink != 1
                    or stat.S_IMODE(file_stat.st_mode) & ~0o644
                ):
                    raise AssertionError(f"published response identity mode was unsafe: {path}")

            def unexpected_process_lock(_path: Path) -> int:
                raise AssertionError("hot response identity publication acquired the process lock")

            response_identity._acquire_publication_process_lock = unexpected_process_lock
            try:
                if response_identity.response_public_key_info() != key_info:
                    raise AssertionError("cached response identity publication changed key info")
            finally:
                response_identity._acquire_publication_process_lock = original_process_lock

            cleanup_root = root / "cleanup-failure"
            cleanup_root.mkdir()
            cleanup_public = cleanup_root / "public.pem"
            cleanup_id = cleanup_root / "key-id"
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = cleanup_public
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = cleanup_id
            response_identity._PUBLICATION_CACHE = None
            cleanup_calls = 0

            def failing_cleanup(publication: response_identity._PendingPublication) -> None:
                nonlocal cleanup_calls
                cleanup_calls += 1
                original_cleanup(publication)
                if cleanup_calls == 1:
                    raise response_identity.ResponseIdentityPublicationError(
                        "injected publication cleanup failure"
                    )

            response_identity._cleanup_publication = failing_cleanup
            expect_publication_failure("an injected cleanup failure")
            response_identity._cleanup_publication = original_cleanup
            cleanup_lock_fd = os.open(
                cleanup_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                fcntl.flock(cleanup_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(cleanup_lock_fd, fcntl.LOCK_UN)
            except BlockingIOError as exc:
                raise AssertionError("publication cleanup failure retained the process lock") from exc
            finally:
                os.close(cleanup_lock_fd)
            response_identity._PUBLICATION_CACHE = None
            response_identity.response_public_key_info()
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = public_path
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = key_id_path

            stale_key = Ed25519PrivateKey.generate()
            public_path.write_bytes(
                stale_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            key_id_path.write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
            public_path.chmod(0o600)
            key_id_path.chmod(0o600)
            stale_inodes = (public_path.stat().st_ino, key_id_path.stat().st_ino)
            response_identity._PUBLICATION_CACHE = None
            response_identity.response_public_key_info()
            if public_path.read_bytes() != expected_pem or key_id_path.read_bytes() != published_id:
                raise AssertionError("response identity publication did not replace stale outputs")
            current_inodes = (public_path.stat().st_ino, key_id_path.stat().st_ino)
            if any(stale == current for stale, current in zip(stale_inodes, current_inodes)):
                raise AssertionError("response identity outputs were rewritten in place instead of replaced")

            process_root = root / "process-concurrency"
            process_root.mkdir()
            process_private = process_root / "private.pem"
            process_public = process_root / "public.pem"
            process_id = process_root / "key-id"
            process_signal = process_root / "staged"
            process_lock_attempt = process_root / "lock-attempt"
            process_release = process_root / "release"
            process_restage = process_root / "restaged"
            process_private.write_bytes(private_pem)
            process_private.chmod(0o600)
            process_env = dict(base_env)
            process_env.update(
                {
                    "SERVERWARE_DATA_DIR": str(process_root / "data"),
                    "SERVERWARE_RESPONSE_SIGNING_KEY": str(process_private),
                    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY": str(process_public),
                    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH": str(process_id),
                }
            )
            slow_publisher = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import pathlib,time\nimport serverware.response_identity as r\n"
                        "original=r._prepare_publication\nfirst=[True]\n"
                        f"signal=pathlib.Path({str(process_signal)!r})\n"
                        f"release=pathlib.Path({str(process_release)!r})\n"
                        "def slow(path,content):\n"
                        " result=original(path,content)\n"
                        " if first[0]:\n"
                        "  first[0]=False; signal.write_text('staged',encoding='ascii')\n"
                        "  deadline=time.monotonic()+10\n"
                        "  while not release.exists():\n"
                        "   if time.monotonic()>=deadline: raise TimeoutError('release barrier timed out')\n"
                        "   time.sleep(0.01)\n"
                        " return result\n"
                        "r._prepare_publication=slow; r.response_public_key_info()"
                    ),
                ],
                cwd=repository_root,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 10
            while not process_signal.exists() and slow_publisher.poll() is None:
                if time.monotonic() >= deadline:
                    stop_publishers(slow_publisher)
                    raise AssertionError("slow response identity publisher did not stage")
                time.sleep(0.01)
            competing_lock_fd = os.open(
                process_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                try:
                    fcntl.flock(competing_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    fcntl.flock(competing_lock_fd, fcntl.LOCK_UN)
                    stop_publishers(slow_publisher)
                    raise AssertionError("slow response identity publisher did not hold the process lock")
            finally:
                os.close(competing_lock_fd)
            try:
                concurrent_publisher = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import pathlib\nimport serverware.response_identity as r\n"
                            "original_flock=r.fcntl.flock\n"
                            f"attempt=pathlib.Path({str(process_lock_attempt)!r})\n"
                            f"restaged=pathlib.Path({str(process_restage)!r})\n"
                            "def signaling_flock(fd,operation):\n"
                            " if operation & r.fcntl.LOCK_EX: attempt.write_text('attempted',encoding='ascii')\n"
                            " return original_flock(fd,operation)\n"
                            "def unexpected_prepare(path,content):\n"
                            " restaged.write_text('restaged',encoding='ascii')\n"
                            " raise AssertionError('exact publication was restaged')\n"
                            "r.fcntl.flock=signaling_flock\n"
                            "r._prepare_publication=unexpected_prepare\n"
                            "r.response_public_key_info()"
                        ),
                    ],
                    cwd=repository_root,
                    env=process_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except BaseException:
                stop_publishers(slow_publisher)
                raise
            deadline = time.monotonic() + 10
            while not process_lock_attempt.exists() and concurrent_publisher.poll() is None:
                if time.monotonic() >= deadline:
                    stop_publishers(slow_publisher, concurrent_publisher)
                    raise AssertionError("concurrent response identity publisher did not attempt the process lock")
                time.sleep(0.01)
            if slow_publisher.poll() is not None or concurrent_publisher.poll() is not None:
                stop_publishers(slow_publisher, concurrent_publisher)
                raise AssertionError("response identity publishers did not overlap at the process lock")
            try:
                process_release.write_text("release", encoding="ascii")
            except BaseException:
                stop_publishers(slow_publisher, concurrent_publisher)
                raise
            try:
                slow_stdout, slow_stderr = slow_publisher.communicate(timeout=15)
                concurrent_stdout, concurrent_stderr = concurrent_publisher.communicate(timeout=15)
            except subprocess.TimeoutExpired as exc:
                stop_publishers(slow_publisher, concurrent_publisher)
                raise AssertionError("cross-process response identity publication deadlocked") from exc
            finally:
                stop_publishers(slow_publisher, concurrent_publisher)
            if slow_publisher.returncode != 0 or concurrent_publisher.returncode != 0:
                raise AssertionError(
                    "cross-process response identity publication failed: "
                    f"slow={slow_publisher.returncode}:{slow_stdout}:{slow_stderr}; "
                    f"concurrent={concurrent_publisher.returncode}:"
                    f"{concurrent_stdout}:{concurrent_stderr}"
                )
            if process_public.read_bytes() != expected_pem or process_id.read_bytes() != published_id:
                raise AssertionError("cross-process response identity publication diverged")
            if process_restage.exists():
                raise AssertionError("exact cross-process response identity publication was restaged")

            process_public.chmod(0o600)
            process_id.chmod(0o600)
            restricted_inodes = (process_public.stat().st_ino, process_id.stat().st_ino)
            restricted_env_probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import serverware.response_identity as r; r.response_public_key_info()",
                ],
                cwd=repository_root,
                env=process_env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if restricted_env_probe.returncode != 0:
                raise AssertionError(
                    "response identity publication did not repair restricted public modes: "
                    f"{restricted_env_probe.stderr}"
                )
            if (
                stat.S_IMODE(process_public.stat().st_mode) != 0o644
                or stat.S_IMODE(process_id.stat().st_mode) != 0o644
                or process_public.stat().st_ino == restricted_inodes[0]
                or process_id.stat().st_ino == restricted_inodes[1]
            ):
                raise AssertionError("exact response identity outputs with restricted modes were not replaced")

            for unsafe_slot in ("pem", "id"):
                case_root = root / f"symlink-{unsafe_slot}"
                case_root.mkdir()
                victim = case_root / "victim"
                victim.write_text("do not replace\n", encoding="ascii")
                case_public = case_root / "public.pem"
                case_id = case_root / "key-id"
                unsafe_path = case_public if unsafe_slot == "pem" else case_id
                unsafe_path.symlink_to(victim)
                response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = case_public
                response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = case_id
                expect_publication_failure(f"a symlink {unsafe_slot} target")
                if victim.read_text(encoding="ascii") != "do not replace\n":
                    raise AssertionError("response identity publication followed a target symlink")
                other_path = case_id if unsafe_slot == "pem" else case_public
                if other_path.exists():
                    raise AssertionError("response identity publication partially committed after symlink rejection")

            for unsafe_slot in ("pem", "id"):
                case_root = root / f"nonregular-{unsafe_slot}"
                case_root.mkdir()
                case_public = case_root / "public.pem"
                case_id = case_root / "key-id"
                unsafe_path = case_public if unsafe_slot == "pem" else case_id
                unsafe_path.mkdir()
                response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = case_public
                response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = case_id
                expect_publication_failure(f"a nonregular {unsafe_slot} target")
                other_path = case_id if unsafe_slot == "pem" else case_public
                if other_path.exists():
                    raise AssertionError("response identity publication partially committed after type rejection")

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = linked_parent / "public.pem"
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = linked_parent / "key-id"
            expect_publication_failure("a symlinked parent")
            if any(real_parent.iterdir()):
                raise AssertionError("response identity publication followed a parent symlink")

            nontraversable_parent = root / "nontraversable-parent"
            nontraversable_parent.mkdir(mode=0o700)
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = nontraversable_parent / "public.pem"
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = nontraversable_parent / "key-id"
            expect_publication_failure("a cross-UID nontraversable parent")
            if any(nontraversable_parent.iterdir()):
                raise AssertionError("response identity publication used a nontraversable parent")

            race_root = root / "race"
            race_root.mkdir()
            race_public = race_root / "public.pem"
            race_id = race_root / "key-id"
            race_public.write_bytes(b"stale-public\n")
            race_id.write_bytes(b"stale-id\n")
            race_public.chmod(0o600)
            race_id.chmod(0o600)
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = race_public
            response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = race_id
            public_snapshots = 0
            race_injected = False

            def raced_snapshot(parent_fd: int, name: str) -> tuple[int, ...] | None:
                nonlocal public_snapshots, race_injected
                snapshot = original_snapshot(parent_fd, name)
                if name == race_public.name:
                    public_snapshots += 1
                    if public_snapshots == 1:
                        race_public.write_bytes(b"raced-public\n")
                        race_injected = True
                return snapshot

            response_identity._target_snapshot = raced_snapshot
            response_identity._PUBLICATION_CACHE = None
            try:
                response_identity.response_public_key_info()
            except response_identity.ResponseIdentityPublicationError as exc:
                if "changed" not in str(exc):
                    raise AssertionError(
                        f"response identity target race failed for an unrelated reason: {exc}"
                    ) from exc
            else:
                raise AssertionError("response identity publication accepted a target change race")
            response_identity._target_snapshot = original_snapshot
            if not race_injected:
                raise AssertionError("response identity target-race hook did not execute")
            if race_public.read_bytes() != b"raced-public\n" or race_id.read_bytes() != b"stale-id\n":
                raise AssertionError("response identity publication changed the post-race state")
            if list(race_root.glob(".serverware-response-*.tmp")):
                raise AssertionError("response identity publication left temporary files after failure")
    finally:
        response_identity._target_snapshot = original_snapshot
        response_identity._cleanup_publication = original_cleanup
        response_identity._acquire_publication_process_lock = original_process_lock
        response_identity.RESPONSE_SIGNING_KEY_PATH = original_key_path
        response_identity.RESPONSE_SIGNING_PUBLIC_KEY_PATH = original_public_path
        response_identity.RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = original_key_id_path
        response_identity.DATA_DIR = original_data_dir


def exercise_bounded_control_plane_response_signing() -> None:
    import serverware.app as app_module
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.responses import StreamingResponse

    context = {
        "runtime_manifest_digest": "sha256:" + "1" * 64,
        "policy_bundle_digest": "sha256:" + "2" * 64,
        "provenance_digest": "sha256:" + "3" * 64,
        "image_signatures_digest": "sha256:" + "4" * 64,
        "source_tree_digest": "sha256:" + "5" * 64,
    }
    original_limit = app_module._SIGNED_RESPONSE_MAX_BYTES
    original_header_builder = (
        app_module._signed_control_plane_response_headers
    )
    original_buffer_slots = app_module._SIGNED_RESPONSE_BUFFER_SLOTS
    original_admission_seconds = (
        app_module._SIGNED_RESPONSE_BUFFER_ADMISSION_SECONDS
    )
    original_context_functions = {
        "runtime_manifest_digest": app_module.runtime_manifest_digest,
        "release_provenance_digest": app_module.release_provenance_digest,
        "image_signatures_digest": app_module.image_signatures_digest,
        "source_tree_digest": app_module.source_tree_digest,
        "get_policy_snapshot": app_module.get_policy_snapshot,
        "response_signature_headers": app_module.response_signature_headers,
    }

    def request_for(nonce: str | None) -> Request:
        headers: list[tuple[bytes, bytes]] = []
        if nonce is not None:
            headers.append(
                (b"x-serverware-response-nonce", nonce.encode("latin-1"))
            )
        return Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "path": "/api/bounded-response",
                "raw_path": b"/api/bounded-response",
                "query_string": b"code=oauth-code-secret&state=oauth-state-secret",
                "root_path": "",
                "headers": headers,
                "client": ("192.0.2.1", 12345),
                "server": ("serverware.test", 443),
            }
        )

    async def signed_stream(
        *,
        nonce: str | None,
        chunks: list[bytes],
        source_headers: dict[str, str] | None = None,
        tail_observed: list[bool] | None = None,
        emitted_messages: list[dict[str, object]] | None = None,
    ):
        async def body_iterator():
            for index, chunk in enumerate(chunks):
                if tail_observed is not None and index == len(chunks) - 1:
                    tail_observed[0] = True
                yield chunk

        async def downstream(scope, receive, send):
            response = StreamingResponse(
                body_iterator(),
                status_code=200,
                headers=source_headers,
                media_type="application/octet-stream",
            )
            await response(scope, receive, send)

        request = request_for(nonce)
        request_delivered = False
        request_finished = asyncio.Event()
        messages = (
            emitted_messages if emitted_messages is not None else []
        )

        async def receive():
            nonlocal request_delivered
            if not request_delivered:
                request_delivered = True
                return {
                    "type": "http.request",
                    "body": b"",
                    "more_body": False,
                }
            await request_finished.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            copied = dict(message)
            if message["type"] == "http.response.start":
                copied["headers"] = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                copied["body"] = bytes(message.get("body", b""))
            messages.append(copied)

        try:
            await app_module._SignedControlPlaneASGI(downstream)(
                request.scope,
                receive,
                send,
            )
        finally:
            request_finished.set()

        starts = [
            message
            for message in messages
            if message["type"] == "http.response.start"
        ]
        if len(starts) != 1:
            raise AssertionError(
                f"signed ASGI response start count changed: {messages}"
            )
        bodies = [
            bytes(message.get("body", b""))
            for message in messages
            if message["type"] == "http.response.body"
        ]
        return SimpleNamespace(
            status_code=int(starts[0]["status"]),
            raw_headers=list(starts[0]["headers"]),
            headers={
                name.decode("latin-1").lower(): value.decode("latin-1")
                for name, value in starts[0]["headers"]
            },
            body=b"".join(bodies),
        )

    def statement_from(response) -> dict[str, object]:
        return json.loads(
            b64d(response.headers["x-serverware-response-statement-b64"])
        )

    def verify(response, statement: dict[str, object]) -> None:
        authenticated_headers = [
            (name, value)
            for name, value in response.raw_headers
            if not name.lower().startswith(b"x-serverware-response-")
        ]
        headers_digest, header_count = response_headers_binding(
            authenticated_headers
        )
        if (
            statement.get("response_headers_sha256") != headers_digest
            or statement.get("response_header_count") != header_count
        ):
            raise AssertionError(
                "signed response statement did not bind exact response headers"
            )
        public_key = serialization.load_pem_public_key(
            response_public_key_info()["pem"].encode("ascii")
        )
        public_key.verify(
            b64d(
                response.headers["x-serverware-response-signature"].split(
                    ":", 1
                )[1]
            ),
            canonical_json(statement).encode("utf-8"),
        )

    try:
        captured_worker: dict[str, object] = {}

        def capture_plain_signing_inputs(**kwargs: object) -> dict[str, str]:
            captured_worker.update(kwargs)
            captured_worker["thread_id"] = threading.get_ident()
            return {
                "X-Serverware-Response-Test-Signature": "captured"
            }

        app_module._signed_control_plane_response_headers = (
            capture_plain_signing_inputs
        )
        captured_response = asyncio.run(
            signed_stream(
                nonce="captured-nonce",
                chunks=[b"captured-body"],
                source_headers={"X-Captured-Source": "preserved"},
            )
        )
        app_module._signed_control_plane_response_headers = (
            original_header_builder
        )
        expected_query = "code=oauth-code-secret&state=oauth-state-secret"
        captured_headers = captured_worker.get("response_headers")
        if (
            captured_worker.get("request_method") != "POST"
            or captured_worker.get("request_path") != "/api/bounded-response"
            or captured_worker.get("request_query") != expected_query
            or captured_worker.get("request_nonce") != "captured-nonce"
            or captured_worker.get("response_status_code") != 200
            or captured_worker.get("body") != b"captured-body"
            or not isinstance(captured_headers, list)
            or (b"x-captured-source", b"preserved")
            not in captured_headers
            or (b"content-type", b"application/octet-stream")
            not in captured_headers
            or (b"content-length", b"13") not in captured_headers
        ):
            raise AssertionError(
                f"signing worker inputs changed: {captured_worker}"
            )
        if captured_worker["thread_id"] == threading.get_ident():
            raise AssertionError("response signing remained on the event-loop thread")
        if any(
            isinstance(value, (Request, Response))
            for value in captured_worker.values()
        ):
            raise AssertionError(
                "response signing worker received a framework object"
            )
        if captured_response.body != b"captured-body":
            raise AssertionError("event-loop response construction changed the body")
        if (
            captured_response.headers.get(
                "x-serverware-response-test-signature"
            )
            != "captured"
        ):
            raise AssertionError("event-loop response lost signed worker headers")

        app_module._SIGNED_RESPONSE_MAX_BYTES = 64
        app_module.runtime_manifest_digest = lambda: context["runtime_manifest_digest"]
        app_module.release_provenance_digest = lambda: context["provenance_digest"]
        app_module.image_signatures_digest = lambda: context["image_signatures_digest"]
        app_module.source_tree_digest = lambda: context["source_tree_digest"]
        app_module.get_policy_snapshot = lambda: SimpleNamespace(
            hash=context["policy_bundle_digest"]
        )

        original_secret = b"original-response-secret"
        unconsumed_secret = b"unconsumed-response-secret"
        tail_observed = [False]
        nonce = "bounded-response-nonce"
        oversized = asyncio.run(
            signed_stream(
                nonce=nonce,
                chunks=[
                    original_secret + b"x" * (64 - len(original_secret)),
                    b"!",
                    unconsumed_secret,
                ],
                source_headers={"X-Original-Secret": "must-not-leave"},
                tail_observed=tail_observed,
            )
        )
        expected_body = b'{"detail":"signed response exceeds 8 MiB"}'
        if oversized.status_code != 503 or oversized.body != expected_body:
            raise AssertionError("oversized response did not become the bounded synthetic 503")
        if tail_observed[0]:
            raise AssertionError("oversized response iterator was drained after the size violation")
        if "x-original-secret" in oversized.headers:
            raise AssertionError("oversized response retained rejected source headers")
        if original_secret in oversized.body or unconsumed_secret in oversized.body:
            raise AssertionError("oversized response leaked rejected source bytes")

        statement = statement_from(oversized)
        statement_json = canonical_json(statement)
        expected_query = "code=oauth-code-secret&state=oauth-state-secret"
        if statement != {
            **statement,
            "version": "serverware.responseSignature/v3",
            "request": {
                "method": "POST",
                "path": "/api/bounded-response",
                "query_sha256": sha256_prefixed(expected_query.encode("utf-8")),
            },
            "status_code": 503,
            "body_sha256": sha256_prefixed(expected_body),
            "nonce": nonce,
            "context": context,
        }:
            raise AssertionError(f"synthetic response statement lost its bindings: {statement}")
        if (
            "oauth-code-secret" in statement_json
            or "oauth-state-secret" in statement_json
            or original_secret.decode("ascii") in statement_json
        ):
            raise AssertionError("synthetic response statement exposed rejected request or response secrets")
        verify(oversized, statement)

        missing_nonce = asyncio.run(signed_stream(nonce=None, chunks=[b"ok"]))
        if statement_from(missing_nonce)["nonce"] is not None:
            raise AssertionError("missing response nonce behavior changed")
        invalid_nonce_value = "not-valid nonce!"
        invalid_nonce = asyncio.run(
            signed_stream(nonce=invalid_nonce_value, chunks=[b"ok"])
        )
        invalid_statement = statement_from(invalid_nonce)
        if (
            invalid_nonce.status_code != 400
            or invalid_statement["nonce"] is not None
            or invalid_nonce.body
            != b'{"detail":"response nonce header is invalid or repeated"}'
        ):
            raise AssertionError(
                "invalid response nonce did not become a signed denial"
            )

        def signing_failure(_statement: dict[str, object]) -> dict[str, str]:
            raise RuntimeError("injected synthetic signing failure")

        app_module.response_signature_headers = signing_failure
        signing_failure_messages: list[dict[str, object]] = []
        try:
            asyncio.run(
                signed_stream(
                    nonce=nonce,
                    chunks=[b"x" * 65],
                    emitted_messages=signing_failure_messages,
                )
            )
        except RuntimeError as exc:
            if str(exc) != "injected synthetic signing failure":
                raise
        else:
            raise AssertionError("synthetic signing failure returned an unsigned response")
        if signing_failure_messages:
            raise AssertionError(
                "signing failure emitted an unsigned ASGI response"
            )
    finally:
        app_module._signed_control_plane_response_headers = (
            original_header_builder
        )
        app_module._SIGNED_RESPONSE_MAX_BYTES = original_limit
        for name, value in original_context_functions.items():
            setattr(app_module, name, value)


def exercise_middleware_blocking_offload() -> None:
    import serverware.app as app_module
    from fastapi import HTTPException
    from starlette.requests import Request
    from starlette.responses import Response

    original_csrf_validator = app_module.validate_csrf_request
    original_drain = app_module.db.drain_metadata_audit_outbox
    original_to_thread = app_module.asyncio.to_thread
    original_drain_slots = app_module._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS

    def request_for(method: str) -> Request:
        return Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": "/api/mutation",
                "raw_path": b"/api/mutation",
                "query_string": b"",
                "headers": [],
                "client": ("192.0.2.1", 12345),
                "server": ("serverware.test", 443),
            }
        )

    async def call_next(_request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    try:
        async def reject_to_thread(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("CSRF rejection dispatched blocking work")

        def reject_csrf(_request: Request) -> None:
            raise HTTPException(status_code=403, detail="rejected")

        app_module.validate_csrf_request = reject_csrf
        app_module.asyncio.to_thread = reject_to_thread
        rejected = asyncio.run(
            app_module.csrf_middleware(request_for("POST"), call_next)
        )
        if rejected.status_code != 403:
            raise AssertionError("CSRF rejection behavior changed")

        app_module.validate_csrf_request = lambda _request: None
        app_module.asyncio.to_thread = original_to_thread
        drain_calls: list[tuple[int, int]] = []

        def drain_outbox(*, limit: int) -> None:
            drain_calls.append((limit, threading.get_ident()))

        app_module.db.drain_metadata_audit_outbox = drain_outbox
        app_module._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS = (
            asyncio.BoundedSemaphore(1)
        )
        caller_thread_id = threading.get_ident()
        response = asyncio.run(
            app_module.csrf_middleware(request_for("POST"), call_next)
        )
        if (
            response.status_code != 200
            or len(drain_calls) != 1
            or drain_calls[0][0] != 100
        ):
            raise AssertionError(
                f"metadata audit outbox dispatch changed: {drain_calls}"
            )
        if drain_calls[0][1] == caller_thread_id:
            raise AssertionError(
                "metadata audit outbox drain remained on the event-loop thread"
            )

        drain_calls.clear()
        response = asyncio.run(
            app_module.csrf_middleware(request_for("GET"), call_next)
        )
        if response.status_code != 200 or drain_calls:
            raise AssertionError("safe method unexpectedly drained the audit outbox")

        def failing_drain(*, limit: int) -> None:
            if limit != 100:
                raise AssertionError("metadata audit drain limit changed")
            raise RuntimeError("synthetic outbox failure")

        app_module.db.drain_metadata_audit_outbox = failing_drain
        response = asyncio.run(
            app_module.csrf_middleware(request_for("POST"), call_next)
        )
        if response.status_code != 200:
            raise AssertionError("best-effort audit drain failure changed the response")

        async def exercise_cancellation_capacity() -> None:
            first_started = asyncio.Event()
            first_release = asyncio.Event()
            second_started = asyncio.Event()

            def first_worker() -> str:
                return "first"

            def second_worker() -> str:
                return "second"

            async def controlled_to_thread(
                function: object, *_args: object, **_kwargs: object
            ) -> str:
                if function is first_worker:
                    first_started.set()
                    await first_release.wait()
                    return "first"
                if function is second_worker:
                    second_started.set()
                    return "second"
                raise AssertionError("unexpected bounded worker")

            app_module.asyncio.to_thread = controlled_to_thread
            slots = asyncio.BoundedSemaphore(1)
            first = asyncio.create_task(
                app_module._run_bounded_blocking(slots, first_worker)
            )
            await first_started.wait()
            first.cancel()
            try:
                await first
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("bounded worker caller was not cancelled")

            second = asyncio.create_task(
                app_module._run_bounded_blocking(slots, second_worker)
            )
            await asyncio.sleep(0)
            if second_started.is_set():
                raise AssertionError(
                    "cancelled caller released capacity before its worker exited"
                )
            first_release.set()
            if await second != "second" or not second_started.is_set():
                raise AssertionError("bounded worker capacity was not released")

        asyncio.run(exercise_cancellation_capacity())
    finally:
        app_module.validate_csrf_request = original_csrf_validator
        app_module.db.drain_metadata_audit_outbox = original_drain
        app_module.asyncio.to_thread = original_to_thread
        app_module._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS = original_drain_slots


def exercise_exported_asgi_signing_boundary() -> None:
    import serverware.app as app_module
    from starlette.responses import Response, StreamingResponse

    original_header_builder = (
        app_module._signed_control_plane_response_headers
    )
    original_buffer_slots = app_module._SIGNED_RESPONSE_BUFFER_SLOTS
    original_admission_seconds = (
        app_module._SIGNED_RESPONSE_BUFFER_ADMISSION_SECONDS
    )
    original_route_count = len(app_module._fastapi_app.router.routes)
    normal_path = "/__serverware_test__/signed-boundary"
    failure_path = "/__serverware_test__/endpoint-failure"
    iterator_failure_path = "/__serverware_test__/iterator-failure"
    invalid_no_body_path = "/__serverware_test__/invalid-no-body"
    partial_secret = b"partial-response-must-not-escape"
    normal_calls: list[bool] = []

    async def normal_endpoint() -> Response:
        normal_calls.append(True)
        response = Response(content=b"normal-response")
        response.raw_headers.extend(
            [
                (b"set-cookie", b"first=one; Path=/"),
                (b"set-cookie", b"second=two; Path=/"),
                (b"x-serverware-response-signature", b"downstream-forgery"),
            ]
        )
        return response

    async def endpoint_failure() -> Response:
        raise RuntimeError("synthetic endpoint failure")

    async def iterator_failure() -> StreamingResponse:
        async def body_iterator():
            yield partial_secret
            raise RuntimeError("synthetic response iterator failure")

        return StreamingResponse(
            body_iterator(),
            media_type="application/octet-stream",
        )

    async def invalid_no_body() -> Response:
        return Response(content=b"forbidden-body", status_code=204)

    async def invoke(
        path: str,
        *,
        duplicate_nonce: bool = False,
        method: str = "GET",
    ) -> tuple[Exception | None, list[dict[str, object]]]:
        request_delivered = False
        request_finished = asyncio.Event()
        messages: list[dict[str, object]] = []

        async def receive():
            nonlocal request_delivered
            if not request_delivered:
                request_delivered = True
                return {
                    "type": "http.request",
                    "body": b"",
                    "more_body": False,
                }
            await request_finished.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            copied = dict(message)
            if message["type"] == "http.response.start":
                copied["headers"] = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                copied["body"] = bytes(message.get("body", b""))
            messages.append(copied)

        error = None
        try:
            request_headers = [
                (b"host", b"serverware.test"),
                (
                    b"x-serverware-response-nonce",
                    b"exported-boundary-test",
                ),
            ]
            if duplicate_nonce:
                request_headers.append(
                    (
                        b"x-serverware-response-nonce",
                        b"ambiguous-second-value",
                    )
                )
            await app_module.app(
                {
                    "type": "http",
                    "asgi": {"version": "3.0", "spec_version": "2.3"},
                    "http_version": "1.1",
                    "method": method,
                    "scheme": "https",
                    "path": path,
                    "raw_path": path.encode("ascii"),
                    "query_string": b"",
                    "root_path": "",
                    "headers": request_headers,
                    "client": ("192.0.2.1", 12345),
                    "server": ("serverware.test", 443),
                },
                receive,
                send,
            )
        except Exception as exc:
            error = exc
        finally:
            request_finished.set()
        return error, messages

    def successful_signer(**kwargs: object) -> dict[str, str]:
        source_headers = kwargs.get("response_headers")
        if not isinstance(source_headers, list):
            raise AssertionError(
                "exported signing boundary did not pass raw headers"
            )
        signing_inputs.append(dict(kwargs))
        return {"X-Serverware-Response-Test-Signed": "yes"}

    def failing_signer(**_kwargs: object) -> dict[str, str]:
        raise RuntimeError("synthetic signer failure")

    def signed_response(
        messages: list[dict[str, object]],
        *,
        expected_status: int,
    ) -> bytes:
        starts = [
            (index, message)
            for index, message in enumerate(messages)
            if message["type"] == "http.response.start"
        ]
        bodies = [
            (index, message)
            for index, message in enumerate(messages)
            if message["type"] == "http.response.body"
        ]
        if len(starts) != 1 or not bodies:
            raise AssertionError(
                f"exported ASGI response framing changed: {messages}"
            )
        start_index, start = starts[0]
        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in start["headers"]
        }
        if (
            int(start["status"]) != expected_status
            or headers.get("x-serverware-response-test-signed") != "yes"
        ):
            raise AssertionError(
                f"exported ASGI response was not signed: {messages}"
            )
        if any(index < start_index for index, _message in bodies):
            raise AssertionError(
                "exported ASGI body preceded its signed response start"
            )
        return b"".join(
            bytes(message.get("body", b""))
            for _index, message in bodies
        )

    try:
        signing_inputs: list[dict[str, object]] = []
        app_module._fastapi_app.add_api_route(
            normal_path,
            normal_endpoint,
            methods=["GET", "HEAD"],
        )
        app_module._fastapi_app.add_api_route(
            failure_path,
            endpoint_failure,
            methods=["GET"],
        )
        app_module._fastapi_app.add_api_route(
            iterator_failure_path,
            iterator_failure,
            methods=["GET"],
        )
        app_module._fastapi_app.add_api_route(
            invalid_no_body_path,
            invalid_no_body,
            methods=["GET"],
        )

        app_module._signed_control_plane_response_headers = failing_signer
        normal_error, normal_messages = asyncio.run(invoke(normal_path))
        if (
            not isinstance(normal_error, RuntimeError)
            or str(normal_error) != "synthetic signer failure"
            or normal_messages
        ):
            raise AssertionError(
                "failing signer emitted through the exported ASGI boundary"
            )

        app_module._signed_control_plane_response_headers = successful_signer
        normal_error, normal_messages = asyncio.run(invoke(normal_path))
        if normal_error is not None:
            raise AssertionError(
                f"normal signed response failed: {normal_error}"
            )
        if signed_response(normal_messages, expected_status=200) != b"normal-response":
            raise AssertionError("normal signed response body changed")
        normal_start = next(
            message
            for message in normal_messages
            if message["type"] == "http.response.start"
        )
        normal_headers = list(normal_start["headers"])
        cookies = [
            value
            for name, value in normal_headers
            if name.lower() == b"set-cookie"
        ]
        if cookies != [
            b"first=one; Path=/",
            b"second=two; Path=/",
        ]:
            raise AssertionError(
                f"repeated response headers were collapsed: {cookies}"
            )
        if any(
            name.lower() == b"x-serverware-response-signature"
            for name, _value in normal_headers
        ):
            raise AssertionError(
                "downstream response signature header escaped replacement"
            )

        head_error, head_messages = asyncio.run(
            invoke(normal_path, method="HEAD")
        )
        if head_error is not None:
            raise AssertionError(f"signed HEAD response failed: {head_error}")
        if signed_response(head_messages, expected_status=200) != b"":
            raise AssertionError("signed HEAD response emitted representation bytes")
        head_signing_input = signing_inputs[-1]
        if (
            head_signing_input.get("body") != b""
            or (b"content-length", b"15")
            not in head_signing_input.get("response_headers", [])
        ):
            raise AssertionError(
                "HEAD signature did not bind empty wire body and "
                "representation length"
            )

        calls_before_duplicate = len(normal_calls)
        duplicate_error, duplicate_messages = asyncio.run(
            invoke(normal_path, duplicate_nonce=True)
        )
        if duplicate_error is not None:
            raise AssertionError(
                f"duplicate response nonce was not signed: {duplicate_error}"
            )
        duplicate_body = signed_response(
            duplicate_messages,
            expected_status=400,
        )
        if (
            duplicate_body
            != b'{"detail":"response nonce header is invalid or repeated"}'
            or len(normal_calls) != calls_before_duplicate
        ):
            raise AssertionError(
                "duplicate response nonce reached the application or changed "
                "its signed denial"
            )

        no_body_error, no_body_messages = asyncio.run(
            invoke(invalid_no_body_path)
        )
        if no_body_error is None:
            raise AssertionError(
                "invalid no-body response framing was not re-raised"
            )
        if (
            signed_response(no_body_messages, expected_status=500)
            != b'{"detail":"internal server error"}'
        ):
            raise AssertionError(
                "invalid no-body response did not become a signed 500"
            )

        endpoint_error, endpoint_messages = asyncio.run(
            invoke(failure_path)
        )
        if endpoint_error is None:
            raise AssertionError(
                "unhandled endpoint failure was not re-raised"
            )
        endpoint_body = signed_response(
            endpoint_messages,
            expected_status=500,
        )
        if endpoint_body != b'{"detail":"internal server error"}':
            raise AssertionError(
                f"endpoint failure response changed: {endpoint_body!r}"
            )

        iterator_error, iterator_messages = asyncio.run(
            invoke(iterator_failure_path)
        )
        if iterator_error is None:
            raise AssertionError(
                "response iterator failure was not re-raised"
            )
        iterator_body = signed_response(
            iterator_messages,
            expected_status=500,
        )
        if (
            iterator_body != b'{"detail":"internal server error"}'
            or partial_secret in iterator_body
        ):
            raise AssertionError(
                f"partial iterator response escaped: {iterator_body!r}"
            )

        app_module._signed_control_plane_response_headers = failing_signer
        endpoint_signer_error, endpoint_signer_messages = asyncio.run(
            invoke(failure_path)
        )
        if (
            not isinstance(endpoint_signer_error, RuntimeError)
            or str(endpoint_signer_error) != "synthetic signer failure"
            or endpoint_signer_messages
        ):
            raise AssertionError(
                "endpoint and signer failure emitted an unsigned response"
            )

        app_module._SIGNED_RESPONSE_BUFFER_SLOTS = asyncio.BoundedSemaphore(1)
        awaitable_slot = app_module._SIGNED_RESPONSE_BUFFER_SLOTS.acquire()
        asyncio.run(awaitable_slot)
        app_module._SIGNED_RESPONSE_BUFFER_ADMISSION_SECONDS = 0.001
        admission_calls = len(normal_calls)
        admission_error, admission_messages = asyncio.run(invoke(normal_path))
        if (
            not isinstance(admission_error, RuntimeError)
            or str(admission_error)
            != "signed response buffering capacity is unavailable"
            or admission_messages
            or len(normal_calls) != admission_calls
        ):
            raise AssertionError(
                "response buffer admission overflow emitted bytes or "
                "entered the application"
            )
    finally:
        app_module._signed_control_plane_response_headers = (
            original_header_builder
        )
        app_module._SIGNED_RESPONSE_BUFFER_SLOTS = original_buffer_slots
        app_module._SIGNED_RESPONSE_BUFFER_ADMISSION_SECONDS = (
            original_admission_seconds
        )
        del app_module._fastapi_app.router.routes[original_route_count:]


def exercise_signed_only_uvicorn_boundary() -> None:
    from serverware.signed_http import (
        SignedOnlyHttpToolsProtocol,
        _SignedHttpToolsRequestResponseCycle,
        validate_signed_http_protocol,
    )
    from uvicorn import Config
    from uvicorn.server import ServerState

    def cycle(cycle_class, *, waiting_for_continue: bool = False):
        closed: list[bool] = []
        logged: list[str] = []
        instance = object.__new__(cycle_class)
        instance.waiting_for_100_continue = waiting_for_continue
        instance.logger = SimpleNamespace(
            warning=lambda message, *args, **kwargs: logged.append(str(message)),
            error=lambda message, *args, **kwargs: logged.append(str(message)),
        )
        instance.transport = SimpleNamespace(
            close=lambda: closed.append(True)
        )
        instance.scope = {"type": "http"}
        instance.receive = None
        instance.send = None
        instance.response_started = False
        instance.response_complete = False
        instance.disconnected = False
        instance.on_response = lambda: None
        return instance, closed, logged

    invoked: list[bool] = []

    async def failing_app(_scope, _receive, _send):
        invoked.append(True)
        raise RuntimeError("synthetic signing boundary failure")

    for cycle_class in (_SignedHttpToolsRequestResponseCycle,):
        failed_cycle, failed_closed, failed_logged = cycle(cycle_class)
        asyncio.run(failed_cycle.run_asgi(failing_app))
        if not failed_closed or not failed_logged or invoked != [True]:
            raise AssertionError(
                "signed-only Uvicorn cycle did not close on application failure"
            )

        invoked.clear()
        expect_cycle, expect_closed, expect_logged = cycle(
            cycle_class,
            waiting_for_continue=True,
        )
        asyncio.run(expect_cycle.run_asgi(failing_app))
        if (
            not expect_closed
            or not expect_logged
            or invoked
            or expect_cycle.response_started
        ):
            raise AssertionError(
                "signed-only Uvicorn cycle emitted or entered the app for "
                "Expect: 100-continue"
            )

    for protocol_class in (SignedOnlyHttpToolsProtocol,):
        protocol = object.__new__(protocol_class)
        protocol_closed: list[bool] = []
        protocol.logger = SimpleNamespace(
            warning=lambda _message, *args, **kwargs: None
        )
        protocol.transport = SimpleNamespace(
            close=lambda: protocol_closed.append(True)
        )
        protocol.send_400_response("synthetic parser failure")
        if protocol_closed != [True]:
            raise AssertionError(
                "signed-only Uvicorn protocol emitted an unsigned parser response"
            )

    try:
        validate_signed_http_protocol(limit_concurrency=1)
    except RuntimeError as exc:
        if "unsigned concurrency response" not in str(exc):
            raise AssertionError(
                f"signed protocol preflight failed for the wrong reason: {exc}"
            ) from exc
    else:
        raise AssertionError(
            "signed protocol preflight accepted Uvicorn concurrency responses"
        )

    class RecordingTransport(asyncio.Transport):
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.closed = False
            self.reading_paused = False

        def get_extra_info(self, name, default=None):
            if name == "peername":
                return ("192.0.2.10", 12345)
            if name == "sockname":
                return ("192.0.2.20", 8443)
            return default

        def is_closing(self) -> bool:
            return self.closed

        def write(self, data) -> None:
            if not self.closed:
                self.writes.append(bytes(data))

        def close(self) -> None:
            self.closed = True

        def pause_reading(self) -> None:
            self.reading_paused = True

        def resume_reading(self) -> None:
            self.reading_paused = False

    async def protocol_fixture(application):
        loop = asyncio.get_running_loop()
        config = Config(
            app=application,
            http=SignedOnlyHttpToolsProtocol,
            ws="none",
            lifespan="off",
            log_config=None,
            access_log=False,
            server_header=False,
            date_header=False,
            proxy_headers=False,
        )
        config.load()
        server_state = ServerState()
        server_state.default_headers = []
        protocol = SignedOnlyHttpToolsProtocol(
            config=config,
            server_state=server_state,
            app_state={},
            _loop=loop,
        )
        transport = RecordingTransport()
        protocol.connection_made(transport)
        return protocol, transport, server_state

    async def exercise_protocol_bytes() -> None:
        called_paths: list[str] = []

        async def signed_application(scope, receive, send):
            called_paths.append(str(scope["path"]))
            await receive()
            body = str(scope["path"]).encode("ascii")
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"x-serverware-test-signed", b"yes"),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": body,
                    "more_body": False,
                }
            )

        protocol, transport, state = await protocol_fixture(
            signed_application
        )
        protocol.data_received(
            b"GET /first HTTP/1.1\r\nHost: serverware.test\r\n\r\n"
            b"GET /second HTTP/1.1\r\nHost: serverware.test\r\n\r\n"
        )
        if not isinstance(
            protocol.cycle, _SignedHttpToolsRequestResponseCycle
        ) or any(
            not isinstance(item[0], _SignedHttpToolsRequestResponseCycle)
            for item in protocol.pipeline
        ):
            raise AssertionError(
                "httptools protocol created a stock unsigned response cycle"
            )
        for _attempt in range(20):
            await asyncio.sleep(0)
            if state.total_requests == 2:
                break
        wire = b"".join(transport.writes)
        if (
            state.total_requests != 2
            or called_paths != ["/first", "/second"]
            or wire.count(b"HTTP/1.1 200 OK\r\n") != 2
            or wire.count(b"x-serverware-test-signed: yes\r\n") != 2
            or b"Internal Server Error" in wire
            or b"100 Continue" in wire
        ):
            raise AssertionError(
                f"signed pipelined protocol output changed: {wire!r}"
            )

        async def failing_application(_scope, _receive, _send):
            raise RuntimeError("synthetic top-level signer failure")

        failing_protocol, failing_transport, _state = await protocol_fixture(
            failing_application
        )
        failing_protocol.data_received(
            b"GET /fail HTTP/1.1\r\nHost: serverware.test\r\n\r\n"
        )
        for _attempt in range(5):
            await asyncio.sleep(0)
        if not failing_transport.closed or failing_transport.writes:
            raise AssertionError(
                "top-level signer failure emitted Uvicorn fallback bytes"
            )

        expect_calls: list[bool] = []

        async def expect_application(_scope, _receive, _send):
            expect_calls.append(True)

        expect_protocol, expect_transport, _state = await protocol_fixture(
            expect_application
        )
        expect_protocol.data_received(
            b"POST /expect HTTP/1.1\r\n"
            b"Host: serverware.test\r\n"
            b"Content-Length: 1\r\n"
            b"Expect: 100-continue\r\n\r\n"
        )
        for _attempt in range(5):
            await asyncio.sleep(0)
        if (
            not expect_transport.closed
            or expect_transport.writes
            or expect_calls
        ):
            raise AssertionError(
                "Expect: 100-continue did not terminate without unsigned bytes"
            )

        upgrade_protocol, upgrade_transport, _state = await protocol_fixture(
            signed_application
        )
        upgrade_protocol.data_received(
            b"GET /upgrade HTTP/1.1\r\n"
            b"Host: serverware.test\r\n"
            b"Connection: Upgrade\r\n"
            b"Upgrade: websocket\r\n\r\n"
        )
        if not upgrade_transport.closed or upgrade_transport.writes:
            raise AssertionError(
                "HTTP upgrade did not terminate without unsigned bytes"
            )

        malformed_protocol, malformed_transport, _state = (
            await protocol_fixture(signed_application)
        )
        malformed_protocol.data_received(b"not-http\r\n\r\n")
        if not malformed_transport.closed or malformed_transport.writes:
            raise AssertionError(
                "malformed HTTP emitted an unsigned parser response"
            )

    asyncio.run(exercise_protocol_bytes())


def fixture_sigstore(
    key: Ed25519PrivateKey,
    key_id: str,
    public_key_pem: str,
    statement: dict[str, object],
) -> dict[str, object]:
    statement_digest = verifier.sha256_prefixed_json(statement)
    signature = "cosign-fixture-ed25519:" + b64e(
        key.sign(verifier.canonical_json(statement).encode("utf-8"))
    )
    proof = {
        "treeSize": 1,
        "logIndex": 0,
        "rootHash": "sha256:" + "d" * 64,
        "hashes": [],
    }
    transparency = {
        "log_id": "sha256:" + "e" * 64,
        "log_index": 0,
        "integrated_time": 1_789_000_000,
        "entry_uuid": "entry-test",
        "inclusion_proof": proof,
    }
    return {
        "ok": True,
        "provider": "cosign",
        "statement_digest": statement_digest,
        "signature": signature,
        "key_provider": {"type": "test", "key_id": key_id},
        "transparency": transparency,
        "bundle": {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "sha256",
                    "digest": statement_digest.split(":", 1)[1],
                },
                "signature": signature,
            },
            "verificationMaterial": {
                "publicKey": public_key_pem,
                "tlogEntries": [
                    {
                        "entryUUID": "entry-test",
                        "inclusionProof": proof,
                        "integratedTime": 1_789_000_000,
                        "logId": {"keyId": "sha256:" + "e" * 64},
                        "logIndex": 0,
                    }
                ],
            },
        },
    }


def signed_bundle_fixture(
    key: Ed25519PrivateKey,
    key_id: str,
    public_key_pem: str,
    provenance: dict[str, object],
    provenance_digest: str,
    release_key_id: str,
) -> dict[str, object]:
    image_id = "sha256:" + "6" * 64
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://serverware.local/attestations/oci-image/v1",
        "subject": [{"name": "serverware", "digest": {"sha256": "6" * 64}}],
        "predicate": {
            "image_id": image_id,
            "repo_digests": [],
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_key_id,
            "source_tree_digest": provenance["source_tree"]["digest"],
            "compose_config_sha256": provenance["compose_config_sha256"],
            "sbom_cyclonedx_sha256": provenance["sbom"]["cyclonedx"]["sha256"],
            "sbom_cyclonedx_components": provenance["sbom"]["cyclonedx"]["components"],
        },
    }
    image_sigstore = fixture_sigstore(key, key_id, public_key_pem, statement)
    bundle: dict[str, object] = {
        "apiVersion": "serverware.imageSignatures/v1",
        "kind": "ImageSignatureBundle",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": release_key_id,
            "imageSigningKeyId": key_id,
            "sourceTreeDigest": provenance["source_tree"]["digest"],
            "composeConfigSha256": provenance["compose_config_sha256"],
            "sbomCyclonedxSha256": provenance["sbom"]["cyclonedx"]["sha256"],
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
        },
        "images": [
            {
                "service": "serverware",
                "image_id": image_id,
                "statement": statement,
                "statement_digest": verifier.sha256_prefixed_json(statement),
                "signature": image_sigstore["signature"],
                "sigstore": image_sigstore,
            }
        ],
    }
    normalized = verifier.normalized_image_signature_payload(bundle)
    bundle_sigstore = fixture_sigstore(key, key_id, public_key_pem, normalized)
    bundle["metadata"]["bundleSigstore"] = bundle_sigstore
    bundle["metadata"]["signature"] = bundle_sigstore["signature"]
    bundle["bundle_signature"] = bundle_sigstore
    bundle["image_signature_bundle_digest"] = verifier.sha256_prefixed_json(normalized)
    return bundle


def exercise_bundle_verification() -> None:
    release_key = Ed25519PrivateKey.generate()
    image_key = Ed25519PrivateKey.generate()
    release_public_pem = release_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    image_public_pem = image_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    release_key_id = sha256_prefixed(
        release_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    image_key_id = sha256_prefixed(
        image_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    provenance: dict[str, object] = {
        "source_tree": {"digest": "sha256:" + "5" * 64},
        "compose_config_sha256": "sha256:" + "7" * 64,
        "sbom": {
            "cyclonedx": {"sha256": "sha256:" + "8" * 64, "components": 2}
        },
        "images": {
            "serverware": {"image_id": "sha256:" + "6" * 64, "repo_digests": []}
        },
    }
    provenance_digest = verifier.sha256_prefixed_json(provenance)
    provenance_document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": release_key_id,
        "release_signing_public_key_pem": release_public_pem,
        "signature": "ed25519:"
        + b64e(release_key.sign(verifier.canonical_json(provenance).encode("utf-8"))),
    }
    verifier.verify_release_provenance(
        provenance_document,
        release_public_pem,
        release_key_id,
    )
    bundle = signed_bundle_fixture(
        image_key,
        image_key_id,
        image_public_pem,
        provenance,
        provenance_digest,
        release_key_id,
    )
    original_external = verifier.run_sigstore_verifier
    verifier.run_sigstore_verifier = lambda *_args, **_kwargs: None  # type: ignore[assignment]
    try:
        verifier.verify_image_signature_bundle(
            bundle,
            bundle["image_signature_bundle_digest"],
            provenance=provenance,
            provenance_digest=provenance_digest,
            release_signing_key_id=release_key_id,
            trusted_public_key_pem=image_public_pem,
            trusted_key_id=image_key_id,
            verify_command="test-verifier",
        )
        unsigned = json.loads(json.dumps(bundle))
        unsigned.pop("bundle_signature")
        try:
            verifier.verify_image_signature_bundle(
                unsigned,
                bundle["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=image_public_pem,
                trusted_key_id=image_key_id,
                verify_command="test-verifier",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unsigned image signature bundle was accepted")

        wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        try:
            verifier.verify_image_signature_bundle(
                bundle,
                bundle["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=wrong_key,
                trusted_key_id="sha256:" + "9" * 64,
                verify_command="test-verifier",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("image signature bundle accepted the wrong trust root")

        rebound = json.loads(json.dumps(bundle))
        rebound["metadata"]["provenanceDigest"] = "sha256:" + "0" * 64
        normalized = verifier.normalized_image_signature_payload(rebound)
        bundle_sigstore = fixture_sigstore(image_key, image_key_id, image_public_pem, normalized)
        rebound["metadata"]["bundleSigstore"] = bundle_sigstore
        rebound["metadata"]["signature"] = bundle_sigstore["signature"]
        rebound["bundle_signature"] = bundle_sigstore
        rebound["image_signature_bundle_digest"] = verifier.sha256_prefixed_json(normalized)
        try:
            verifier.verify_image_signature_bundle(
                rebound,
                rebound["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=image_public_pem,
                trusted_key_id=image_key_id,
                verify_command="test-verifier",
            )
        except ValueError as exc:
            if "provenanceDigest mismatch" not in str(exc):
                raise AssertionError(f"cross-binding failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("image signature bundle accepted another provenance digest")
    finally:
        verifier.run_sigstore_verifier = original_external  # type: ignore[assignment]

    with tempfile.TemporaryDirectory() as tmp_raw:
        private_path = Path(tmp_raw) / "trusted.pem"
        private_path.write_bytes(
            image_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        _key, _pem, loaded_id = verifier.trusted_ed25519_key(
            private_path, "test trust root"
        )
        if loaded_id != image_key_id:
            raise AssertionError("trusted key loader changed the SPKI identity")


def exercise_verifier_state_v3_wire_contract() -> None:
    from jsonschema import Draft202012Validator, ValidationError

    import attestation_verifier_state_service as state_service
    import test_verify_nitro_tee as state_fixtures

    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "attestation-verifier-state-service.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture = state_fixtures.NonceAuthorityVerifierStateServiceFixtures(
        methodName=(
            "test_lost_prepare_response_recovers_exact_prepared_operation"
        )
    )
    fixture.setUp()
    try:
        transition = fixture.prepare_transition()
        prior_read = fixture.last_read_response
        receipt = fixture.service.commit(
            transition["request"],
            now=fixture.now + 1,
        )
        recovery_request = {
            "apiVersion": state_service.RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": transition["recoveryIdentity"],
            "recoveryIdentitySha256": verifier.sha256_json(
                transition["recoveryIdentity"]
            ),
            "recoveryKeySha256":
            transition["recoveryKeySha256"],
        }
        recovery_response = fixture.service.recover(
            recovery_request,
            now=fixture.now + 2,
        )
        documents = (
            {
                "apiVersion": state_service.READ_REQUEST_VERSION,
                "assuranceSha256": fixture.assurance_sha256,
            },
            prior_read,
            transition["prepareRequest"],
            transition["request"],
            receipt,
            recovery_request,
            recovery_response,
        )
        for document in documents:
            validator.validate(document)

        hostile_documents = (
            {
                **transition["request"],
                "apiVersion":
                "serverware.nonceAuthorityVerifierStateCommitRequest/v2",
            },
            {
                **recovery_request,
                "apiVersion":
                "serverware.attestationVerifierStateRecoveryRequest/v1",
            },
            {
                **recovery_response,
                "unexpected": False,
            },
        )
        for document in hostile_documents:
            try:
                validator.validate(document)
            except ValidationError:
                pass
            else:
                raise AssertionError(
                    "verifier-state schema accepted protocol drift"
                )

        substituted_recovery = {
            **recovery_request,
            "recoveryIdentity": {
                **recovery_request["recoveryIdentity"],
                "requestBodySha256": verifier.sha256(
                    b"substituted-request"
                ),
            },
        }
        validator.validate(substituted_recovery)
        try:
            fixture.service.recover(
                substituted_recovery,
                now=fixture.now + 2,
            )
        except state_service.ContractError:
            pass
        else:
            raise AssertionError(
                "verifier-state runtime accepted operation substitution"
            )
    finally:
        fixture.doCleanups()


def main() -> None:
    exercise_response_identity_publication()
    exercise_middleware_blocking_offload()
    exercise_exported_asgi_signing_boundary()
    exercise_signed_only_uvicorn_boundary()
    exercise_bounded_control_plane_response_signing()
    exercise_verifier_state_v3_wire_contract()
    body = b'{"ok":true}'
    context = {
        "runtime_manifest_digest": "sha256:" + "1" * 64,
        "policy_bundle_digest": "sha256:" + "2" * 64,
        "provenance_digest": "sha256:" + "3" * 64,
        "image_signatures_digest": "sha256:" + "4" * 64,
        "source_tree_digest": "sha256:" + "5" * 64,
    }
    sensitive_query = "code=oauth-code-canary&state=oauth-state-canary"
    statement = response_statement(
        method="GET",
        path="/attestation",
        query=sensitive_query,
        status_code=200,
        body=body,
        response_headers=[
            (b"content-length", str(len(body)).encode("ascii")),
            (b"content-type", b"application/json"),
        ],
        nonce="client-nonce",
        context=context,
    )
    headers = response_signature_headers(statement)
    try:
        response_headers_binding(
            [
                (b"content-type", b"application/json"),
                (b"Content-Type", b"text/plain"),
            ]
        )
    except ValueError as exc:
        if "duplicate singleton" not in str(exc):
            raise AssertionError(
                f"duplicate singleton header failed for the wrong reason: {exc}"
            ) from exc
    else:
        raise AssertionError(
            "response header binding accepted a duplicate singleton"
        )
    first_cookie_digest = response_headers_binding(
        [
            (b"set-cookie", b"first=one"),
            (b"set-cookie", b"second=two"),
        ]
    )[0]
    second_cookie_digest = response_headers_binding(
        [
            (b"set-cookie", b"second=two"),
            (b"set-cookie", b"first=one"),
        ]
    )[0]
    if first_cookie_digest == second_cookie_digest:
        raise AssertionError("response header binding lost repeated-field order")
    assert headers["X-Serverware-Response-Body-SHA256"] == sha256_prefixed(body)
    assert statement["request"]["query_sha256"] == sha256_prefixed(
        sensitive_query.encode("utf-8")
    )
    assert "query" not in statement["request"]
    assert "oauth-code-canary" not in canonical_json(statement)
    assert "oauth-state-canary" not in canonical_json(statement)
    assert statement["version"] == "serverware.responseSignature/v3"
    decoded = json.loads(b64d(headers["X-Serverware-Response-Statement-B64"]))
    assert decoded == statement
    public_key = serialization.load_pem_public_key(response_public_key_info()["pem"].encode("ascii"))
    public_key.verify(
        b64d(headers["X-Serverware-Response-Signature"].split(":", 1)[1]),
        canonical_json(statement).encode("utf-8"),
    )
    attestation = {
        **context,
        "response_signing_key_id": response_public_key_info()["spki_sha256"],
        "response_signing_public_key_pem": response_public_key_info()["pem"],
    }
    raw_headers = (
        ("Content-Length", str(len(body))),
        ("Content-Type", "application/json"),
        *tuple(headers.items()),
    )
    verifier.verify_response_signature(
        attestation,
        body,
        raw_headers,
        "client-nonce",
        method="GET",
        path="/attestation",
        query=sensitive_query,
        status=200,
    )
    for label, changed_headers, changed_status in (
        (
            "duplicate proof header",
            raw_headers
            + (
                (
                    "X-Serverware-Response-Signature",
                    headers["X-Serverware-Response-Signature"],
                ),
            ),
            200,
        ),
        (
            "detached body digest",
            tuple(
                (
                    name,
                    "sha256:" + "0" * 64
                    if name.lower()
                    == "x-serverware-response-body-sha256"
                    else value,
                )
                for name, value in raw_headers
            ),
            200,
        ),
        ("signed status", raw_headers, 201),
    ):
        try:
            verifier.verify_response_signature(
                attestation,
                body,
                changed_headers,
                "client-nonce",
                method="GET",
                path="/attestation",
                query=sensitive_query,
                status=changed_status,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"live response verifier accepted changed {label}"
            )
    substituted_attestation = dict(attestation)
    substituted_attestation["response_signing_public_key_pem"] = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    try:
        verifier.verify_response_signature(
            substituted_attestation,
            body,
            raw_headers,
            "client-nonce",
            method="GET",
            path="/attestation",
            query=sensitive_query,
            status=200,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "live response verifier accepted a substituted response key"
        )
    exercise_bundle_verification()
    print("codebase attestation response signature tests passed")


class SealedTerminalJournalBehavioralFixtures(unittest.TestCase):
    @staticmethod
    def _identity() -> dict[str, str]:
        return {
            "operationIdSha256": "11" * 32,
            "recoveryKeySha256": "22" * 32,
            "requestSha256": "33" * 32,
        }

    def test_sealed_reload_exact_recovery_rebind_and_retirement(self) -> None:
        import importlib
        import os
        import tempfile

        from serverware import attestation as attestation_module

        body = b'{"stable":"terminal-result"}'
        historical_tls = {
            "exporterSha256": "44" * 32,
            "peerSpkiSha256": "55" * 32,
            "connectionIdSha256": "66" * 32,
            "expiresAtUnix": 130,
        }
        current_tls = {
            "exporterSha256": "77" * 32,
            "peerSpkiSha256": "55" * 32,
            "connectionIdSha256": "88" * 32,
            "expiresAtUnix": 130,
        }
        proof = {
            "apiVersion": "fixture.proof/v1",
            "expiresAtUnix": 120,
            "value": "historical",
        }
        signature = "ed25519:AA"
        identity = self._identity()
        key = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            prepared_path = os.path.join(
                directory,
                (
                    attestation_module._terminal_journal_identity_key(identity)
                    + ".json"
                ),
            )
            with open(prepared_path, "wb") as prepared:
                prepared.write(b"plaintext-ephemeral-seed")
                prepared.flush()
                os.fsync(prepared.fileno())
            os.chmod(prepared_path, 0o600)

            stored = (
                attestation_module._public_evidence_terminal_journal_store(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                    historical_tls_binding=historical_tls,
                    response_body=body,
                    live_session_proof=proof,
                    live_session_signature=signature,
                    terminal_at_unix=100,
                )
            )
            replayed = (
                attestation_module._public_evidence_terminal_journal_store(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                    historical_tls_binding=historical_tls,
                    response_body=body,
                    live_session_proof=proof,
                    live_session_signature=signature,
                    terminal_at_unix=100,
                )
            )
            self.assertEqual(replayed, stored)
            with self.assertRaises(Exception):
                attestation_module._public_evidence_terminal_journal_store(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                    historical_tls_binding=historical_tls,
                    response_body=b'{"stable":"crossed-result"}',
                    live_session_proof=proof,
                    live_session_signature=signature,
                    terminal_at_unix=100,
                )
            self.assertFalse(os.path.exists(prepared_path))

            terminal_path = attestation_module._terminal_journal_path(
                directory,
                identity,
            )
            with open(terminal_path, "rb") as sealed_file:
                sealed_bytes = sealed_file.read()
            self.assertNotIn(body, sealed_bytes)
            self.assertNotIn(b"plaintext-ephemeral-seed", sealed_bytes)

            reloaded_module = importlib.reload(attestation_module)
            loaded = (
                reloaded_module._public_evidence_terminal_journal_load(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                )
            )
            self.assertEqual(loaded, stored)
            recovered = (
                reloaded_module
                ._public_evidence_terminal_journal_recover_delivery(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                    current_tls_binding=current_tls,
                    rebind_issued_at_unix=101,
                    response_signing_key_id="fixture-response-key",
                    sign_delivery_rebind=lambda _core: "ed25519:AA",
                )
            )
            self.assertEqual(recovered["responseBody"], body)
            self.assertEqual(recovered["liveSessionProof"], proof)
            self.assertEqual(recovered["liveSessionSignature"], signature)
            self.assertEqual(
                recovered["deliveryRebind"]["payload"][
                    "currentTlsBinding"
                ],
                current_tls,
            )
            self.assertEqual(
                recovered["deliveryRebind"]["payload"][
                    "rebindIssuedAtUnix"
                ],
                101,
            )
            self.assertNotIn(
                "deliveredAtUnix",
                recovered["deliveryRebind"]["payload"],
            )
            self.assertNotEqual(current_tls, historical_tls)

            evidence = {
                "apiVersion": (
                    "serverware.publicAttestationTerminalAuthorityEvidence/v1"
                ),
                "status": "aborted",
                "recoveryIdentity": identity,
                "terminalResultSha256": stored["terminalResultSha256"],
                "evidenceAtUnix": 102,
                "issuer": {
                    "provider": "fixture",
                    "keyId": "terminal-authority",
                },
                "signature": {
                    "algorithm": "Ed25519",
                    "signatureBase64url": "AA",
                },
            }
            reloaded_module._public_evidence_terminal_journal_retire(
                directory=directory,
                retained_sealing_key=key,
                recovery_identity=identity,
                terminal_authority_evidence=evidence,
                verify_terminal_authority_evidence=lambda value: (
                    value == evidence
                ),
            )
            self.assertFalse(os.path.exists(terminal_path))

    def test_cross_process_no_replace_idempotency_and_conflict(self) -> None:
        from serverware import attestation as attestation_module

        context = multiprocessing.get_context("fork")
        historical_tls = {
            "connectionIdSha256": "44" * 32,
            "expiresAtUnix": 130,
            "exporterSha256": "55" * 32,
            "peerSpkiSha256": "66" * 32,
        }
        proof = {
            "apiVersion": "fixture.proof/v1",
            "expiresAtUnix": 120,
            "value": "historical",
        }
        key = bytes(range(32))

        def race(
            directory: str,
            identity: dict[str, str],
            body: bytes,
            gate: object,
            outcomes: object,
        ) -> None:
            gate.wait()
            try:
                stored = (
                    attestation_module
                    ._public_evidence_terminal_journal_store(
                        directory=directory,
                        retained_sealing_key=key,
                        recovery_identity=identity,
                        historical_tls_binding=historical_tls,
                        response_body=body,
                        live_session_proof=proof,
                        live_session_signature="ed25519:AA",
                        terminal_at_unix=100,
                    )
                )
                outcomes.put(
                    (
                        "ok",
                        attestation_module
                        ._terminal_journal_canonical_bytes(stored),
                    )
                )
            except Exception as exc:
                outcomes.put(("error", type(exc).__name__))

        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            identity = self._identity()
            gate = context.Event()
            outcomes = context.Queue()
            workers = [
                context.Process(
                    target=race,
                    args=(
                        directory,
                        identity,
                        b'{"stable":"same"}',
                        gate,
                        outcomes,
                    ),
                )
                for _ in range(2)
            ]
            for worker in workers:
                worker.start()
            gate.set()
            for worker in workers:
                worker.join(5)
                self.assertEqual(worker.exitcode, 0)
            results = [outcomes.get(timeout=1) for _ in workers]
            self.assertEqual([item[0] for item in results], ["ok", "ok"])
            self.assertEqual(results[0][1], results[1][1])
            terminal_path = attestation_module._terminal_journal_path(
                directory,
                identity,
            )
            with open(terminal_path, "rb") as sealed:
                original_sealed_bytes = sealed.read()
            replayed = (
                attestation_module._public_evidence_terminal_journal_store(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=identity,
                    historical_tls_binding=historical_tls,
                    response_body=b'{"stable":"same"}',
                    live_session_proof=proof,
                    live_session_signature="ed25519:AA",
                    terminal_at_unix=100,
                )
            )
            with open(terminal_path, "rb") as sealed:
                self.assertEqual(sealed.read(), original_sealed_bytes)
            self.assertEqual(
                base64.urlsafe_b64decode(
                    replayed["responseBodyBase64url"]
                    + "="
                    * (-len(replayed["responseBodyBase64url"]) % 4)
                ),
                b'{"stable":"same"}',
            )
            lock_path = terminal_path.replace(
                ".terminal.json",
                ".terminal.lock",
            )
            lock_metadata = os.stat(lock_path, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(lock_metadata.st_mode))
            self.assertEqual(stat.S_IMODE(lock_metadata.st_mode), 0o600)
            self.assertEqual(lock_metadata.st_nlink, 1)
            self.assertEqual(lock_metadata.st_uid, os.geteuid())

            conflict_identity = {
                **identity,
                "operationIdSha256": "77" * 32,
            }
            conflict_gate = context.Event()
            conflict_outcomes = context.Queue()
            conflict_workers = [
                context.Process(
                    target=race,
                    args=(
                        directory,
                        conflict_identity,
                        body,
                        conflict_gate,
                        conflict_outcomes,
                    ),
                )
                for body in (
                    b'{"stable":"left"}',
                    b'{"stable":"right"}',
                )
            ]
            for worker in conflict_workers:
                worker.start()
            conflict_gate.set()
            for worker in conflict_workers:
                worker.join(5)
                self.assertEqual(worker.exitcode, 0)
            conflict_results = [
                conflict_outcomes.get(timeout=1)
                for _ in conflict_workers
            ]
            self.assertEqual(
                sorted(item[0] for item in conflict_results),
                ["error", "ok"],
            )
            winner = (
                attestation_module._public_evidence_terminal_journal_load(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=conflict_identity,
                )
            )
            winner_body = base64.urlsafe_b64decode(
                winner["responseBodyBase64url"]
                + "="
                * (-len(winner["responseBodyBase64url"]) % 4)
            )
            self.assertIn(
                winner_body,
                {b'{"stable":"left"}', b'{"stable":"right"}'},
            )

    def test_cross_process_distinct_identity_capacity_is_atomic(
        self,
    ) -> None:
        from serverware import attestation as attestation_module

        context = multiprocessing.get_context("fork")
        key = bytes(range(32))
        historical_tls = {
            "connectionIdSha256": "44" * 32,
            "expiresAtUnix": 130,
            "exporterSha256": "55" * 32,
            "peerSpkiSha256": "66" * 32,
        }
        proof = {
            "apiVersion": "fixture.proof/v1",
            "expiresAtUnix": 120,
            "value": "historical",
        }
        first_identity = self._identity()
        second_identity = {
            "operationIdSha256": "77" * 32,
            "recoveryKeySha256": "88" * 32,
            "requestSha256": "99" * 32,
        }

        def authority_evidence(
            document: dict[str, object],
            status: str,
            evidence_at_unix: int,
        ) -> dict[str, object]:
            return {
                "apiVersion": (
                    "serverware."
                    "publicAttestationTerminalAuthorityEvidence/v1"
                ),
                "status": status,
                "recoveryIdentity": document["recoveryIdentity"],
                "terminalResultSha256": document[
                    "terminalResultSha256"
                ],
                "evidenceAtUnix": evidence_at_unix,
                "issuer": {"provider": "fixture", "keyId": "fixture"},
                "signature": {
                    "algorithm": "Ed25519",
                    "signatureBase64url": "AA",
                },
            }

        def race(
            directory: str,
            identity: dict[str, str],
            body: bytes,
            gate: object,
            outcomes: object,
        ) -> None:
            gate.wait()
            try:
                stored = (
                    attestation_module
                    ._public_evidence_terminal_journal_store(
                        directory=directory,
                        retained_sealing_key=key,
                        recovery_identity=identity,
                        historical_tls_binding=historical_tls,
                        response_body=body,
                        live_session_proof=proof,
                        live_session_signature="ed25519:AA",
                        terminal_at_unix=100,
                        maximum_entries=1,
                        verify_terminal_authority_evidence=(
                            lambda _evidence: True
                        ),
                        terminal_authority_evidence_for=(
                            authority_evidence
                        ),
                        now_unix=100,
                    )
                )
                outcomes.put(
                    (
                        "ok",
                        identity,
                        attestation_module
                        ._terminal_journal_canonical_bytes(stored),
                    )
                )
            except Exception as exc:
                outcomes.put(("error", identity, type(exc).__name__))

        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            gate = context.Event()
            outcomes = context.Queue()
            workers = [
                context.Process(
                    target=race,
                    args=(
                        directory,
                        identity,
                        body,
                        gate,
                        outcomes,
                    ),
                )
                for identity, body in (
                    (first_identity, b'{"stable":"first"}'),
                    (second_identity, b'{"stable":"second"}'),
                )
            ]
            for worker in workers:
                worker.start()
            gate.set()
            for worker in workers:
                worker.join(5)
                self.assertEqual(worker.exitcode, 0)
            results = [
                outcomes.get(timeout=1) for _ in workers
            ]
            self.assertEqual(
                sorted(result[0] for result in results),
                ["error", "ok"],
            )
            retained_identities = (
                attestation_module
                ._public_evidence_terminal_journal_recovery_identities(
                    directory=directory,
                    maximum_entries=2,
                )
            )
            self.assertEqual(len(retained_identities), 1)
            winner = next(
                result for result in results if result[0] == "ok"
            )
            self.assertEqual(retained_identities[0], winner[1])
            inventory_lock = os.stat(
                os.path.join(directory, ".terminal.inventory.lock"),
                follow_symlinks=False,
            )
            self.assertTrue(stat.S_ISREG(inventory_lock.st_mode))
            self.assertEqual(stat.S_IMODE(inventory_lock.st_mode), 0o600)
            self.assertEqual(inventory_lock.st_nlink, 1)
            self.assertEqual(inventory_lock.st_uid, os.geteuid())

            winner_body = (
                b'{"stable":"first"}'
                if winner[1] == first_identity
                else b'{"stable":"second"}'
            )
            replayed = (
                attestation_module
                ._public_evidence_terminal_journal_store(
                    directory=directory,
                    retained_sealing_key=key,
                    recovery_identity=winner[1],
                    historical_tls_binding=historical_tls,
                    response_body=winner_body,
                    live_session_proof=proof,
                    live_session_signature="ed25519:AA",
                    terminal_at_unix=100,
                    maximum_entries=1,
                    verify_terminal_authority_evidence=(
                        lambda _evidence: True
                    ),
                    terminal_authority_evidence_for=authority_evidence,
                    now_unix=100,
                )
            )
            self.assertEqual(
                attestation_module
                ._terminal_journal_canonical_bytes(replayed),
                winner[2],
            )
            replacement_identity = {
                "operationIdSha256": "aa" * 32,
                "recoveryKeySha256": "bb" * 32,
                "requestSha256": "cc" * 32,
            }
            attestation_module._public_evidence_terminal_journal_store(
                directory=directory,
                retained_sealing_key=key,
                recovery_identity=replacement_identity,
                historical_tls_binding=historical_tls,
                response_body=b'{"stable":"replacement"}',
                live_session_proof={
                    **proof,
                    "expiresAtUnix": 150,
                },
                live_session_signature="ed25519:AA",
                terminal_at_unix=121,
                maximum_entries=1,
                verify_terminal_authority_evidence=(
                    lambda _evidence: True
                ),
                terminal_authority_evidence_for=authority_evidence,
                now_unix=121,
            )
            self.assertEqual(
                attestation_module
                ._public_evidence_terminal_journal_recovery_identities(
                    directory=directory,
                    maximum_entries=2,
                ),
                (replacement_identity,),
            )


if __name__ == "__main__":
    main()
