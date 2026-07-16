from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("SERVERWARE_DATA_DIR", str(Path(".tmp/test-codebase-attestation/data").resolve()))
os.environ.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY", None)
os.environ.pop("SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import serverware.response_identity as response_identity
from serverware.response_identity import canonical_json, response_public_key_info, response_signature_headers, response_statement

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


def main() -> None:
    exercise_response_identity_publication()
    body = b'{"ok":true}'
    context = {
        "runtime_manifest_digest": "sha256:" + "1" * 64,
        "policy_bundle_digest": "sha256:" + "2" * 64,
        "provenance_digest": "sha256:" + "3" * 64,
        "image_signatures_digest": "sha256:" + "4" * 64,
        "source_tree_digest": "sha256:" + "5" * 64,
    }
    statement = response_statement(
        method="GET",
        path="/attestation",
        query="nonce=test",
        status_code=200,
        body=body,
        nonce="client-nonce",
        context=context,
    )
    headers = response_signature_headers(statement)
    assert headers["X-Serverware-Response-Body-SHA256"] == sha256_prefixed(body)
    decoded = json.loads(b64d(headers["X-Serverware-Response-Statement-B64"]))
    assert decoded == statement
    public_key = serialization.load_pem_public_key(response_public_key_info()["pem"].encode("ascii"))
    public_key.verify(
        b64d(headers["X-Serverware-Response-Signature"].split(":", 1)[1]),
        canonical_json(statement).encode("utf-8"),
    )
    exercise_bundle_verification()
    print("codebase attestation response signature tests passed")


if __name__ == "__main__":
    main()
