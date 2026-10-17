#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def make_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))


def run(args: list[str]) -> tuple[int, dict]:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_images_no_shell.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(result.stdout.decode("utf-8"))
    except Exception as exc:
        raise AssertionError(f"verifier returned non-JSON: {detail}") from exc
    return result.returncode, parsed


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean.tar"
        dirty = Path(tmp) / "dirty.tar"
        make_tar(clean, {"usr/bin/python3": b"python", "app/catchplate/app.py": b"print('ok')"})
        make_tar(dirty, {"bin/sh": b"shell", "usr/bin/python3": b"python"})

        code, parsed = run(["--rootfs-tar", str(clean)])
        assert code == 0 and parsed["ok"] is True, parsed

        code, parsed = run(["--rootfs-tar", str(dirty)])
        assert code != 0 and parsed["ok"] is False, parsed
        assert "/bin/sh" in json.dumps(parsed), parsed

        good_image = "registry.prod.catchplate.dev/catchplate/control@sha256:" + "a" * 64
        code, parsed = run(["--validate-refs-only", "--image", good_image])
        assert code == 0 and parsed["ok"] is True, parsed

        code, parsed = run(["--local-image-id", "sha256:" + "b" * 64])
        assert code != 0 and "image is not available locally" in json.dumps(parsed), parsed

        mutable = "registry.prod.catchplate.dev/catchplate/control:latest"
        code, parsed = run(["--validate-refs-only", "--image", mutable])
        assert code != 0 and "immutable" in json.dumps(parsed), parsed

    print(json.dumps({"ok": True, "production_images_no_shell": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
