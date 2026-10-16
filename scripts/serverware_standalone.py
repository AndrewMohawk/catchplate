#!/usr/bin/env python3
"""Install and operate a separate host-trusted Serverware instance.

Build is explicit. Ordinary starts use the installed image pins and state, never
the current checkout, an implicit image pull, or newly generated credentials.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import shlex
import stat
import sys


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Build the paired application/proxy image once")
    build.add_argument("--tag", default="serverware-standalone:local")
    build.add_argument("--cached-binary", type=Path, help="Advanced: reuse a verified normal proxy artifact")
    build.add_argument("--compiler-inputs", type=Path, help="Advanced: matching compiler-input receipt")
    build.add_argument("--cached-app-image", help="Advanced: compatible cached dependency image")
    initialize = commands.add_parser("init", help="Prepare a new private installation; never replace existing state")
    initialize.add_argument("--config", type=Path, required=True, help="Nonsecret installation JSON")
    initialize.add_argument("--admin-password-file", type=Path,
                            help="Read the console password from a private file instead of prompting")
    tls = commands.add_parser("replace-tls", help="Replace the outer HTTPS certificate without replacing the proxy CA")
    tls.add_argument("--state-dir", type=Path, default=Path("/var/lib/serverware-standalone"))
    tls.add_argument("--certificate", type=Path, required=True, help="New PEM chain covering both configured hostnames")
    tls.add_argument("--private-key", type=Path, required=True, help="Matching private PEM key")
    for command, description in (
        ("start", "Start the installed app, proxy and HTTPS edge using retained state"),
        ("status", "Inspect this installation without starting or changing anything"),
        ("stop", "Stop this installation without deleting state, keys or credentials"),
    ):
        child = commands.add_parser(command, help=description)
        child.add_argument("--state-dir", type=Path, default=Path("/var/lib/serverware-standalone"))
        if command == "start":
            child.add_argument("--timeout", type=int, default=120,
                               help="Maximum readiness wait in seconds (default: 120)")
    for child in commands.choices.values():
        child.add_argument("--json", action="store_true", help="Print a nonsecret machine-readable result")
    return root


def password_file(path: Path) -> bytes:
    """Read an explicitly selected private regular file, without following links."""
    from operator_install.config import InstallError

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        owners = {os.geteuid()}
        if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
            owners.add(int(os.environ["SUDO_UID"]))
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
                or before.st_uid not in owners or not 1 <= before.st_size <= 4096):
            raise InstallError("Password file must be a private, owned regular file with mode 0600 or 0400.")
        value = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        if (len(value) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise InstallError("Password file changed while being read; nothing was initialized.")
    finally:
        os.close(descriptor)
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if not value or any(character in value for character in (b"\x00", b"\n", b"\r")):
        raise InstallError("Password file must contain one nonempty password, without embedded line breaks.")
    return value


def console_password(path: Path | None) -> bytes:
    from operator_install.config import InstallError

    if path is not None:
        return password_file(path)
    if not sys.stdin.isatty():
        raise InstallError("Use an interactive terminal or --admin-password-file; passwords are never command-line values.")
    value = getpass.getpass("Choose the console password: ")
    confirmation = getpass.getpass("Confirm the console password: ")
    if value != confirmation:
        raise InstallError("Passwords did not match; nothing was initialized.")
    return value.encode("utf-8")


def dispatch(args: argparse.Namespace) -> dict:
    from operator_install.config import InstallError

    if args.command == "build":
        selected = (args.cached_binary is not None, args.compiler_inputs is not None,
                    args.cached_app_image is not None)
        if any(selected) and not all(selected):
            raise InstallError("Cached builds require --cached-binary, --compiler-inputs and --cached-app-image together.")
        from operator_install.build import build
        return build(Path(__file__).resolve().parents[1], args.tag,
                     cached_binary=args.cached_binary, compiler_inputs=args.compiler_inputs,
                     cached_app_image=args.cached_app_image)
    if args.command == "init":
        # Validate public configuration before asking for a private password.
        from operator_install.config import load_config
        from operator_install.bootstrap import initialize
        load_config(args.config)
        password = console_password(args.admin_password_file)
        try:
            return initialize(args.config, password)
        finally:
            password = b""
    if args.command == "replace-tls":
        from operator_install.tls import replace_tls
        return replace_tls(args.state_dir, args.certificate, args.private_key)
    from operator_install import lifecycle
    if args.command == "start":
        if not 5 <= args.timeout <= 600:
            raise InstallError("Readiness timeout must be between 5 and 600 seconds.")
        return lifecycle.start(args.state_dir, timeout=args.timeout)
    return getattr(lifecycle, args.command)(args.state_dir)


def show(result: dict, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
        return
    print("Serverware:", result.get("status") or result.get("phase") or result.get("operation", "ready"))
    for label, key in (("Instance", "project_name"), ("State", "state_dir"),
                       ("Console", "console_origin"), ("Proxy", "proxy_origin"), ("Image", "image_id")):
        if result.get(key):
            print(f"{label}: {result[key]}")
    for service, value in result.get("services", {}).items():
        print(f"{service}: {json.dumps(value, sort_keys=True) if isinstance(value, dict) else value}")
    if result.get("operation") == "init":
        command = ["sudo", "python3", "scripts/serverware_standalone.py", "start"]
        if result.get("state_dir") != "/var/lib/serverware-standalone":
            command.extend(["--state-dir", result["state_dir"]])
        print("Next: " + shlex.join(command))
        print("The console uses the administrator password you just supplied.")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    from operator_install.config import InstallError

    if not args.json:
        if args.command == "build":
            print("Checking build inputs. The first source build may take several minutes; later starts do not rebuild.", file=sys.stderr, flush=True)
        elif args.command == "start":
            print(f"Starting the installed instance (up to {args.timeout} seconds). No build or image download.", file=sys.stderr, flush=True)
    diagnostic_path = None
    try:
        result = dispatch(args)
    except InstallError as error:
        message = str(error)
        diagnostic_path = getattr(error, "diagnostic_path", None)
    except OSError:
        message = "A required file or command could not be accessed. Check paths, private file permissions and Docker availability. Existing state was not deleted."
    except (KeyboardInterrupt, EOFError):
        message = "Interrupted. Existing state was not deleted; inspect status before retrying."
    else:
        show(result, as_json=args.json)
        return 0
    if args.json:
        print(json.dumps({"ok": False, "error": message,
            **({"diagnostic_path": diagnostic_path} if diagnostic_path else {})}), file=sys.stderr)
    else:
        print("Serverware: " + message, file=sys.stderr)
        if diagnostic_path:
            print("Private diagnostic file: " + diagnostic_path + " (inspect locally; it may contain sensitive details)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
