#!/usr/bin/env python3
"""Inspect, or explicitly create, the fixed native pilot resource parents.

Only directory metadata and bounded immediate directory entries are read.
No project modules, supplied paths, configurations, keys, sockets, journals,
processes or readiness evidence are accepted or produced. Existing objects
are never chmod/chown'd, repaired, removed or adopted as runtime resources.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys

FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
ANCHORS = ("/", "/run", "/var", "/var/lib")
SHARED = ("/var/lib/serverware", "/var/lib/serverware/custody-generation")
ROLES = (
    "durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper",
)
LEAVES = (
    "/run/serverware-custody-business",
    "/run/serverware-shadow-retrieval",
    "/run/serverware-shadow-persistence",
    "/run/serverware-shadow-trusted-time",
    "/run/serverware-shadow-generation-install",
    "/run/serverware-shadow-commit-request",
    "/run/serverware-shadow-ingress-admission",
    "/run/serverware-shadow-terminal-append",
    "/run/serverware-shadow-dispatch-barrier",
    "/run/serverware-shadow-active-effect-barrier",
    "/run/serverware-shadow-active-effect-commit",
    "/run/serverware-native-pilot-bridge",
    "/var/lib/serverware/custody-business",
    "/var/lib/serverware/native-ledger-spool",
    "/var/lib/serverware/native-shadow-persistence",
    "/var/lib/serverware/native-shadow-generation-install",
    "/var/lib/serverware/native-pilot-bridge",
) + tuple("/var/lib/serverware/custody-generation/" + role for role in ROLES)
TARGETS = SHARED + LEAVES
PROFILES = ("legacy", "adopted-cold")
ADOPTED_SHARED = SHARED + ("/run/serverware",)
ADOPTED_ADDITIONS = (
    ("/run/serverware-custody-genesis", 0o711),
    ("/var/lib/serverware/custody-genesis", 0o711),
    ("/var/lib/serverware/publication-genesis-endpoints", 0o711),
    ("/run/serverware-shadow-publication-reconciliation", 0o711),
    ("/run/serverware/native-pilot-core-handoff", 0o700),
)
MAX_REPORT_BYTES = 32768


class Refused(Exception):
    def __init__(self, code, path):
        super().__init__(code)
        self.code, self.path = code, path


def require(condition, code, path):
    if not condition:
        raise Refused(code, path)


def structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def protected(info, path):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_mode & 0o022 == 0, "unprotected-directory", path)


def split(path):
    parent, name = path.rsplit("/", 1)
    return parent or "/", name


def selection(profile):
    """Select only a source-fixed inventory, never supplied paths or modes."""
    require(type(profile) is str and profile in PROFILES, "unknown-resource-profile", "/")
    if profile == "legacy":
        return SHARED, LEAVES, {path: 0o711 for path in LEAVES}
    leaves = LEAVES + tuple(path for path, _ in ADOPTED_ADDITIONS)
    modes = {path: 0o711 for path in LEAVES}
    modes.update(ADOPTED_ADDITIONS)
    return ADOPTED_SHARED, leaves, modes


def initial_report(profile, create):
    shared, leaves, _ = selection(profile)
    require(type(create) is bool, "invalid-resource-operation", "/")
    report = {"apiVersion": "serverware.nativePilotResourceRoots/v1",
              "operation": "create" if create else "inspect", "result": "refused",
              "directories": [{"path": path, "kind": "resource-parent" if path in leaves else "shared-container",
                               "state": "not-inspected"} for path in shared + leaves],
              "releaseAuthority": False, "liveReady": False, "runtimeResourcesCreated": False,
              "filesystemSupportVerified": False}
    if profile == "adopted-cold":
        report["apiVersion"] = "serverware.nativePilotResourceRoots/v2"
        report["profile"] = profile
    return report


class Roots:
    """Retain every actual ancestor and name while checking this finite graph."""

    def __init__(self, report, *, profile="legacy"):
        self.shared, self.leaves, self.leaf_modes = selection(profile)
        self.targets = self.shared + self.leaves
        self.nodes = {}
        self.records = {entry["path"]: entry for entry in report["directories"]}
        self.current = "/"

    def close(self):
        for fd, _ in reversed(tuple(self.nodes.values())):
            os.close(fd)
        self.nodes.clear()

    def record(self, path, state, info=None):
        value = self.records[path]
        value["state"] = state
        if info is not None:
            value.update(device=info.st_dev, inode=info.st_ino,
                         uid=info.st_uid, gid=info.st_gid,
                         mode=format(stat.S_IMODE(info.st_mode), "04o"))

    def retain(self, path, fd):
        try:
            info = os.fstat(fd)
            protected(info, path)
            if path in self.leaf_modes:
                require(stat.S_IMODE(info.st_mode) == self.leaf_modes[path], "resource-parent-mode-differs", path)
        except BaseException:
            os.close(fd)
            raise
        self.nodes[path] = (fd, structural(info))
        return info

    def recheck(self):
        for path, (fd, expected) in self.nodes.items():
            self.current = path
            info = os.fstat(fd)
            protected(info, path)
            require(structural(info) == expected, "retained-directory-changed", path)
            if path == "/":
                named = os.stat("/", follow_symlinks=False)
            else:
                parent, name = split(path)
                named = os.stat(name, dir_fd=self.nodes[parent][0], follow_symlinks=False)
            require(structural(named) == expected, "retained-name-changed", path)

    def population(self, path):
        """One entry suffices to refuse a leaf; the role container allows five."""
        fd, expected = self.nodes[path]
        scan = os.open(".", FLAGS, dir_fd=fd)  # Fresh OFD, not a shared directory offset.
        try:
            require(structural(os.fstat(scan)) == expected, "scan-directory-changed", path)
            with os.scandir(scan) as entries:
                if path in self.leaf_modes:
                    require(next(entries, None) is None, "resource-parent-not-empty", path)
                elif path == SHARED[1]:
                    names = set()
                    for entry in entries:
                        require(entry.name in ROLES and entry.name not in names,
                                "unexpected-generation-child", path)
                        names.add(entry.name)
                        require(len(names) <= len(ROLES), "generation-child-bound", path)
        finally:
            os.close(scan)

    def inspect(self):
        for path in ANCHORS + self.targets:
            self.current = path
            if path == "/":
                fd = os.open("/", FLAGS)
            else:
                parent, name = split(path)
                if parent not in self.nodes:
                    require(path in self.targets, "missing-required-system-ancestor", path)
                    self.record(path, "missing")
                    continue
                try:
                    fd = os.open(name, FLAGS, dir_fd=self.nodes[parent][0])
                except FileNotFoundError:
                    require(path in self.targets, "missing-required-system-ancestor", path)
                    self.record(path, "missing")
                    continue
            info = self.retain(path, fd)
            if path in self.targets:
                self.record(path, "present", info)
        # Inspect every existing target before creating anything. Shared
        # /var/lib/serverware and selected /run/serverware may contain unrelated
        # state and are not enumerated.
        self.recheck()
        self.check_populations()

    def check_populations(self):
        for path in (SHARED[1],) + self.leaves:
            if path in self.nodes:
                self.current = path
                self.population(path)
        self.recheck()

    def create_missing(self):
        # The standalone CLI has no threads. Restrict only new directories
        # during creation; no existing object's owner/mode is ever modified.
        previous_umask = os.umask(0o077)
        try:
            for path in self.targets:
                if path in self.nodes:
                    continue
                self.recheck()
                self.current = path
                parent, name = split(path)
                parent_fd = self.nodes[parent][0]
                mode = self.leaf_modes.get(path, 0o755)
                # EEXIST is an uncertainty/refusal, never permission to adopt
                # a path which appeared after the retained preflight.
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                self.record(path, "created-unconfirmed")
                fd = os.open(name, FLAGS, dir_fd=parent_fd)
                try:
                    info = os.fstat(fd)
                    protected(info, path)
                    require(stat.S_IMODE(info.st_mode) == 0o700, "new-directory-mode-differs", path)
                    require(structural(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                            == structural(info), "new-directory-name-changed", path)
                    os.fchmod(fd, mode)  # Only the new exclusive directory.
                    os.fsync(fd)
                    os.fsync(parent_fd)
                    require(stat.S_IMODE(os.fstat(fd).st_mode) == mode,
                            "new-directory-readback-differs", path)
                except BaseException:
                    os.close(fd)
                    raise
                info = self.retain(path, fd)
                self.record(path, "created", info)
                self.recheck()
                self.check_populations()
        finally:
            os.umask(previous_umask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", action="store_true",
                        help="create only missing fixed parent directories; preserve any partial result")
    parser.add_argument("--profile", choices=PROFILES, default="legacy",
                        help="select the fixed legacy inventory (default) or cold/adopted parent inventory")
    args = parser.parse_args()
    report = initial_report(args.profile, args.create)
    owner = Roots(report, profile=args.profile)
    code = 2
    try:
        require(sys.platform == "linux" and os.getresuid() == (0, 0, 0)
                and os.getresgid() == (0, 0, 0), "real-root-required", "/")
        owner.inspect()
        if args.create:
            owner.create_missing()
        owner.check_populations()
        complete = all(path in owner.nodes for path in owner.targets)
        report["result"] = "parents-present" if complete else "parents-missing"
        code = 0 if complete else 1
    except Refused as error:
        report["error"] = {"code": error.code, "path": error.path}
    except OSError as error:
        report["error"] = {"code": "filesystem-operation-failed", "path": owner.current,
                           "errno": error.errno}
    except KeyboardInterrupt:
        report["error"] = {"code": "interrupted-partial-state-preserved", "path": owner.current}
        code = 130
    finally:
        owner.close()
    raw = json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(raw.encode("ascii")) > MAX_REPORT_BYTES:
        raise RuntimeError("fixed resource-root report exceeds its bound")
    print(raw)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
