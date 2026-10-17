"""Retained external-driver binding for the fixed ten-endpoint cohort.

Only an actual DriverBootstrap can produce this owner. Public originals do not
construct process ownership; Rust independently admits the three real rights.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from catchplate import native_shadow_guest_delivery as delivery

p = delivery.p
CONFIG_FIELDS = ("configurationSha256", "windowSha256", "observationSha256", "supervisorExecutableSha256")
ORIGINAL_FIELDS = ("apiVersion", "bindingSha256", "configurationSha256", "windowSha256", "observationSha256",
                   "supervisor", "driver", "executable")
PROCESS_FIELDS = ("processId", "startTimeTicks", "pidfdDevice", "pidfdInode")
EXE_FIELDS = ("device", "inode", "length", "sha256")
WINDOW_JOIN = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
               "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
_TOKEN = object()


def configuration(value):
    p.fields(value, CONFIG_FIELDS)
    for name in CONFIG_FIELDS:
        p.digest(value[name])
    return value


def original(value, selected):
    """Closed data checks only; no PIDFD or live-process authority."""
    configuration(selected)
    p.fields(value, ORIGINAL_FIELDS)
    p.require(value["apiVersion"] == "catchplate.nativeShadowEndpointDriverOriginal/v1")
    p.digest(value["bindingSha256"])
    for name in CONFIG_FIELDS[:3]:
        p.require(value[name] == selected[name])
    for name in ("supervisor", "driver"):
        item = p.fields(value[name], PROCESS_FIELDS)
        p.integer(item["processId"], minimum=2, maximum=(1 << 31) - 1)
        for field in PROCESS_FIELDS[1:]:
            p.integer(item[field], minimum=0 if field == "pidfdDevice" else 1, maximum=(1 << 64) - 1)
    p.require(value["supervisor"]["processId"] != value["driver"]["processId"])
    exe = p.fields(value["executable"], EXE_FIELDS)
    p.integer(exe["device"], minimum=0, maximum=(1 << 64) - 1)
    p.integer(exe["inode"], maximum=(1 << 64) - 1)
    p.integer(exe["length"], maximum=64 * 1024 * 1024)
    p.digest(exe["sha256"])
    return value


class EndpointDriver:
    def __init__(self, token, driver):
        p.require(token is _TOKEN)
        self.driver, self._fds, self._copies = driver, [], []
        self._closed = self._sent = False

    @classmethod
    def retain(cls, driver, selected, window):
        from catchplate.native_shadow_driver_bootstrap import DriverBootstrap
        from catchplate import native_shadow_proof_cohort_control as mechanics
        p.require(cls is EndpointDriver and type(driver) is DriverBootstrap)
        driver.check()
        p.require(driver._config["apiVersion"] == "catchplate.nativeShadowDriverBootstrapConfiguration/v4"
            and not driver._attempted and all(window[name] == driver._window[name] for name in WINDOW_JOIN))
        configuration(selected)
        p.require(selected["configurationSha256"] == driver._config_sha
            and selected["windowSha256"] == driver._window_sha
            and selected["observationSha256"] == p.sha(driver.observation_original()))
        owner = cls(_TOKEN, driver)
        try:
            originals = []
            for digest in (driver._config_sha, driver._window_sha):
                matches = [item for item in driver._originals if p.sha(item.raw) == digest]
                p.require(len(matches) == 1)
                item = matches[0]; item.check()
                duplicate = fcntl.fcntl(item.fd, fcntl.F_DUPFD_CLOEXEC, 128)
                owner._fds.append(duplicate)
                owner._copies.append((duplicate, mechanics.originals._identity(os.fstat(duplicate)), item.raw))
                originals.append(item.raw.decode("ascii"))
            owner.packet = p.canonical({"apiVersion": "catchplate.nativeShadowEndpointDriverBinding/v1",
                "configurationOriginal": originals[0], "windowOriginal": originals[1],
                "observationOriginal": driver.observation_original().decode("ascii")})
            p.require(0 < len(owner.packet) <= 32768)
            supervisor = fcntl.fcntl(driver._pidfd, fcntl.F_DUPFD_CLOEXEC, 128); owner._fds.append(supervisor)
            child = fcntl.fcntl(driver._driver_pidfd, fcntl.F_DUPFD_CLOEXEC, 128); owner._fds.append(child)
            # Deliberately follow only the kernel-owned exe link of the actual
            # retained live child, never an operator-supplied path or PID.
            executable = os.open("/proc/" + str(driver._driver_pid) + "/exe", os.O_RDONLY | os.O_CLOEXEC)
            owner._fds.append(executable)
            info = os.fstat(executable)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o500 and info.st_nlink == 0
                and 0 < info.st_size <= 64 * 1024 * 1024
                and fcntl.fcntl(executable, fcntl.F_GET_SEALS) & 15 == 15)
            data = os.pread(executable, info.st_size + 1, 0)
            p.require(len(data) == info.st_size)
            owner._exe_identity = mechanics.originals._identity(info)
            exe = dict(device=info.st_dev, inode=info.st_ino, length=info.st_size, sha256=p.sha(data))
            observed = [item for item in driver._observation["descriptors"] if item["name"] == "executable"]
            p.require(len(observed) == 1 and (observed[0]["device"], observed[0]["inode"])
                == (info.st_dev, info.st_ino) and exe["sha256"] == driver._observation["driver"]["driverExecutableSha256"])
            supervisor_info = os.fstat(driver._exec)
            p.require(p.sha(os.pread(driver._exec, supervisor_info.st_size + 1, 0)) == selected["supervisorExecutableSha256"])
            owner.rights = (supervisor, child, executable)
            def process(fd, pid, start):
                info = os.fstat(fd)
                return dict(processId=pid, startTimeTicks=start, pidfdDevice=info.st_dev, pidfdInode=info.st_ino)
            owner.value = dict(apiVersion="catchplate.nativeShadowEndpointDriverOriginal/v1",
                bindingSha256=p.sha(owner.packet), configurationSha256=driver._config_sha,
                windowSha256=driver._window_sha, observationSha256=p.sha(driver._observation_raw),
                supervisor=process(supervisor, driver._child_pid, driver._child_start),
                driver=process(child, driver._driver_pid, driver._driver_start), executable=exe)
            original(owner.value, selected)
            owner.check(live=True)
            return owner
        except BaseException:
            owner._dispose()
            raise

    def check(self, *, live):
        from catchplate import native_shadow_proof_cohort_control as mechanics
        p.require(not self._closed and os.getpid() == self.driver._pid
            and mechanics.originals._start() == self.driver._start and mechanics.originals._boot() == self.driver._boot)
        for fd, identity, raw in self._copies:
            p.require(mechanics.originals._identity(os.fstat(fd)) == identity and os.pread(fd, len(raw) + 1, 0) == raw)
        p.require(all(not os.get_inheritable(fd) for fd in self._fds))
        for fd, name in zip(self.rights[:2], ("supervisor", "driver"), strict=True):
            info = os.fstat(fd); item = self.value[name]
            p.require((info.st_dev, info.st_ino) == (item["pidfdDevice"], item["pidfdInode"]))
        p.require(mechanics.originals._identity(os.fstat(self.rights[2])) == self._exe_identity
            and fcntl.fcntl(self.rights[2], fcntl.F_GET_SEALS) & 15 == 15)
        if live:
            self.driver.check()
            p.require(not any(mechanics._terminal(fd) for fd in self.rights[:2]))
            current = os.stat("/proc/" + str(self.driver._driver_pid) + "/exe")
            p.require((current.st_dev, current.st_ino, current.st_size)
                == (self.value["executable"]["device"], self.value["executable"]["inode"], self.value["executable"]["length"]))

    def send(self, channel):
        import array
        self.check(live=True); p.require(not self._sent); self._sent = True
        count = channel.sendmsg([self.packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", self.rights))],
            socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        p.require(count == len(self.packet))

    def terminal(self):
        from catchplate import native_shadow_proof_cohort_control as mechanics
        self.check(live=False)
        p.require(self.driver._closed and self.driver.subtree_terminal_original()
            and all(mechanics._terminal(fd) for fd in self.rights[:2]))

    def close(self):
        if not self._closed:
            self.terminal(); self._dispose()

    def _dispose(self):
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear(); self._closed = True
